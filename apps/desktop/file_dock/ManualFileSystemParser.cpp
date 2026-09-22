#include "ManualFileSystemParser.h"

// ============================================================
// ManualFileSystemParser.cpp
// Notes:
// 1) Provides manual directory parsing for NTFS/FAT32;
// 2) Provide NTFS deleted item scanning and safe recovery for resident and non-resident data.
// 3) Parsing logic is fully encapsulated in this file; the UI only consumes the unified structure.
// ============================================================

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QTemporaryFile>
#include <QTimeZone>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#include "NtfsRunListDecode.h"

namespace
{
    // runlist decoding has been moved to ks::file (see NtfsRunListDecode.h): it is a pure byte-level parse. Extracting
    // it allows boundary testing without a real volume. An alias is retained here to keep call sites unchanged.
    using ks::file::NtfsDataRun;
    using ks::file::parseNtfsRunList;

    // NtfsNameLink:
    // - Represents a 'directory name link' under a single MFT record;
    // - Used to preserve hard link/multi-parent scenarios, avoiding a single record mapping to only one directory.
    struct NtfsNameLink
    {
        std::uint64_t parentIndex = 0;         // Parent directory record number.
        QString fileName;                      // The file name displayed under this parent directory.
        int nameScore = -1;                    // Name priority: prefer Win32/Win32&DOS.
    };

    // NtfsVolumeBitmapSnapshot:
    // - Save volume bitmap snapshot;
    // - Used to determine if the data clusters of a deleted file remain unallocated.
    struct NtfsVolumeBitmapSnapshot
    {
        std::uint64_t startingLcn = 0;         // Current bitmap starting LCN.
        std::uint64_t clusterCount = 0;        // Number of clusters covered by the bitmap.
        std::vector<std::uint8_t> bitmapBytes; // Each bit indicates whether a cluster is allocated.
    };

    // NtfsRawRecord:
    // - Save MFT record fields related to directory display/recovery for a single entry.
    // - Also used for both 'directory list' and 'undelete scan' scenarios.
    struct NtfsRawRecord
    {
        std::uint64_t recordIndex = 0;         // Record index.
        std::uint16_t sequenceNumber = 0;      // MFT record sequence number, used to identify record reuse.
        std::uint64_t parentIndex = 0;         // Parent directory record number.
        QString fileName;                      // File name (prioritizing the Win32 namespace).
        std::uint64_t sizeBytes = 0;           // File size.
        std::uint64_t initializedSizeBytes = 0;// Initialized length of the non-resident stream; zero-fill the uninitialized tail.
        std::uint64_t modifiedTime100ns = 0;   // Modified time (FILETIME 100ns).
        bool inUse = false;                    // Whether in use.
        bool isDirectory = false;              // Whether a directory.
        bool hasPrimaryDataStream = false;     // Whether an unnamed primary data stream exists.
        bool nonResidentData = false;          // Whether the unnamed primary data stream is non-resident.
        bool residentReady = false;            // Whether resident data was successfully extracted.
        bool unsupportedDataStream = false;    // Whether the main data stream uses a currently unsupported layout, compression, or encryption.
        bool hasAttributeList = false;         // Whether $ATTRIBUTE_LIST exists, which may contain external data segments.
        std::uint16_t dataAttributeFlags = 0;  // $DATA attribute flags (compressed/encrypted/sparse).
        QByteArray residentData;               // Resident data content.
        std::vector<NtfsDataRun> dataRuns;     // Collection of data runs for non-resident main data streams.
        std::vector<NtfsNameLink> nameLinks;   // All directory name links currently recorded.
    };

    // NtfsDirectoryLink:
    // - Expand directory entry view from "record level" to "directory name level";
    // - This ensures that when the same record has multiple parent directories or hard links, the directory page displays them completely.
    struct NtfsDirectoryLink
    {
        std::uint64_t parentIndex = 0;         // Parent directory record number.
        std::uint64_t recordIndex = 0;         // Sub-record index.
        QString fileName;                      // Display name under the parent directory.
    };

    // Fat32BootInfo:
    // - Saves necessary fields from the FAT32 BPB;
    // - Used to read cluster chains and parse directory entries.
    struct Fat32BootInfo
    {
        std::uint16_t bytesPerSector = 512;    // Bytes per sector.
        std::uint8_t sectorsPerCluster = 8;    // Sectors per cluster.
        std::uint16_t reservedSectors = 0;     // Reserved sectors.
        std::uint8_t fatCount = 2;             // FAT table count.
        std::uint32_t sectorsPerFat = 0;       // Sectors per FAT.
        std::uint32_t rootCluster = 2;         // Root cluster number.
        std::uint64_t fatOffset = 0;           // FAT table start offset (bytes).
        std::uint64_t dataOffset = 0;          // Data region start offset (bytes).
        std::uint32_t bytesPerCluster = 4096;  // Bytes per cluster.
    };

    // Fat32Entry purpose: Represents the raw parsing result of a FAT32 directory entry.
    struct Fat32Entry
    {
        QString name;                           // File name (prefer LFN).
        std::uint32_t firstCluster = 0;         // Start cluster number.
        std::uint64_t sizeBytes = 0;            // File size.
        bool isDirectory = false;               // Whether a directory.
        QDateTime modifiedTime;                 // Modified time.
    };

    // ExFatBootInfo:
    // - Stores fields required for directory enumeration in the exFAT Boot Region.
    // - The exFAT cluster heap starts at clusterHeapOffset, but cluster numbering still begins at 2.
    struct ExFatBootInfo
    {
        std::uint64_t fatOffsetBytes = 0;        // FAT start byte offset.
        std::uint64_t clusterHeapOffsetBytes = 0;// Cluster heap start byte offset.
        std::uint32_t clusterCount = 0;          // Cluster count within the volume.
        std::uint32_t rootDirectoryCluster = 2;  // Root directory starting cluster.
        std::uint32_t bytesPerSector = 512;      // Bytes per sector.
        std::uint32_t sectorsPerCluster = 1;     // Sectors per cluster.
        std::uint32_t bytesPerCluster = 512;     // Bytes per cluster.
    };

    // ExFatEntry purpose: represents the result of exFAT directory entry parsing.
    struct ExFatEntry
    {
        QString name;                            // File name.
        std::uint32_t firstCluster = 0;          // Start cluster number.
        std::uint64_t sizeBytes = 0;             // File size.
        bool isDirectory = false;                // Whether a directory.
        bool noFatChain = false;                 // true indicates directory/file content is read via contiguous clusters.
    };

    // NtfsCacheEntry:
    // - Cache the most recent MFT parsing results for the same volume.
    // - Avoid performance lag caused by repeated scanning when manually traversing directories consecutively.
    struct NtfsCacheEntry
    {
        std::vector<NtfsRawRecord> records;                       // Cached record collection.
        std::vector<NtfsDirectoryLink> directoryLinks;            // Collection of directory entry-level indices.
        std::unordered_map<std::uint64_t, std::size_t> recordOffsetByIndex; // Mapping from record number to array index.
        qint64 loadedMsec = 0;                                    // Cache timestamp (milliseconds).
        std::uint64_t recordLimit = 0;                            // Maximum number of records covered by this cache.
        bool fsctlFallbackAllowed = false;                        // Whether FSCTL fallback parsing is allowed for this cache.
    };

    // NtfsRecordKeepPolicy:
    // - Controls which records to retain in the result set during scanning.
    // Why it is needed:
    // - Deleted file scanning must cover the entire $MFT: NTFS record numbers are allocated from low to high, and deleted records
    //   with low numbers are reused first; thus, 'deleted but unreused' records are almost entirely concentrated at the end of the MFT;
    //   Scanning only the first tens of thousands of entries yields a stable count of 0 deletions.
    // - However, the full volume MFT can contain millions of records. Retaining all of them would cause memory to scale linearly with the
    //   MFT size. Therefore, the deletion scan only retains deleted items and directories (directories are used to reconstruct path hints).
    enum class NtfsRecordKeepPolicy : int
    {
        kAll = 0,                  // Retain all successfully parsed records (for directory browsing).
        kDeletedAndDirectories = 1 // Keep only deleted records and directory records (for accidental deletion scanning).
    };

    std::mutex gNtfsCacheMutex; // NTFS cache mutex.
    std::unordered_map<std::wstring, std::shared_ptr<NtfsCacheEntry>> gNtfsCache; // Volume cache dictionary.

    // buildTypeText forward declaration:
    // - Allows the WinAPI helper function above to reuse type text generation logic.
    // - The specific implementation remains in place below to avoid duplication.
    QString buildTypeText(const QString& fileName, const bool isDirectory);

    // buildNtfsCacheIndex:
    // - Generate "directory entry-level indices" and "record number indices" for cache entries.
    // - Avoid re-traversing the full MFT records every time the directory is switched.
    void buildNtfsCacheIndex(NtfsCacheEntry& cacheEntry)
    {
        cacheEntry.directoryLinks.clear();
        cacheEntry.recordOffsetByIndex.clear();
        cacheEntry.directoryLinks.reserve(cacheEntry.records.size() * 2);
        cacheEntry.recordOffsetByIndex.reserve(cacheEntry.records.size());

        for (std::size_t i = 0; i < cacheEntry.records.size(); ++i)
        {
            const NtfsRawRecord& recordValue = cacheEntry.records[i];
            cacheEntry.recordOffsetByIndex.emplace(recordValue.recordIndex, i);

            if (!recordValue.nameLinks.empty())
            {
                for (const NtfsNameLink& nameLink : recordValue.nameLinks)
                {
                    if (nameLink.fileName.isEmpty())
                    {
                        continue;
                    }

                    NtfsDirectoryLink dirLink{};
                    dirLink.parentIndex = nameLink.parentIndex;
                    dirLink.recordIndex = recordValue.recordIndex;
                    dirLink.fileName = nameLink.fileName;
                    cacheEntry.directoryLinks.push_back(std::move(dirLink));
                }
                continue;
            }

            if (!recordValue.fileName.isEmpty())
            {
                NtfsDirectoryLink dirLink{};
                dirLink.parentIndex = recordValue.parentIndex;
                dirLink.recordIndex = recordValue.recordIndex;
                dirLink.fileName = recordValue.fileName;
                cacheEntry.directoryLinks.push_back(std::move(dirLink));
            }
        }

        std::sort(
            cacheEntry.directoryLinks.begin(),
            cacheEntry.directoryLinks.end(),
            [](const NtfsDirectoryLink& left, const NtfsDirectoryLink& right) {
                if (left.parentIndex != right.parentIndex)
                {
                    return left.parentIndex < right.parentIndex;
                }
                const int kCompareResult = QString::compare(left.fileName, right.fileName, Qt::CaseInsensitive);
                if (kCompareResult != 0)
                {
                    return kCompareResult < 0;
                }
                return left.recordIndex < right.recordIndex;
            });
    }

    // findNtfsDirectoryLinkRange:
    // - Locate the range of all child entries for a given parent directory within the directory entry index sorted by parentIndex.
    // - Return value can be used directly to iterate over all children of the directory.
    auto findNtfsDirectoryLinkRange(
        const std::vector<NtfsDirectoryLink>& directoryLinks,
        const std::uint64_t parentIndex)
    {
        const auto kLowerIt = std::lower_bound(
            directoryLinks.begin(),
            directoryLinks.end(),
            parentIndex,
            [](const NtfsDirectoryLink& linkValue, const std::uint64_t targetParentIndex) {
                return linkValue.parentIndex < targetParentIndex;
            });
        const auto kUpperIt = std::upper_bound(
            kLowerIt,
            directoryLinks.end(),
            parentIndex,
            [](const std::uint64_t targetParentIndex, const NtfsDirectoryLink& linkValue) {
                return targetParentIndex < linkValue.parentIndex;
            });
        return std::make_pair(kLowerIt, kUpperIt);
    }

    // enumerateDirectoryByWinApi:
    // - Use Windows API/QDir to quickly list directory entries;
    // - Used as a fallback and final safeguard when manual NTFS results cannot fully cover the data.
    bool enumerateDirectoryByWinApi(
        const QString& pathText,
        std::vector<ks::file::ManualDirectoryEntry>& entriesOut)
    {
        entriesOut.clear();

        const QString kNormalizedPath = QDir::toNativeSeparators(QDir::cleanPath(pathText));
        QDir fallbackDirectory(kNormalizedPath);
        if (!fallbackDirectory.exists())
        {
            return false;
        }

        const QFileInfoList kFallbackEntries = fallbackDirectory.entryInfoList(
            QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
            QDir::DirsFirst | QDir::Name | QDir::IgnoreCase);
        for (const QFileInfo& fileInfoValue : kFallbackEntries)
        {
            ks::file::ManualDirectoryEntry itemValue{};
            itemValue.name = fileInfoValue.fileName();
            itemValue.absolutePath = fileInfoValue.absoluteFilePath();
            itemValue.isDirectory = fileInfoValue.isDir();
            itemValue.sizeBytes = itemValue.isDirectory ? 0 : static_cast<std::uint64_t>(fileInfoValue.size());
            itemValue.modifiedTime = fileInfoValue.lastModified();
            itemValue.typeText = buildTypeText(itemValue.name, itemValue.isDirectory);
            entriesOut.push_back(std::move(itemValue));
        }
        return true;
    }

    // le16/le32/le64 purpose: Read little-endian integers.
    std::uint16_t le16(const std::byte* ptr)
    {
        return static_cast<std::uint16_t>(static_cast<std::uint8_t>(ptr[0]))
            | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(ptr[1])) << 8);
    }
    std::uint32_t le32(const std::byte* ptr)
    {
        return static_cast<std::uint32_t>(static_cast<std::uint8_t>(ptr[0]))
            | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(ptr[1])) << 8)
            | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(ptr[2])) << 16)
            | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(ptr[3])) << 24);
    }
    std::uint64_t le64(const std::byte* ptr)
    {
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
        {
            value |= (static_cast<std::uint64_t>(static_cast<std::uint8_t>(ptr[i])) << (i * 8));
        }
        return value;
    }



    // trimVolumeRoot purpose: Extract the volume root from any path, e.g., C:\.
    QString trimVolumeRoot(const QString& pathText)
    {
        const QString kCleanText = QDir::toNativeSeparators(QDir::cleanPath(pathText.trimmed()));
        if (kCleanText.size() < 2 || kCleanText[1] != QChar(':'))
        {
            return QString();
        }
        return kCleanText.left(2).toUpper() + QStringLiteral("\\");
    }

    // buildVolumeDevicePath: Converts a volume root to a device path (e.g., \\.\C:).
    QString buildVolumeDevicePath(const QString& rootPathText)
    {
        if (rootPathText.size() < 2)
        {
            return QString();
        }
        return QStringLiteral("\\\\.\\%1").arg(rootPathText.left(2).toUpper());
    }

    // toWide: Convert QString to UTF-16 wide-character path.
    std::wstring toWide(const QString& text)
    {
        return std::wstring(reinterpret_cast<const wchar_t*>(text.utf16()));
    }

    // queryExistingPathVolumeIdentity:
    // - Open existing directories and follow Junctions/symbolic links to obtain the real volume GUID.
    // - For network shares, return a stable UNC share root to prevent misidentifying mapped drives as other local volumes;
    // - Non-resident recovery uses this to bypass the 'cannot write back to source volume' security constraint via mount points.
    QString queryExistingPathVolumeIdentity(const QString& existingPath)
    {
        const std::wstring kNativePath = toWide(
            QDir::toNativeSeparators(QDir::cleanPath(existingPath)));
        HANDLE pathHandle = ::CreateFileW(
            kNativePath.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (pathHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }

        // queryFinalPath purpose: Read the final path of the handle according to the specified volume naming format.
        const auto kQueryFinalPath =
            [pathHandle](const DWORD volumeNameFlag) -> QString
            {
                const DWORD kQueryFlags =
                    FILE_NAME_NORMALIZED | volumeNameFlag;
                const DWORD kRequiredChars =
                    ::GetFinalPathNameByHandleW(
                        pathHandle,
                        nullptr,
                        0,
                        kQueryFlags);
                if (kRequiredChars == 0 ||
                    kRequiredChars >
                        static_cast<DWORD>(
                            std::numeric_limits<int>::max() - 2))
                {
                    return QString();
                }
                std::vector<wchar_t> pathBuffer(
                    static_cast<std::size_t>(kRequiredChars) + 2ULL,
                    L'\0');
                const DWORD kWrittenChars =
                    ::GetFinalPathNameByHandleW(
                        pathHandle,
                        pathBuffer.data(),
                        static_cast<DWORD>(pathBuffer.size()),
                        kQueryFlags);
                if (kWrittenChars == 0 ||
                    kWrittenChars >= static_cast<DWORD>(pathBuffer.size()))
                {
                    return QString();
                }
                return QString::fromWCharArray(
                    pathBuffer.data(),
                    static_cast<int>(kWrittenChars));
            };

        QString finalPath = kQueryFinalPath(VOLUME_NAME_GUID);
        if (finalPath.startsWith(
                QStringLiteral("\\\\?\\Volume{"),
                Qt::CaseInsensitive))
        {
            const int kVolumeEndIndex =
                finalPath.indexOf(QStringLiteral("}\\"));
            ::CloseHandle(pathHandle);
            return kVolumeEndIndex >= 0
                ? finalPath.left(kVolumeEndIndex + 2).toUpper()
                : QString();
        }

        // Network shares do not support VOLUME_NAME_GUID; fall back to the DOS/UNC final path and retain only the share root.
        finalPath = kQueryFinalPath(VOLUME_NAME_DOS);
        ::CloseHandle(pathHandle);
        const QString kUncPrefix = QStringLiteral("\\\\?\\UNC\\");
        if (finalPath.startsWith(kUncPrefix, Qt::CaseInsensitive))
        {
            const QStringList kPathParts =
                finalPath.mid(kUncPrefix.size()).split(
                    QChar('\\'),
                    Qt::SkipEmptyParts);
            if (kPathParts.size() >= 2)
            {
                return QString::fromLatin1("UNC:%1\\%2")
                    .arg(kPathParts.at(0), kPathParts.at(1))
                    .toUpper();
            }
            return QString();
        }
        const QString kDosPrefix = QStringLiteral("\\\\?\\");
        if (finalPath.startsWith(kDosPrefix, Qt::CaseInsensitive) &&
            finalPath.size() >= kDosPrefix.size() + 3 &&
            finalPath.at(kDosPrefix.size() + 1) == QChar(':'))
        {
            return (
                QString::fromLatin1("DOS:") +
                finalPath.mid(kDosPrefix.size(), 3))
                .toUpper();
        }
        return QString();
    }

    // readBytesAtOffset purpose: Read a fixed-length byte block at the specified offset.
    bool readBytesAtOffset(
        const HANDLE fileHandle,
        const std::uint64_t offsetValue,
        const std::uint32_t sizeValue,
        std::byte* bufferPtr,
        QString& errorTextOut)
    {
        if (bufferPtr == nullptr ||
            offsetValue >
                static_cast<std::uint64_t>(
                    std::numeric_limits<LONGLONG>::max()) ||
            static_cast<std::uint64_t>(sizeValue) >
                static_cast<std::uint64_t>(
                    std::numeric_limits<LONGLONG>::max()) -
                    offsetValue)
        {
            errorTextOut = QStringLiteral(
                "读取偏移或长度超出 Windows 文件指针范围, offset=%1, size=%2")
                .arg(static_cast<qulonglong>(offsetValue))
                .arg(sizeValue);
            return false;
        }

        LARGE_INTEGER targetOffset{};
        targetOffset.QuadPart = static_cast<LONGLONG>(offsetValue);
        if (::SetFilePointerEx(fileHandle, targetOffset, nullptr, FILE_BEGIN) == FALSE)
        {
            errorTextOut = QStringLiteral("SetFilePointerEx失败, code=%1").arg(::GetLastError());
            return false;
        }

        DWORD readSize = 0;
        if (::ReadFile(fileHandle, bufferPtr, sizeValue, &readSize, nullptr) == FALSE)
        {
            errorTextOut = QStringLiteral("ReadFile失败, code=%1").arg(::GetLastError());
            return false;
        }
        if (readSize != sizeValue)
        {
            errorTextOut = QStringLiteral("读取长度不足, expect=%1, actual=%2").arg(sizeValue).arg(readSize);
            return false;
        }
        return true;
    }

    // readBytesAtSectorAlignedOffset:
    // - Input: arbitrary byte offset and read length within a volume; internally expands to a sector-aligned read window;
    // - Handle the case where raw volume handles reject non-sector-aligned seeks when reading FAT/FAT32/exFAT FAT table entries.
    // - On success, copy only the raw byte range requested by the caller to bufferPtr; the function returns no other data.
    // - On failure, return false and write the phase, cluster number, original offset, aligned offset, and sector size to errorTextOut.
    bool readBytesAtSectorAlignedOffset(
        const HANDLE fileHandle,
        const std::uint64_t offsetValue,
        const std::uint32_t sizeValue,
        const std::uint32_t sectorSizeValue,
        const QString& stageText,
        const std::uint32_t clusterValue,
        std::byte* bufferPtr,
        QString& errorTextOut)
    {
        if (bufferPtr == nullptr || sizeValue == 0)
        {
            errorTextOut = QStringLiteral("%1失败：读取参数为空, cluster=%2, entryOffset=0x%3, size=%4, sectorSize=%5")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper())
                .arg(sizeValue)
                .arg(sectorSizeValue);
            return false;
        }
        if (sectorSizeValue == 0)
        {
            errorTextOut = QStringLiteral("%1失败：扇区大小为0, cluster=%2, entryOffset=0x%3")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper());
            return false;
        }
        if (offsetValue > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(sizeValue))
        {
            errorTextOut = QStringLiteral("%1失败：读取偏移溢出, cluster=%2, entryOffset=0x%3, size=%4, sectorSize=%5")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper())
                .arg(sizeValue)
                .arg(sectorSizeValue);
            return false;
        }

        const std::uint64_t kSectorSize = static_cast<std::uint64_t>(sectorSizeValue);
        const std::uint64_t kAlignedOffset = (offsetValue / kSectorSize) * kSectorSize;
        const std::uint64_t kInSectorOffset = offsetValue - kAlignedOffset;
        const std::uint64_t kRequestEndOffset = offsetValue + static_cast<std::uint64_t>(sizeValue);
        if (kRequestEndOffset > std::numeric_limits<std::uint64_t>::max() - (kSectorSize - 1ULL)
            || kAlignedOffset > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
        {
            errorTextOut = QStringLiteral("%1失败：对齐偏移溢出, cluster=%2, entryOffset=0x%3, alignedOffset=0x%4, size=%5, sectorSize=%6")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper())
                .arg(QString::number(kAlignedOffset, 16).toUpper())
                .arg(sizeValue)
                .arg(sectorSizeValue);
            return false;
        }
        const std::uint64_t kAlignedEndOffset =
            ((kRequestEndOffset + kSectorSize - 1ULL) / kSectorSize) * kSectorSize;
        const std::uint64_t kAlignedSize64 = kAlignedEndOffset - kAlignedOffset;
        if (kAlignedSize64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            errorTextOut = QStringLiteral("%1失败：对齐读取窗口过大, cluster=%2, entryOffset=0x%3, alignedOffset=0x%4, alignedSize=%5, sectorSize=%6")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper())
                .arg(QString::number(kAlignedOffset, 16).toUpper())
                .arg(kAlignedSize64)
                .arg(sectorSizeValue);
            return false;
        }

        std::vector<std::byte> alignedBytes(static_cast<std::size_t>(kAlignedSize64));
        QString innerErrorText;
        if (!readBytesAtOffset(
            fileHandle,
            kAlignedOffset,
            static_cast<std::uint32_t>(kAlignedSize64),
            alignedBytes.data(),
            innerErrorText))
        {
            errorTextOut = QStringLiteral("%1失败, cluster=%2, entryOffset=0x%3, alignedOffset=0x%4, alignedSize=%5, sectorSize=%6, inner=%7")
                .arg(stageText)
                .arg(clusterValue)
                .arg(QString::number(offsetValue, 16).toUpper())
                .arg(QString::number(kAlignedOffset, 16).toUpper())
                .arg(kAlignedSize64)
                .arg(sectorSizeValue)
                .arg(innerErrorText);
            return false;
        }

        std::memcpy(
            bufferPtr,
            alignedBytes.data() + static_cast<std::size_t>(kInSectorOffset),
            static_cast<std::size_t>(sizeValue));
        return true;
    }

    // guessDeletedFileExtension:
    // - When the original filename is lost, attempt to guess the extension based on the resident data header.
    // - If unable to determine, uniformly fall back to 'bin'.
    QString guessDeletedFileExtension(const QByteArray& residentData)
    {
        if (residentData.size() >= 8
            && static_cast<unsigned char>(residentData[0]) == 0x89
            && residentData.mid(1, 3) == "PNG")
        {
            return QStringLiteral("png");
        }
        if (residentData.size() >= 3
            && static_cast<unsigned char>(residentData[0]) == 0xFF
            && static_cast<unsigned char>(residentData[1]) == 0xD8
            && static_cast<unsigned char>(residentData[2]) == 0xFF)
        {
            return QStringLiteral("jpg");
        }
        if (residentData.size() >= 4 && residentData.left(4) == "%PDF")
        {
            return QStringLiteral("pdf");
        }
        if (residentData.size() >= 4 && residentData.left(4) == "PK\x03\x04")
        {
            return QStringLiteral("zip");
        }
        if (residentData.size() >= 6 && (residentData.left(6) == "GIF87a" || residentData.left(6) == "GIF89a"))
        {
            return QStringLiteral("gif");
        }
        if (residentData.size() >= 2 && residentData.left(2) == "BM")
        {
            return QStringLiteral("bmp");
        }
        if (residentData.size() >= 8
            && static_cast<unsigned char>(residentData[0]) == 0x52
            && static_cast<unsigned char>(residentData[1]) == 0x61
            && static_cast<unsigned char>(residentData[2]) == 0x72
            && static_cast<unsigned char>(residentData[3]) == 0x21)
        {
            return QStringLiteral("rar");
        }
        return QStringLiteral("bin");
    }

    // buildSyntheticDeletedFileName:
    // - Generate placeholder filenames for deleted records with missing names.
    // - Facilitates result list display and subsequent export to disk.
    QString buildSyntheticDeletedFileName(const NtfsRawRecord& recordValue)
    {
        QString suffixText = QStringLiteral("bin");
        if (!recordValue.residentData.isEmpty())
        {
            suffixText = guessDeletedFileExtension(recordValue.residentData);
        }

        return QStringLiteral("deleted_%1.%2")
            .arg(static_cast<qulonglong>(recordValue.recordIndex))
            .arg(suffixText);
    }

    // fileTimeToLocal purpose: Convert FILETIME (100ns) to local time.
    QDateTime fileTimeToLocal(const std::uint64_t fileTime100ns)
    {
        if (fileTime100ns == 0)
        {
            return QDateTime();
        }
        constexpr qint64 kEpochDeltaMsec = 11644473600000LL;
        const qint64 kUnixMsec = static_cast<qint64>(fileTime100ns / 10000ULL) - kEpochDeltaMsec;
        return QDateTime::fromMSecsSinceEpoch(kUnixMsec, QTimeZone::UTC).toLocalTime();
    }

    // openReadHandle: Opens the handle uniformly in shared read-only mode.
    HANDLE openReadHandle(const QString& nativePathText, QString& errorTextOut)
    {
        const std::wstring kPathWide = toWide(nativePathText);

        // enablePrivilegeByName: Enables specific process token privileges on demand (e.g., SeBackupPrivilege).
        const auto kEnablePrivilegeByName = [](const wchar_t* privilegeName) -> bool {
            if (privilegeName == nullptr)
            {
                return false;
            }
            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                return false;
            }

            LUID luidValue{};
            if (::LookupPrivilegeValueW(nullptr, privilegeName, &luidValue) == FALSE)
            {
                ::CloseHandle(tokenHandle);
                return false;
            }

            TOKEN_PRIVILEGES privileges{};
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Luid = luidValue;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ::SetLastError(ERROR_SUCCESS);
            const BOOL kAdjustOk = ::AdjustTokenPrivileges(
                tokenHandle,
                FALSE,
                &privileges,
                static_cast<DWORD>(sizeof(privileges)),
                nullptr,
                nullptr);
            const DWORD kAdjustError = ::GetLastError();
            ::CloseHandle(tokenHandle);
            return kAdjustOk != FALSE && kAdjustError == ERROR_SUCCESS;
        };

        // First round: standard read-only open.
        HANDLE handleValue = ::CreateFileW(
            kPathWide.c_str(),
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            const DWORD kFirstError = ::GetLastError();

            // Round 2: For $MFT/system metadata files, enable backup-related privileges and retry with BackupSemantics.
            if (kFirstError == ERROR_ACCESS_DENIED)
            {
                kEnablePrivilegeByName(SE_BACKUP_NAME);
                kEnablePrivilegeByName(SE_RESTORE_NAME);
                kEnablePrivilegeByName(SE_MANAGE_VOLUME_NAME);
                handleValue = ::CreateFileW(
                    kPathWide.c_str(),
                    FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
            }

            if (handleValue == INVALID_HANDLE_VALUE)
            {
                errorTextOut = QStringLiteral("CreateFile失败: %1, code=%2").arg(nativePathText).arg(::GetLastError());
                return INVALID_HANDLE_VALUE;
            }
        }
        return handleValue;
    }

    // loadNtfsVolumeBitmapSnapshot:
    // - Read the full volume cluster bitmap.
    // - Used for estimating whether data clusters have not yet been overwritten during accidental deletion scanning.
    bool loadNtfsVolumeBitmapSnapshot(
        const QString& volumeRoot,
        NtfsVolumeBitmapSnapshot& bitmapOut,
        QString& errorTextOut)
    {
        bitmapOut = NtfsVolumeBitmapSnapshot{};
        errorTextOut.clear();

        QString openErrorText;
        HANDLE volumeHandle = openReadHandle(buildVolumeDevicePath(volumeRoot), openErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        NTFS_VOLUME_DATA_BUFFER volumeData{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            nullptr,
            0,
            &volumeData,
            static_cast<DWORD>(sizeof(volumeData)),
            &returnedBytes,
            nullptr) == FALSE)
        {
            errorTextOut = QStringLiteral("FSCTL_GET_NTFS_VOLUME_DATA失败, code=%1").arg(::GetLastError());
            ::CloseHandle(volumeHandle);
            return false;
        }

        const std::uint64_t kTotalClusters =
            static_cast<std::uint64_t>(volumeData.TotalClusters.QuadPart);
        if (kTotalClusters == 0)
        {
            errorTextOut = QStringLiteral("卷位图为空。");
            ::CloseHandle(volumeHandle);
            return false;
        }

        // FSCTL_GET_VOLUME_BITMAP returns only the portion that fits in the output buffer at a time. When the buffer is
        // insufficient, it returns ERROR_MORE_DATA with the buffer filled, so the caller must loop to continue reading.
        // Early implementations allocated buffers by fetching the entire volume bitmap at once: large volumes were blocked by the
        // limit, and missing bitmaps caused all non-resident entries to degrade to 'unknown completeness / export prohibited'.
        constexpr std::size_t kBitmapChunkPayloadBytes = 8ULL * 1024ULL * 1024ULL;
        constexpr std::uint64_t kMaxBitmapBytes = 256ULL * 1024ULL * 1024ULL;
        const std::size_t kHeaderBytes = offsetof(VOLUME_BITMAP_BUFFER, Buffer);
        std::vector<std::uint8_t> outputBuffer(kHeaderBytes + kBitmapChunkPayloadBytes + 64ULL);

        bitmapOut.startingLcn = 0;
        bitmapOut.clusterCount = 0;
        bitmapOut.bitmapBytes.clear();
        bitmapOut.bitmapBytes.reserve(
            static_cast<std::size_t>(
                std::min<std::uint64_t>((kTotalClusters + 7ULL) / 8ULL, kMaxBitmapBytes)));

        std::uint64_t nextLcn = 0;
        while (nextLcn < kTotalClusters)
        {
            STARTING_LCN_INPUT_BUFFER inputBuffer{};
            inputBuffer.StartingLcn.QuadPart = static_cast<LONGLONG>(nextLcn);
            returnedBytes = 0;
            const BOOL kQueryOk = ::DeviceIoControl(
                volumeHandle,
                FSCTL_GET_VOLUME_BITMAP,
                &inputBuffer,
                static_cast<DWORD>(sizeof(inputBuffer)),
                outputBuffer.data(),
                static_cast<DWORD>(outputBuffer.size()),
                &returnedBytes,
                nullptr);
            const DWORD kQueryErrorCode = kQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (kQueryOk == FALSE && kQueryErrorCode != ERROR_MORE_DATA)
            {
                ::CloseHandle(volumeHandle);
                errorTextOut = QStringLiteral("FSCTL_GET_VOLUME_BITMAP失败, startLcn=%1, code=%2")
                    .arg(static_cast<qulonglong>(nextLcn))
                    .arg(kQueryErrorCode);
                return false;
            }
            if (returnedBytes <= kHeaderBytes)
            {
                ::CloseHandle(volumeHandle);
                errorTextOut = QStringLiteral("卷位图返回长度不足, startLcn=%1")
                    .arg(static_cast<qulonglong>(nextLcn));
                return false;
            }

            const VOLUME_BITMAP_BUFFER* bitmapBuffer =
                reinterpret_cast<const VOLUME_BITMAP_BUFFER*>(outputBuffer.data());
            // The driver aligns StartingLcn down to byte boundaries; nextLcn is always a multiple of 8. Thus, the aligned
            // start must match the request exactly; otherwise, a gap exists between segments, so stop immediately.
            const std::uint64_t kChunkStartLcn =
                static_cast<std::uint64_t>(bitmapBuffer->StartingLcn.QuadPart);
            if (kChunkStartLcn != nextLcn)
            {
                break;
            }

            // BitmapSize represents the remaining cluster count from StartingLcn to the end of the volume, not the cluster count returned in this segment.
            const std::uint64_t kRemainingClusters =
                static_cast<std::uint64_t>(bitmapBuffer->BitmapSize.QuadPart);
            const std::uint64_t kPayloadBytes =
                static_cast<std::uint64_t>(returnedBytes) - kHeaderBytes;
            const std::uint64_t kChunkClusters =
                std::min<std::uint64_t>(kRemainingClusters, kPayloadBytes * 8ULL);
            if (kChunkClusters == 0)
            {
                break;
            }
            const std::uint64_t kChunkBytes = (kChunkClusters + 7ULL) / 8ULL;
            if (kChunkBytes > kPayloadBytes)
            {
                ::CloseHandle(volumeHandle);
                errorTextOut = QStringLiteral("卷位图数据长度异常, startLcn=%1")
                    .arg(static_cast<qulonglong>(kChunkStartLcn));
                return false;
            }

            const std::uint8_t* payloadPtr = outputBuffer.data() + kHeaderBytes;
            bitmapOut.bitmapBytes.insert(
                bitmapOut.bitmapBytes.end(),
                payloadPtr,
                payloadPtr + static_cast<std::size_t>(kChunkBytes));
            bitmapOut.clusterCount += kChunkClusters;
            nextLcn = kChunkStartLcn + kChunkClusters;

            // For oversized volumes, only the leading bitmap segment is retained: deleted items partially covered by this range are still detectable;
            // items outside the range are marked as 'unassessable' by tryCountAllocatedClustersInRange, avoiding false positives for safety.
            if (bitmapOut.bitmapBytes.size() >= static_cast<std::size_t>(kMaxBitmapBytes))
            {
                errorTextOut = QStringLiteral("卷位图超过 %1MB 上限，仅加载前 %2 个簇。")
                    .arg(static_cast<qulonglong>(kMaxBitmapBytes / (1024ULL * 1024ULL)))
                    .arg(static_cast<qulonglong>(bitmapOut.clusterCount));
                break;
            }
        }
        ::CloseHandle(volumeHandle);

        if (bitmapOut.clusterCount == 0 || bitmapOut.bitmapBytes.empty())
        {
            errorTextOut = QStringLiteral("卷位图未返回任何有效数据。");
            return false;
        }
        return true;
    }

    // tryCountAllocatedClustersInRange:
    // - Count the number of currently allocated clusters within the specified cluster range.
    // - Returns false if the bitmap does not cover the range, making evaluation impossible at this time.
    bool tryCountAllocatedClustersInRange(
        const NtfsVolumeBitmapSnapshot& bitmapValue,
        const std::uint64_t startLcn,
        const std::uint64_t clusterCount,
        std::uint64_t& allocatedClustersOut)
    {
        allocatedClustersOut = 0;
        if (clusterCount == 0)
        {
            return true;
        }
        if (startLcn < bitmapValue.startingLcn)
        {
            return false;
        }

        const std::uint64_t kRelativeStartBit = startLcn - bitmapValue.startingLcn;
        if (clusterCount > bitmapValue.clusterCount ||
            kRelativeStartBit > bitmapValue.clusterCount - clusterCount)
        {
            return false;
        }

        const std::uint64_t kEndBitExclusive = kRelativeStartBit + clusterCount;
        std::uint64_t currentBit = kRelativeStartBit;
        while (currentBit < kEndBitExclusive)
        {
            const std::uint64_t kByteIndex = currentBit / 8ULL;
            const std::uint8_t kBitOffset = static_cast<std::uint8_t>(currentBit % 8ULL);
            const std::uint64_t kBitsInThisByte =
                std::min<std::uint64_t>(8ULL - kBitOffset, kEndBitExclusive - currentBit);

            std::uint8_t byteValue = bitmapValue.bitmapBytes[static_cast<std::size_t>(kByteIndex)];
            byteValue = static_cast<std::uint8_t>(byteValue >> kBitOffset);
            if (kBitsInThisByte < 8ULL)
            {
                const std::uint8_t kMaskValue = static_cast<std::uint8_t>((1u << kBitsInThisByte) - 1u);
                byteValue = static_cast<std::uint8_t>(byteValue & kMaskValue);
            }

            allocatedClustersOut += static_cast<std::uint64_t>(std::popcount(static_cast<unsigned int>(byteValue)));
            currentBit += kBitsInThisByte;
        }
        return true;
    }

    // estimateDeletedRecordIntegrityPercent:
    // - Estimates file integrity based on the resident status or whether non-resident data clusters are still free.
    // - Results are used for sorting the recovery list and displaying 'completeness'.
    int estimateDeletedRecordIntegrityPercent(
        const NtfsRawRecord& recordValue,
        const NtfsVolumeBitmapSnapshot* bitmapValue)
    {
        if (recordValue.residentReady && !recordValue.nonResidentData)
        {
            return 100;
        }
        if (!recordValue.nonResidentData || bitmapValue == nullptr || recordValue.dataRuns.empty())
        {
            return -1;
        }

        std::uint64_t totalClusters = 0;
        std::uint64_t intactClusters = 0;
        for (const NtfsDataRun& runValue : recordValue.dataRuns)
        {
            if (totalClusters >
                std::numeric_limits<std::uint64_t>::max() -
                    runValue.clusterCount)
            {
                return -1;
            }
            totalClusters += runValue.clusterCount;
            if (runValue.isSparse)
            {
                if (intactClusters >
                    std::numeric_limits<std::uint64_t>::max() -
                        runValue.clusterCount)
                {
                    return -1;
                }
                intactClusters += runValue.clusterCount;
                continue;
            }

            std::uint64_t allocatedClusters = 0;
            if (!tryCountAllocatedClustersInRange(
                bitmapValue[0],
                runValue.startLcn,
                runValue.clusterCount,
                allocatedClusters))
            {
                return -1;
            }
            if (allocatedClusters > runValue.clusterCount)
            {
                return -1;
            }
            const std::uint64_t kFreeClusterCount =
                runValue.clusterCount - allocatedClusters;
            if (intactClusters >
                std::numeric_limits<std::uint64_t>::max() - kFreeClusterCount)
            {
                return -1;
            }
            intactClusters += kFreeClusterCount;
        }

        if (totalClusters == 0)
        {
            return (recordValue.sizeBytes == 0) ? 100 : -1;
        }

        return static_cast<int>(
            (static_cast<long double>(intactClusters) * 100.0L /
                static_cast<long double>(totalClusters)) +
            0.5L);
    }

    // deletedRecordRecoveryCapability:
    // - normalize underlying record layout and volume bitmap integrity to a recovery capability consumable by the UI;
    // - "Recoverable" only indicates the condition was met during scanning; the volume bitmap will be re-verified twice before actual export.
    ks::file::NtfsRecoveryCapability deletedRecordRecoveryCapability(
        const NtfsRawRecord& recordValue,
        const int integrityPercent)
    {
        if (recordValue.residentReady &&
            !recordValue.nonResidentData &&
            !recordValue.unsupportedDataStream)
        {
            return ks::file::NtfsRecoveryCapability::kResident;
        }
        if (!recordValue.nonResidentData)
        {
            return recordValue.unsupportedDataStream
                ? ks::file::NtfsRecoveryCapability::kUnsupportedStream
                : ks::file::NtfsRecoveryCapability::kMetadataOnly;
        }
        if (recordValue.unsupportedDataStream || recordValue.hasAttributeList)
        {
            return ks::file::NtfsRecoveryCapability::kUnsupportedStream;
        }
        if (recordValue.dataRuns.empty())
        {
            return ks::file::NtfsRecoveryCapability::kMetadataOnly;
        }
        return integrityPercent == 100
            ? ks::file::NtfsRecoveryCapability::kNonResidentIntact
            : ks::file::NtfsRecoveryCapability::kNonResidentAtRisk;
    }

    // validateDeletedDataRunsUnallocated:
    // - Requires that each non-sparse data cluster remains 'unallocated' in the current volume bitmap.
    // - Reject recovery if any cluster is reused, out of bounds, or missing in the bitmap to avoid outputting mixed new and old data.
    bool validateDeletedDataRunsUnallocated(
        const NtfsRawRecord& recordValue,
        const NtfsVolumeBitmapSnapshot& bitmapValue,
        QString& errorTextOut)
    {
        for (const NtfsDataRun& runValue : recordValue.dataRuns)
        {
            if (runValue.isSparse)
            {
                continue;
            }
            std::uint64_t allocatedClusters = 0;
            if (!tryCountAllocatedClustersInRange(
                bitmapValue,
                runValue.startLcn,
                runValue.clusterCount,
                allocatedClusters))
            {
                errorTextOut = QStringLiteral("卷位图未覆盖完整数据段，无法证明恢复安全。");
                return false;
            }
            if (allocatedClusters != 0)
            {
                errorTextOut = QStringLiteral(
                    "检测到 %1 个数据簇已被重新分配，已拒绝输出可能损坏的文件。")
                    .arg(static_cast<qulonglong>(allocatedClusters));
                return false;
            }
        }
        return true;
    }

    // sameDeletedDataRunLayout:
    // - Compare the main data runlist before and after recovery read.
    // - Do not commit the temporary file if the MFT record changes during export.
    bool sameDeletedDataRunLayout(
        const NtfsRawRecord& firstRecord,
        const NtfsRawRecord& secondRecord)
    {
        if (firstRecord.sequenceNumber != secondRecord.sequenceNumber ||
            firstRecord.sizeBytes != secondRecord.sizeBytes ||
            firstRecord.initializedSizeBytes != secondRecord.initializedSizeBytes ||
            firstRecord.dataAttributeFlags != secondRecord.dataAttributeFlags ||
            firstRecord.hasPrimaryDataStream != secondRecord.hasPrimaryDataStream ||
            firstRecord.nonResidentData != secondRecord.nonResidentData ||
            firstRecord.unsupportedDataStream != secondRecord.unsupportedDataStream ||
            firstRecord.hasAttributeList != secondRecord.hasAttributeList ||
            firstRecord.dataRuns.size() != secondRecord.dataRuns.size())
        {
            return false;
        }
        for (std::size_t runIndex = 0;
             runIndex < firstRecord.dataRuns.size();
             ++runIndex)
        {
            const NtfsDataRun& firstRun = firstRecord.dataRuns[runIndex];
            const NtfsDataRun& secondRun = secondRecord.dataRuns[runIndex];
            if (firstRun.startLcn != secondRun.startLcn ||
                firstRun.clusterCount != secondRun.clusterCount ||
                firstRun.isSparse != secondRun.isSparse)
            {
                return false;
            }
        }
        return true;
    }

    // ntfsFixup: Applies NTFS USA fixup to ensure sector tail validation passes.
    bool ntfsFixup(std::vector<std::byte>& recordBytes, const std::uint16_t bytesPerSectorHint)
    {
        if (recordBytes.size() < 64)
        {
            return false;
        }
        const std::uint16_t kUsaOffset = le16(recordBytes.data() + 4);
        const std::uint16_t kUsaCount = le16(recordBytes.data() + 6);
        if (kUsaOffset < 8 || kUsaCount < 2)
        {
            return false;
        }
        const std::size_t kUsaBytes = static_cast<std::size_t>(kUsaCount) * 2;
        if (kUsaOffset + kUsaBytes > recordBytes.size())
        {
            return false;
        }

        const std::byte* usaPtr = recordBytes.data() + kUsaOffset;
        const std::uint16_t kSignature = le16(usaPtr);
        // usaSectorCount usage: records how many physical sector fragments the current FILE record is split into.
        const std::size_t kUsaSectorCount = static_cast<std::size_t>(kUsaCount - 1);
        if (kUsaSectorCount == 0)
        {
            return false;
        }

        // sectorStrideBytes usage: segment stride during USA repair; prioritize validating actual sector size instead of hardcoding 512.
        std::size_t sectorStrideBytes = 0;
        if (bytesPerSectorHint >= 256
            && bytesPerSectorHint <= recordBytes.size()
            && (recordBytes.size() % bytesPerSectorHint) == 0
            && (recordBytes.size() / bytesPerSectorHint) == kUsaSectorCount)
        {
            sectorStrideBytes = static_cast<std::size_t>(bytesPerSectorHint);
        }
        else if ((recordBytes.size() % kUsaSectorCount) == 0)
        {
            sectorStrideBytes = recordBytes.size() / kUsaSectorCount;
        }
        if (sectorStrideBytes < 256)
        {
            return false;
        }

        for (std::uint16_t i = 1; i < kUsaCount; ++i)
        {
            const std::size_t kTailOffset = static_cast<std::size_t>(i) * sectorStrideBytes - 2ULL;
            if (kTailOffset + 2 > recordBytes.size())
            {
                return false;
            }
            if (le16(recordBytes.data() + kTailOffset) != kSignature)
            {
                return false;
            }
            const std::uint16_t kFixedValue = le16(usaPtr + i * 2);
            recordBytes[kTailOffset] = static_cast<std::byte>(kFixedValue & 0xFF);
            recordBytes[kTailOffset + 1] = static_cast<std::byte>((kFixedValue >> 8) & 0xFF);
        }
        return true;
    }

    // parseNtfsRecord purpose: Parse a single MFT record to extract name, parent directory, size, and resident data.
    bool parseNtfsRecord(
        std::vector<std::byte>& recordBytes,
        const std::uint64_t recordIndex,
        const std::uint16_t bytesPerSectorHint,
        const bool captureResidentData,
        NtfsRawRecord& recordOut)
    {
        if (recordBytes.size() < 64 || std::memcmp(recordBytes.data(), "FILE", 4) != 0)
        {
            return false;
        }
        if (!ntfsFixup(recordBytes, bytesPerSectorHint))
        {
            return false;
        }

        recordOut = NtfsRawRecord{};
        recordOut.recordIndex = recordIndex;
        recordOut.sequenceNumber = le16(recordBytes.data() + 16);
        const std::uint16_t kFlags = le16(recordBytes.data() + 22);
        recordOut.inUse = ((kFlags & 0x0001) != 0);
        recordOut.isDirectory = ((kFlags & 0x0002) != 0);

        const std::uint16_t kAttrOffsetStart = le16(recordBytes.data() + 20);
        if (kAttrOffsetStart >= recordBytes.size())
        {
            return false;
        }

        QString preferredName;
        int preferredNameScore = -1;
        std::size_t attrOffset = kAttrOffsetStart;
        while (attrOffset + 24 <= recordBytes.size())
        {
            const std::uint32_t kAttrType = le32(recordBytes.data() + attrOffset);
            if (kAttrType == 0xFFFFFFFF)
            {
                break;
            }
            const std::uint32_t kAttrLength = le32(recordBytes.data() + attrOffset + 4);
            if (kAttrLength < 24 || attrOffset + kAttrLength > recordBytes.size())
            {
                break;
            }
            const std::size_t kAttrEnd = attrOffset + kAttrLength;

            const bool kNonResident = (recordBytes[attrOffset + 8] != std::byte{ 0 });
            const std::uint8_t kAttrNameLength = static_cast<std::uint8_t>(recordBytes[attrOffset + 9]);
            if (kAttrType == 0x20)
            {
                // $ATTRIBUTE_LIST only prevents recovery when it explicitly lists external/subsequent unnamed $DATA
                // extents; listing other attributes will not inadvertently damage readable main data streams.
                if (kNonResident)
                {
                    recordOut.hasAttributeList = true;
                }
                else
                {
                    const std::uint32_t kListLength =
                        le32(recordBytes.data() + attrOffset + 16);
                    const std::uint16_t kListOffset =
                        le16(recordBytes.data() + attrOffset + 20);
                    const std::size_t kListStart = attrOffset + kListOffset;
                    if (kListStart + kListLength > kAttrEnd)
                    {
                        recordOut.hasAttributeList = true;
                    }
                    else
                    {
                        std::size_t listEntryOffset = kListStart;
                        while (listEntryOffset + 26 <= kListStart + kListLength)
                        {
                            const std::uint32_t kListedType =
                                le32(recordBytes.data() + listEntryOffset);
                            const std::uint16_t kListedLength =
                                le16(recordBytes.data() + listEntryOffset + 4);
                            const std::uint8_t kListedNameLength =
                                static_cast<std::uint8_t>(
                                    recordBytes[listEntryOffset + 6]);
                            if (kListedLength < 26 ||
                                listEntryOffset + kListedLength >
                                    kListStart + kListLength)
                            {
                                recordOut.hasAttributeList = true;
                                break;
                            }
                            if (kListedType == 0x80 && kListedNameLength == 0)
                            {
                                const std::uint64_t kListedLowestVcn =
                                    le64(recordBytes.data() + listEntryOffset + 8);
                                const std::uint64_t kListedRecordIndex =
                                    le64(recordBytes.data() + listEntryOffset + 16) &
                                    0x0000FFFFFFFFFFFFULL;
                                if (kListedLowestVcn > 0 ||
                                    kListedRecordIndex != recordIndex)
                                {
                                    recordOut.hasAttributeList = true;
                                }
                            }
                            listEntryOffset += kListedLength;
                        }
                    }
                }
            }
            else if (kAttrType == 0x30 && !kNonResident)
            {
                const std::uint32_t kContentLength = le32(recordBytes.data() + attrOffset + 16);
                const std::uint16_t kContentOffset = le16(recordBytes.data() + attrOffset + 20);
                const std::size_t kContentStart = attrOffset + kContentOffset;
                if (kContentLength >= 66 && kContentStart + kContentLength <= kAttrEnd)
                {
                    const std::byte* contentPtr = recordBytes.data() + kContentStart;
                    const std::uint64_t kParentRef = le64(contentPtr);
                    const std::uint64_t kModified100ns = le64(contentPtr + 16);
                    const std::uint64_t kRealSize = le64(contentPtr + 48);
                    const std::uint8_t kNameLength = static_cast<std::uint8_t>(contentPtr[64]);
                    const std::uint8_t kNameNamespace = static_cast<std::uint8_t>(contentPtr[65]);
                    const std::size_t kNameBytes = static_cast<std::size_t>(kNameLength) * 2ULL;
                    if (66 + kNameBytes <= kContentLength)
                    {
                        const QString kCandidateName = QString::fromUtf16(
                            reinterpret_cast<const char16_t*>(contentPtr + 66),
                            static_cast<qsizetype>(kNameLength));
                        const int kScore = (kNameNamespace == 1 || kNameNamespace == 3) ? 2 : (kNameNamespace == 0 ? 1 : 0);
                        const std::uint64_t kParentIndexValue = (kParentRef & 0x0000FFFFFFFFFFFFULL);

                        // nameLinks: NTFS directory entries are essentially 'filename links', not 'one record per line'.
                        // Here, links are retained by 'parent directory + filename' to prevent multiple hard links in the same directory from being collapsed into one.
                        bool parentLinkUpdated = false;
                        for (NtfsNameLink& nameLink : recordOut.nameLinks)
                        {
                            if (nameLink.parentIndex != kParentIndexValue
                                || nameLink.fileName.compare(kCandidateName, Qt::CaseSensitive) != 0)
                            {
                                continue;
                            }

                            // For duplicate link names, retain only the namespace version better suited for display, primarily to eliminate case sensitivity and namespace duplicates.
                            if (kScore >= nameLink.nameScore)
                            {
                                nameLink.fileName = kCandidateName;
                                nameLink.nameScore = kScore;
                            }
                            parentLinkUpdated = true;
                            break;
                        }
                        if (!parentLinkUpdated)
                        {
                            NtfsNameLink nameLink{};
                            nameLink.parentIndex = kParentIndexValue;
                            nameLink.fileName = kCandidateName;
                            nameLink.nameScore = kScore;
                            recordOut.nameLinks.push_back(std::move(nameLink));
                        }

                        // preferredName: The record-level default name is used only for path hints and does not participate in directory line deduplication.
                        if (kScore >= preferredNameScore)
                        {
                            preferredNameScore = kScore;
                            preferredName = kCandidateName;
                            recordOut.parentIndex = kParentIndexValue;
                            recordOut.modifiedTime100ns = kModified100ns;
                            recordOut.sizeBytes = kRealSize;
                        }
                        else
                        {
                            if (recordOut.modifiedTime100ns == 0 && kModified100ns != 0)
                            {
                                recordOut.modifiedTime100ns = kModified100ns;
                            }
                            if (recordOut.sizeBytes == 0 && kRealSize != 0)
                            {
                                recordOut.sizeBytes = kRealSize;
                            }
                        }
                    }
                }
            }
            else if (kAttrType == 0x80)
            {
                // Process only unnamed primary data streams to avoid misinterpreting ADS as the file's primary content.
                if (kAttrNameLength != 0)
                {
                    attrOffset += kAttrLength;
                    continue;
                }

                const std::uint16_t kAttributeFlags =
                    le16(recordBytes.data() + attrOffset + 12);
                constexpr std::uint16_t kCompressedAttributeFlag = 0x0001;
                constexpr std::uint16_t kEncryptedAttributeFlag = 0x4000;
                const bool kUnsupportedAttributeEncoding =
                    (kAttributeFlags & (kCompressedAttributeFlag | kEncryptedAttributeFlag)) != 0;
                // If a single record contains multiple unnamed $DATA attributes, it typically indicates a multi-extent layout.
                // Single-record safe recovery accepts only one complete main data attribute starting from VCN 0.
                if (recordOut.hasPrimaryDataStream)
                {
                    recordOut.unsupportedDataStream = true;
                    attrOffset += kAttrLength;
                    continue;
                }
                recordOut.dataAttributeFlags = kAttributeFlags;
                recordOut.unsupportedDataStream =
                    recordOut.unsupportedDataStream || kUnsupportedAttributeEncoding;
                recordOut.hasPrimaryDataStream = true;

                if (!kNonResident)
                {
                    recordOut.hasPrimaryDataStream = true;
                    recordOut.nonResidentData = false;
                    const std::uint32_t kDataLength = le32(recordBytes.data() + attrOffset + 16);
                    const std::uint16_t kDataOffset = le16(recordBytes.data() + attrOffset + 20);
                    const std::size_t kDataStart = attrOffset + kDataOffset;
                    constexpr std::uint32_t kMaxResidentSize = 2 * 1024 * 1024;
                    if (kDataLength <= kMaxResidentSize && kDataStart + kDataLength <= kAttrEnd)
                    {
                        recordOut.residentReady = true;
                        recordOut.sizeBytes = static_cast<std::uint64_t>(kDataLength);
                        recordOut.initializedSizeBytes =
                            static_cast<std::uint64_t>(kDataLength);
                        if (captureResidentData && kDataLength > 0)
                        {
                            recordOut.residentData = QByteArray(
                                reinterpret_cast<const char*>(recordBytes.data() + kDataStart),
                                static_cast<int>(kDataLength));
                        }
                    }
                }
                else if (kAttrLength >= 64)
                {
                    recordOut.hasPrimaryDataStream = true;
                    recordOut.nonResidentData = true;
                    const std::uint64_t kLowestVcn =
                        le64(recordBytes.data() + attrOffset + 16);
                    const std::uint64_t kHighestVcn =
                        le64(recordBytes.data() + attrOffset + 24);
                    if (kLowestVcn != 0 || kHighestVcn < kLowestVcn)
                    {
                        recordOut.unsupportedDataStream = true;
                    }
                    const std::uint64_t kNonResidentSize = le64(recordBytes.data() + attrOffset + 48);
                    const std::uint64_t kInitializedSize =
                        le64(recordBytes.data() + attrOffset + 56);
                    if (kNonResidentSize > 0)
                    {
                        recordOut.sizeBytes = kNonResidentSize;
                    }
                    recordOut.initializedSizeBytes =
                        std::min(kInitializedSize, kNonResidentSize);
                    if (kInitializedSize > kNonResidentSize)
                    {
                        recordOut.unsupportedDataStream = true;
                    }

                    const std::uint16_t kRunListOffset = le16(recordBytes.data() + attrOffset + 32);
                    const std::size_t kRunListStart = attrOffset + kRunListOffset;
                    if (kRunListOffset >= 0x40
                        && kRunListStart < kAttrEnd)
                    {
                        std::vector<NtfsDataRun> runValues;
                        if (parseNtfsRunList(recordBytes.data() + kRunListStart, recordBytes.data() + kAttrEnd, runValues))
                        {
                            std::uint64_t parsedClusterCount = 0;
                            for (const NtfsDataRun& runValue : runValues)
                            {
                                if (parsedClusterCount >
                                    std::numeric_limits<std::uint64_t>::max() - runValue.clusterCount)
                                {
                                    recordOut.unsupportedDataStream = true;
                                    parsedClusterCount = 0;
                                    break;
                                }
                                parsedClusterCount += runValue.clusterCount;
                            }
                            if (parsedClusterCount == 0 ||
                                kHighestVcn < kLowestVcn ||
                                parsedClusterCount != (kHighestVcn - kLowestVcn + 1ULL))
                            {
                                recordOut.unsupportedDataStream = true;
                            }
                            recordOut.dataRuns = std::move(runValues);
                        }
                    }
                }
            }

            attrOffset += kAttrLength;
        }

        // parentHasDisplayNameSet: Records whether each parent directory already has a non-DOS name to avoid reading and writing the same vector during remove_if.
        QSet<qulonglong> parentHasDisplayNameSet;
        for (const NtfsNameLink& linkValue : recordOut.nameLinks)
        {
            if (linkValue.nameScore > 0)
            {
                parentHasDisplayNameSet.insert(static_cast<qulonglong>(linkValue.parentIndex));
            }
        }

        // Pure DOS short names are merely 8.3 aliases for the same directory link; they are not displayed separately when the parent directory already has a Win32/POSIX name.
        recordOut.nameLinks.erase(
            std::remove_if(
                recordOut.nameLinks.begin(),
                recordOut.nameLinks.end(),
                [&parentHasDisplayNameSet](const NtfsNameLink& linkValue) {
                    if (linkValue.nameScore != 0)
                    {
                        return false;
                    }
                    return parentHasDisplayNameSet.contains(static_cast<qulonglong>(linkValue.parentIndex));
                }),
            recordOut.nameLinks.end());

        recordOut.fileName = preferredName;
        return true;
    }

    // NtfsMftExtent:
    // - Represents a contiguous data segment of $MFT itself, while storing the starting VCN of that segment.
    // - With the starting VCN, 'logical record numbers' can be converted back to 'physical offsets within the volume'.
    struct NtfsMftExtent
    {
        std::uint64_t startVcn = 0;            // The starting virtual cluster number (VCN) of this extent within $MFT.
        std::uint64_t startLcn = 0;            // The starting logical cluster number of this segment within the volume.
        std::uint64_t clusterCount = 0;        // Cluster count for this segment.
    };

    // NtfsMftLocator:
    // - Save the runlist of unnamed main data streams in $MFT, converting MFT record numbers to actual byte offsets within the volume.
    // Why it is required:
    // - $MFT is almost certainly fragmented on volumes that have been in use for some time (extents are added after the MFT zone is exhausted);
    // Note: If continuing to advance linearly using 'MFT start offset + record number * record length', data read
    //   after the first extent belongs to other files: this may cause parsing failures and premature scan termination,
    //   or worse, incorrectly parse old data with FILE signatures into records with scrambled record numbers.
    struct NtfsMftLocator
    {
        std::vector<NtfsMftExtent> extents;    // $MFT data extent collection (sorted by VCN ascending).
        std::uint64_t bytesPerCluster = 0;     // Bytes per cluster.
        std::uint32_t bytesPerRecord = 0;      // Bytes per MFT record.
        std::uint64_t validRecordCount = 0;    // Valid record count calculated based on $MFT data length.

        // isUsable: Determines if the current locator supports record number conversion.
        bool isUsable() const
        {
            return !extents.empty() && bytesPerCluster > 0 && bytesPerRecord > 0;
        }

        // mappedRecordCapacity: Returns the upper limit of records actually covered by the runlist.
        std::uint64_t mappedRecordCapacity() const
        {
            if (!isUsable())
            {
                return 0;
            }
            const NtfsMftExtent& lastExtent = extents.back();
            if (lastExtent.startVcn >
                std::numeric_limits<std::uint64_t>::max() - lastExtent.clusterCount)
            {
                return 0;
            }
            const std::uint64_t kTotalClusters = lastExtent.startVcn + lastExtent.clusterCount;
            if (kTotalClusters > std::numeric_limits<std::uint64_t>::max() / bytesPerCluster)
            {
                return 0;
            }
            return (kTotalClusters * bytesPerCluster) / bytesPerRecord;
        }

        // tryMapRecordRange:
        // - Convert the MFT record number to a volume-relative byte offset and provide the remaining contiguous byte count in the data segment containing that record.
        // - Callers can use this to read multiple adjacent records at once, avoiding the huge overhead of 1KB reads one by one.
        // Output parameter volumeOffsetOut: Absolute offset of the record's first byte within the volume.
        // Output parameter contiguousBytesOut: The number of consecutive bytes starting from this offset that remain within the same data segment.
        // Returns: false if the record index is out of bounds or falls within a sparse region.
        bool tryMapRecordRange(
            const std::uint64_t recordIndex,
            std::uint64_t& volumeOffsetOut,
            std::uint64_t& contiguousBytesOut) const
        {
            volumeOffsetOut = 0;
            contiguousBytesOut = 0;
            if (!isUsable()
                || recordIndex > std::numeric_limits<std::uint64_t>::max() / bytesPerRecord)
            {
                return false;
            }

            const std::uint64_t kLogicalOffset = recordIndex * bytesPerRecord;
            const std::uint64_t kTargetVcn = kLogicalOffset / bytesPerCluster;
            const std::uint64_t kInClusterOffset = kLogicalOffset % bytesPerCluster;

            // extents are sorted by startVcn in ascending order; use binary search to locate the data extent containing the target VCN.
            const auto kExtentIt = std::upper_bound(
                extents.begin(),
                extents.end(),
                kTargetVcn,
                [](const std::uint64_t vcnValue, const NtfsMftExtent& extentValue) {
                    return vcnValue < extentValue.startVcn;
                });
            if (kExtentIt == extents.begin())
            {
                return false;
            }
            const NtfsMftExtent& extentValue = *(kExtentIt - 1);
            if (kTargetVcn >= extentValue.startVcn + extentValue.clusterCount)
            {
                return false;
            }

            const std::uint64_t kClusterOffsetInExtent = kTargetVcn - extentValue.startVcn;
            if (extentValue.startLcn >
                std::numeric_limits<std::uint64_t>::max() - kClusterOffsetInExtent)
            {
                return false;
            }
            const std::uint64_t kTargetLcn = extentValue.startLcn + kClusterOffsetInExtent;
            if (kTargetLcn > std::numeric_limits<std::uint64_t>::max() / bytesPerCluster)
            {
                return false;
            }
            const std::uint64_t kClusterOffsetBytes = kTargetLcn * bytesPerCluster;
            if (kClusterOffsetBytes >
                std::numeric_limits<std::uint64_t>::max() - kInClusterOffset)
            {
                return false;
            }

            volumeOffsetOut = kClusterOffsetBytes + kInClusterOffset;
            contiguousBytesOut =
                (extentValue.clusterCount - kClusterOffsetInExtent) * bytesPerCluster
                - kInClusterOffset;
            return contiguousBytesOut >= bytesPerRecord;
        }
    };

    // loadNtfsMftLocator:
    // - Note: Reads MFT record 0 ($MFT itself), parses its unnamed main data stream runlist, and builds a record number locator.
    // Call method:
    // - Call the volume offset fallback path once before starting traversal.
    // Input parameter volumeHandle: Opened volume handle.
    // Input parameter mftStartOffset: The starting byte offset of the MFT provided by the boot sector (Record 0 is always located here).
    // Output parameter locatorOut: Successfully constructed locator.
    // Output parameter errorTextOut: Failure reason text.
    // Return value: Returns true on success, false on failure (the caller may degrade to linear progression).
    bool loadNtfsMftLocator(
        const HANDLE volumeHandle,
        const std::uint64_t mftStartOffset,
        const std::uint16_t bytesPerSector,
        const std::uint64_t bytesPerCluster,
        const std::uint32_t bytesPerRecord,
        NtfsMftLocator& locatorOut,
        QString& errorTextOut)
    {
        locatorOut = NtfsMftLocator{};
        errorTextOut.clear();

        std::vector<std::byte> firstRecordBytes(bytesPerRecord);
        if (!readBytesAtSectorAlignedOffset(
            volumeHandle,
            mftStartOffset,
            bytesPerRecord,
            bytesPerSector,
            QStringLiteral("读取$MFT记录0"),
            0,
            firstRecordBytes.data(),
            errorTextOut))
        {
            return false;
        }

        NtfsRawRecord mftRecordValue{};
        if (!parseNtfsRecord(firstRecordBytes, 0, bytesPerSector, false, mftRecordValue))
        {
            errorTextOut = QStringLiteral("解析 $MFT 记录 0 失败，无法建立 MFT runlist 映射。");
            return false;
        }
        if (!mftRecordValue.nonResidentData || mftRecordValue.dataRuns.empty())
        {
            errorTextOut = QStringLiteral("$MFT 记录 0 未给出可用的非驻留 runlist。");
            return false;
        }

        std::uint64_t currentVcn = 0;
        locatorOut.extents.reserve(mftRecordValue.dataRuns.size());
        for (const NtfsDataRun& runValue : mftRecordValue.dataRuns)
        {
            // $MFT itself should not contain sparse runs; if one appears, the runlist parsing is untrustworthy.
            if (runValue.isSparse || runValue.clusterCount == 0)
            {
                errorTextOut = QStringLiteral("$MFT runlist 含稀疏或空数据段，映射不可信。");
                return false;
            }
            if (currentVcn > std::numeric_limits<std::uint64_t>::max() - runValue.clusterCount)
            {
                errorTextOut = QStringLiteral("$MFT runlist 虚拟簇号累加溢出。");
                return false;
            }

            NtfsMftExtent extentValue{};
            extentValue.startVcn = currentVcn;
            extentValue.startLcn = runValue.startLcn;
            extentValue.clusterCount = runValue.clusterCount;
            locatorOut.extents.push_back(extentValue);
            currentVcn += runValue.clusterCount;
        }

        locatorOut.bytesPerCluster = bytesPerCluster;
        locatorOut.bytesPerRecord = bytesPerRecord;
        locatorOut.validRecordCount =
            (mftRecordValue.sizeBytes >= bytesPerRecord)
            ? (mftRecordValue.sizeBytes / bytesPerRecord)
            : 0;

        // hasAttributeList indicates that the $MFT runlist may be split across other records; this only covers the
        // portion listed in the current record, so the caller must be informed that the mapping range may be incomplete.
        if (mftRecordValue.hasAttributeList)
        {
            errorTextOut = QStringLiteral("$MFT 使用 $ATTRIBUTE_LIST，runlist 可能不完整。");
        }
        return locatorOut.isUsable();
    }

    // readNtfsRecordViaLocator:
    // - Read a single record via MFT runlist mapping and cache adjacent records internally in large blocks.
    // - Block caching never spans data segments, so block offsets and record numbers always correspond one-to-one.
    // Input parameters chunkBytes/chunkFirstRecord/chunkRecordCount: The block cache state held by the caller.
    // Output parameter recordBytesOut: the raw bytes of the target record.
    // Return value: returns true on success; returns false if the record number cannot be mapped or if the read fails.
    bool readNtfsRecordViaLocator(
        const HANDLE volumeHandle,
        const NtfsMftLocator& locatorValue,
        const std::uint16_t bytesPerSector,
        const std::uint64_t recordIndex,
        const std::uint64_t parseCount,
        std::vector<std::byte>& chunkBytes,
        std::uint64_t& chunkFirstRecord,
        std::uint64_t& chunkRecordCount,
        std::vector<std::byte>& recordBytesOut,
        QString& errorTextOut)
    {
        const std::uint32_t kBytesPerRecord = locatorValue.bytesPerRecord;
        if (kBytesPerRecord == 0)
        {
            errorTextOut = QStringLiteral("MFT 记录长度为 0。");
            return false;
        }

        const bool kInsideChunk =
            (chunkRecordCount > 0)
            && (recordIndex >= chunkFirstRecord)
            && (recordIndex - chunkFirstRecord < chunkRecordCount);
        if (!kInsideChunk)
        {
            std::uint64_t volumeOffset = 0;
            std::uint64_t contiguousBytes = 0;
            if (!locatorValue.tryMapRecordRange(recordIndex, volumeOffset, contiguousBytes))
            {
                chunkRecordCount = 0;
                errorTextOut = QStringLiteral("记录号 %1 超出 $MFT runlist 覆盖范围。")
                    .arg(static_cast<qulonglong>(recordIndex));
                return false;
            }

            // Single-read limit of 1MB: balances throughput and memory usage while avoiding crossing the current data segment.
            constexpr std::uint64_t kMftChunkTargetBytes = 1ULL * 1024ULL * 1024ULL;
            const std::uint64_t kRemainingRecords = (parseCount > recordIndex)
                ? (parseCount - recordIndex)
                : 1ULL;
            std::uint64_t chunkRecords = std::min<std::uint64_t>(
                { kMftChunkTargetBytes / kBytesPerRecord,
                  contiguousBytes / kBytesPerRecord,
                  kRemainingRecords });
            if (chunkRecords == 0)
            {
                chunkRecords = 1;
            }

            const std::uint64_t kChunkSizeBytes = chunkRecords * kBytesPerRecord;
            chunkBytes.resize(static_cast<std::size_t>(kChunkSizeBytes));
            if (!readBytesAtSectorAlignedOffset(
                volumeHandle,
                volumeOffset,
                static_cast<std::uint32_t>(kChunkSizeBytes),
                bytesPerSector,
                QStringLiteral("按$MFT runlist读取记录块"),
                0,
                chunkBytes.data(),
                errorTextOut))
            {
                chunkRecordCount = 0;
                return false;
            }
            chunkFirstRecord = recordIndex;
            chunkRecordCount = chunkRecords;
        }

        const std::size_t kInChunkOffset =
            static_cast<std::size_t>((recordIndex - chunkFirstRecord) * kBytesPerRecord);
        recordBytesOut.resize(kBytesPerRecord);
        std::memcpy(recordBytesOut.data(), chunkBytes.data() + kInChunkOffset, kBytesPerRecord);
        return true;
    }

    // buildTypeText: Maps file types to display text for the UI.
    QString buildTypeText(const QString& fileName, const bool isDirectory)
    {
        if (isDirectory)
        {
            return QStringLiteral("目录");
        }
        const QString kSuffixText = QFileInfo(fileName).suffix().trimmed();
        return kSuffixText.isEmpty() ? QStringLiteral("文件") : (kSuffixText.toUpper() + QStringLiteral(" 文件"));
    }

    // splitRelativeSegments purpose: Extract volume-relative path segments (excluding the drive letter).
    QStringList splitRelativeSegments(const QString& absolutePath)
    {
        QString cleanPathText = QDir::cleanPath(QDir::fromNativeSeparators(absolutePath));
        if (cleanPathText.size() >= 2 && cleanPathText[1] == QChar(':'))
        {
            cleanPathText = cleanPathText.mid(2);
        }
        if (cleanPathText.startsWith('/'))
        {
            cleanPathText.remove(0, 1);
        }
        return cleanPathText.isEmpty() ? QStringList() : cleanPathText.split('/', Qt::SkipEmptyParts);
    }

    // tryLoadNtfsRecordsByFsctl:
    // - Extracts MFT records one by one from the volume handle via FSCTL_GET_NTFS_FILE_RECORD.
    // - Does not rely on the direct $MFT path, allowing bypass of access restrictions on \\.\X:\$MFT;
    // - Correctly handles MFT fragmentation, avoiding record loss unlike 'volume offset sequential reads'.
    // Parameter volumeHandle:
    // - Opened volume handle (\\.\X:).
    // Parameter bytesPerRecordHint:
    // - MFT record size inferred from the boot sector (fallback).
    // Parameter maxRecordCount:
    // - Maximum number of records to scan in this round.
    // Parameter recordsOut:
    // - Output: The collection of parsed NTFS records.
    // Parameter errorTextOut:
    // - Returns text describing the failure reason.
    // Return value:
    // - Return true on success; return false on failure.
    bool tryLoadNtfsRecordsByFsctl(
        const HANDLE volumeHandle,
        const std::uint16_t bytesPerSectorHint,
        const std::uint32_t bytesPerRecordHint,
        const std::uint64_t maxRecordCount,
        const bool captureResidentData,
        const bool keepNamelessRecords,
        const std::function<void(int, const QString&)>& progressCallback,
        std::vector<NtfsRawRecord>& recordsOut,
        QString& errorTextOut)
    {
        NTFS_VOLUME_DATA_BUFFER volumeData{};
        DWORD returnedBytes = 0;
        const BOOL kVolumeDataOk = ::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            nullptr,
            0,
            &volumeData,
            static_cast<DWORD>(sizeof(volumeData)),
            &returnedBytes,
            nullptr);
        if (kVolumeDataOk == FALSE)
        {
            errorTextOut = QStringLiteral("FSCTL_GET_NTFS_VOLUME_DATA失败, code=%1").arg(::GetLastError());
            return false;
        }

        // bytesPerRecord: Prioritizes the record size returned by FSCTL; falls back to the boot sector estimate in case of anomalies.
        std::uint32_t bytesPerRecord = volumeData.BytesPerFileRecordSegment;
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            bytesPerRecord = bytesPerRecordHint;
        }
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            errorTextOut = QStringLiteral("FSCTL回退失败：MFT记录大小异常, bytesPerRecord=%1").arg(bytesPerRecord);
            return false;
        }

        // mftRecordCountByValidData: Estimates the number of traversable records based on the MFT valid data length.
        const std::uint64_t kMftRecordCountByValidData =
            static_cast<std::uint64_t>(volumeData.MftValidDataLength.QuadPart)
            / static_cast<std::uint64_t>(bytesPerRecord);
        std::uint64_t parseCount = std::min(kMftRecordCountByValidData, maxRecordCount);
        if (parseCount == 0)
        {
            // Some systems may return 0; this provides a conservative fallback to avoid immediate failure.
            parseCount = std::min<std::uint64_t>(maxRecordCount, 65536ULL);
        }

        // outputBufferBytes: FSCTL output buffer size (structure header + one record).
        const std::size_t kOutputHeaderBytes = offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer);
        const std::size_t kOutputBufferBytes = kOutputHeaderBytes + static_cast<std::size_t>(bytesPerRecord) + 16ULL;
        std::vector<std::uint8_t> outputBuffer(kOutputBufferBytes);

        recordsOut.clear();
        recordsOut.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(parseCount, 200000ULL)));

        // Behavior of FSCTL_GET_NTFS_FILE_RECORD:
        // - Returns the most recent active record with index <= input value.
        // - Therefore, enumeration must be from high to low; forward scanning from 0 is not allowed.
        std::uint64_t requestRecordIndex = (parseCount > 0) ? (parseCount - 1) : 0;
        std::uint64_t lastReturnedRecordIndex = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t visitedCount = 0;                 // visitedCount: count of visited records (subject to maxRecordCount limit).
        std::uint32_t consecutiveQueryFailCount = 0;    // Count of consecutive query failures.
        std::uint32_t consecutiveInvalidRecordCount = 0; // Count of consecutive invalid records.
        int lastReportedPercent = -1;                   // lastReportedPercent: The most recently reported percentage for the FSCTL branch.
        while (visitedCount < parseCount)
        {
            NTFS_FILE_RECORD_INPUT_BUFFER inputBuffer{};
            inputBuffer.FileReferenceNumber.QuadPart = static_cast<LONGLONG>(requestRecordIndex);

            returnedBytes = 0;
            const BOOL kQueryOk = ::DeviceIoControl(
                volumeHandle,
                FSCTL_GET_NTFS_FILE_RECORD,
                &inputBuffer,
                static_cast<DWORD>(sizeof(inputBuffer)),
                outputBuffer.data(),
                static_cast<DWORD>(outputBuffer.size()),
                &returnedBytes,
                nullptr);
            if (kQueryOk == FALSE)
            {
                const DWORD kQueryErrorCode = ::GetLastError();
                ++consecutiveQueryFailCount;
                if (!recordsOut.empty()
                    && consecutiveQueryFailCount > 2048)
                {
                    break;
                }

                if (kQueryErrorCode == ERROR_HANDLE_EOF || kQueryErrorCode == ERROR_FILE_NOT_FOUND)
                {
                    break;
                }

                if (requestRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex -= 1;
                continue;
            }
            consecutiveQueryFailCount = 0;
            visitedCount += 1;
            if (progressCallback)
            {
                const int kPercentValue = 10
                    + static_cast<int>((visitedCount * 70ULL) / std::max<std::uint64_t>(parseCount, 1ULL));
                if (kPercentValue != lastReportedPercent
                    && ((visitedCount % 4096ULL) == 0 || visitedCount == parseCount))
                {
                    lastReportedPercent = kPercentValue;
                    progressCallback(kPercentValue, QStringLiteral("FSCTL扫描 MFT 记录"));
                }
            }

            if (returnedBytes <= kOutputHeaderBytes)
            {
                if (requestRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex -= 1;
                continue;
            }
            NTFS_FILE_RECORD_OUTPUT_BUFFER* outputRecord =
                reinterpret_cast<NTFS_FILE_RECORD_OUTPUT_BUFFER*>(outputBuffer.data());
            const std::uint32_t kFileRecordLength = outputRecord->FileRecordLength;
            const std::uint64_t kActualRecordIndex =
                static_cast<std::uint64_t>(outputRecord->FileReferenceNumber.QuadPart & 0x0000FFFFFFFFFFFFULL);

            // If the returned record index exceeds the requested value, the current return violates the 'downward enumeration' expectation; directly downgrade the request index and continue.
            if (kActualRecordIndex > requestRecordIndex)
            {
                if (requestRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex -= 1;
                continue;
            }

            // Prevent infinite loops caused by continuously returning the same record.
            if (kActualRecordIndex == lastReturnedRecordIndex)
            {
                if (kActualRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex = kActualRecordIndex - 1;
                continue;
            }
            lastReturnedRecordIndex = kActualRecordIndex;

            if (kFileRecordLength < 64
                || kFileRecordLength > bytesPerRecord
                || kOutputHeaderBytes + kFileRecordLength > returnedBytes
                || kOutputHeaderBytes + kFileRecordLength > outputBuffer.size())
            {
                if (kActualRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex = kActualRecordIndex - 1;
                continue;
            }

            std::vector<std::byte> recordBytes(kFileRecordLength);
            std::memcpy(
                recordBytes.data(),
                outputBuffer.data() + kOutputHeaderBytes,
                kFileRecordLength);

            NtfsRawRecord recordValue{};
            if (!parseNtfsRecord(recordBytes, kActualRecordIndex, bytesPerSectorHint, captureResidentData, recordValue))
            {
                ++consecutiveInvalidRecordCount;
                if (!recordsOut.empty()
                    && consecutiveInvalidRecordCount > 8192)
                {
                    break;
                }

                if (kActualRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex = kActualRecordIndex - 1;
                continue;
            }

            consecutiveInvalidRecordCount = 0;
            if (!keepNamelessRecords
                && recordValue.fileName.isEmpty()
                && recordValue.recordIndex != 5)
            {
                if (kActualRecordIndex == 0)
                {
                    break;
                }
                requestRecordIndex = kActualRecordIndex - 1;
                continue;
            }
            recordsOut.push_back(std::move(recordValue));

            if (kActualRecordIndex == 0)
            {
                break;
            }
            requestRecordIndex = kActualRecordIndex - 1;
        }

        if (recordsOut.empty())
        {
            errorTextOut = QStringLiteral("FSCTL回退失败：未解析到任何MFT记录。");
            return false;
        }
        return true;
    }

    // loadNtfsRecords: Scans $MFT and parses records.
    // Notes:
    // 1) Prioritizes reading via the \\.\X:\$MFT file method;
    // 2) If opening $MFT fails (commonly ERROR_ACCESS_DENIED=5), automatically fall back to "volume offset direct read".
    // 3) Fallback mode locates and reads based on the MFT starting cluster in the NTFS boot sector to avoid interception by $MFT path permissions.
    bool loadNtfsRecords(
        const QString& volumeRoot,
        std::vector<NtfsRawRecord>& recordsOut,
        QString& errorTextOut,
        const std::uint64_t maxRecordCountHint,
        const bool allowFsctlFallback,
        const bool useCache,
        const bool copyRecordsOut,
        const bool captureResidentData,
        const bool keepNamelessRecords,
        const NtfsRecordKeepPolicy keepPolicy,
        const std::function<void(int, const QString&)>& progressCallback,
        std::shared_ptr<const NtfsCacheEntry>* cacheEntryOut)
    {
        const std::wstring kCacheKey = toWide(volumeRoot.toUpper());
        const qint64 kNowMsec = QDateTime::currentMSecsSinceEpoch();
        constexpr qint64 kNtfsCacheTtlMsec = 60000; // Cache for 60 seconds to avoid repeated full volume scans on the same volume in a short time.
        const bool kKeepDeletedAndDirectoriesOnly =
            (keepPolicy == NtfsRecordKeepPolicy::kDeletedAndDirectories);
        // Hard limit varies by retention policy:
        // - All mode keeps every record in memory, so limit it to at most 1.5 million records;
        // - In DeletedAndDirectories mode, only deleted items and directories are retained, potentially covering the entire $MFT.
        //   The value here is a pathological upper bound; actual scan volume is determined by the number of valid records in $MFT.
        const std::uint64_t kNtfsHardMaxRecordCount =
            kKeepDeletedAndDirectoriesOnly ? 64000000ULL : 1500000ULL;
        const std::uint64_t kEffectiveMaxRecordCount = (maxRecordCountHint == 0)
            ? kNtfsHardMaxRecordCount
            : std::min<std::uint64_t>(maxRecordCountHint, kNtfsHardMaxRecordCount);
        // Do not cache if the record set is incomplete, to avoid polluting directory listings that depend on complete records.
        const bool kCacheAllowed = useCache && !kKeepDeletedAndDirectoriesOnly;
        if (kCacheAllowed)
        {
            std::scoped_lock<std::mutex> lock(gNtfsCacheMutex);
            const auto kCacheIt = gNtfsCache.find(kCacheKey);
            if (kCacheIt != gNtfsCache.end()
                && (kNowMsec - kCacheIt->second->loadedMsec) <= kNtfsCacheTtlMsec
                && kCacheIt->second->recordLimit >= kEffectiveMaxRecordCount)
            {
                if (kCacheIt->second->fsctlFallbackAllowed == allowFsctlFallback)
                {
                    if (copyRecordsOut)
                    {
                        recordsOut = kCacheIt->second->records;
                    }
                    else
                    {
                        recordsOut.clear();
                    }
                    if (cacheEntryOut != nullptr)
                    {
                        *cacheEntryOut = kCacheIt->second;
                    }
                    if (progressCallback)
                    {
                        progressCallback(75, QStringLiteral("命中 NTFS 缓存"));
                    }
                    return true;
                }
            }
        }

        const QString kVolumeDevicePath = buildVolumeDevicePath(volumeRoot);
        QString openVolumeErrorText;
        HANDLE volumeHandle = openReadHandle(kVolumeDevicePath, openVolumeErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openVolumeErrorText;
            return false;
        }
        if (progressCallback)
        {
            progressCallback(4, QStringLiteral("已打开卷句柄"));
        }

        // Read the NTFS boot sector first; both normal and fallback modes depend on these parameters.
        std::array<std::byte, 512> bootBytes{};
        if (!readBytesAtOffset(volumeHandle, 0, 512, bootBytes.data(), errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }
        if (progressCallback)
        {
            progressCallback(8, QStringLiteral("已读取 NTFS 引导区"));
        }

        const QByteArray kOemText(reinterpret_cast<const char*>(bootBytes.data() + 3), 8);
        if (!kOemText.startsWith("NTFS"))
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("不是 NTFS 卷。");
            return false;
        }

        const std::uint16_t kBytesPerSector = le16(bootBytes.data() + 11);
        const std::uint8_t kSectorsPerCluster = static_cast<std::uint8_t>(bootBytes[13]);
        if (kBytesPerSector == 0 || kSectorsPerCluster == 0)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("NTFS 引导参数异常：扇区或簇大小为 0。");
            return false;
        }

        const std::uint64_t kBytesPerCluster =
            static_cast<std::uint64_t>(kBytesPerSector) *
            static_cast<std::uint64_t>(kSectorsPerCluster);
        const std::uint64_t kMftStartCluster = le64(bootBytes.data() + 0x30);
        if (kMftStartCluster >
            std::numeric_limits<std::uint64_t>::max() /
                kBytesPerCluster)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("卷偏移记录解析失败。");
            return false;
        }
        const std::uint64_t kMftStartOffset = kMftStartCluster * kBytesPerCluster;

        const std::int8_t kClustersPerRecord = static_cast<std::int8_t>(bootBytes[64]);
        std::uint32_t bytesPerRecord = 1024;
        if (kClustersPerRecord < 0)
        {
            const int kPowerValue = -kClustersPerRecord;
            bytesPerRecord = (1u << kPowerValue);
        }
        else
        {
            bytesPerRecord =
                static_cast<std::uint32_t>(kBytesPerSector) *
                static_cast<std::uint32_t>(kSectorsPerCluster) *
                static_cast<std::uint32_t>(kClustersPerRecord);
        }
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("MFT记录大小异常: %1").arg(bytesPerRecord);
            return false;
        }

        const std::uint64_t kMaxRecordCount = kEffectiveMaxRecordCount;
        HANDLE sourceHandle = INVALID_HANDLE_VALUE;        // sourceHandle: The actual handle read in this round ($MFT or volume handle).
        std::uint64_t sourceBaseOffset = 0;               // sourceBaseOffset: Read start offset ($MFT=0, volume rollback=MFT offset).
        std::uint64_t parseCount = 0;                     // parseCount: Planned number of records to parse.
        bool usingVolumeFallback = false;                 // usingVolumeFallback: Whether to enter the volume offset direct-read fallback.
        QString fallbackReasonText;                       // fallbackReasonText: Fallback reason log text.
        NtfsMftLocator mftLocator;                        // mftLocator: Uses the $MFT's own runlist to precisely locate records when rolling back volume offsets.
        bool usingMftLocator = false;                     // usingMftLocator: Indicates whether record numbers are advanced via runlist mapping rather than linearly in this round.

        // First priority: directly read \\.\X:\$MFT.
        const QString kMftPath = QStringLiteral("\\\\.\\%1\\$MFT").arg(volumeRoot.left(2).toUpper());
        QString openMftErrorText;
        HANDLE mftHandle = openReadHandle(kMftPath, openMftErrorText);
        if (mftHandle != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER mftFileSize{};
            if (::GetFileSizeEx(mftHandle, &mftFileSize) == FALSE)
            {
                fallbackReasonText = QStringLiteral("读取$MFT大小失败, code=%1，改用卷偏移回退。")
                    .arg(::GetLastError());
                usingVolumeFallback = true;
            }
            else
            {
                const std::uint64_t kRecordCount =
                    static_cast<std::uint64_t>(mftFileSize.QuadPart) / bytesPerRecord;
                parseCount = std::min(kRecordCount, kMaxRecordCount);
                sourceHandle = mftHandle;
                sourceBaseOffset = 0;
            }
        }
        else
        {
            // Typical scenario: CreateFile \\.\C:\$MFT returns code=5.
            fallbackReasonText = openMftErrorText;
            usingVolumeFallback = true;
        }

        // Fallback path:
        // 1) First attempt FSCTL_GET_NTFS_FILE_RECORD (handles MFT fragmentation);
        // 2) If FSCTL also fails, fall back to 'volume offset sequential read'.
        if (usingVolumeFallback)
        {
            if (mftHandle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(mftHandle);
                mftHandle = INVALID_HANDLE_VALUE;
            }

            // First fallback: read MFT by record number via FSCTL.
            std::vector<NtfsRawRecord> fsctlRecords;
            QString fsctlErrorText;
            if (allowFsctlFallback
                && tryLoadNtfsRecordsByFsctl(
                    volumeHandle,
                    kBytesPerSector,
                    bytesPerRecord,
                    kMaxRecordCount,
                    captureResidentData,
                    keepNamelessRecords,
                    progressCallback,
                    fsctlRecords,
                    fsctlErrorText))
            {
                recordsOut = std::move(fsctlRecords);
                ::CloseHandle(volumeHandle);

                {
                    KLogEvent fallbackEvent;
                    info << fallbackEvent
                        << "[FileDock] $MFT 打开失败，启用FSCTL回退解析, volume="
                        << volumeRoot.toStdString()
                        << ", reason="
                        << fallbackReasonText.toStdString()
                        << ", rows="
                        << recordsOut.size()
                        << eol;
                }

                if (kCacheAllowed)
                {
                    std::shared_ptr<NtfsCacheEntry> cacheEntry = std::make_shared<NtfsCacheEntry>();
                    if (copyRecordsOut)
                    {
                        cacheEntry->records = recordsOut;
                    }
                    else
                    {
                        cacheEntry->records = std::move(recordsOut);
                    }
                    cacheEntry->loadedMsec = kNowMsec;
                    cacheEntry->recordLimit = kMaxRecordCount;
                    cacheEntry->fsctlFallbackAllowed = allowFsctlFallback;
                    buildNtfsCacheIndex(*cacheEntry);

                    std::scoped_lock<std::mutex> lock(gNtfsCacheMutex);
                    gNtfsCache[kCacheKey] = cacheEntry;
                    if (cacheEntryOut != nullptr)
                    {
                        *cacheEntryOut = cacheEntry;
                    }
                }
                if (!copyRecordsOut)
                {
                    recordsOut.clear();
                }
                return true;
            }

            if (!fsctlErrorText.isEmpty())
            {
                fallbackReasonText =
                    fallbackReasonText.isEmpty()
                    ? fsctlErrorText
                    : (fallbackReasonText + QStringLiteral("; FSCTL回退失败: ") + fsctlErrorText);
            }

            // Second-level fallback: direct read from volume offset.
            // First, read the 0th MFT record ($MFT itself) and parse its runlist:
            // 1) runlist provides the actual MFT data length, avoiding pushing parseCount to the hard limit by estimating based on full volume space;
            // 2) More critically, it enables precise mapping of record numbers to physical offsets within the volume. When
            //    $MFT is fragmented, it avoids reading data from other files after the first extent, unlike 'linear progression'.
            std::uint64_t estimatedMftRecordCount = 0;
            {
                QString locatorErrorText;
                if (loadNtfsMftLocator(
                    volumeHandle,
                    kMftStartOffset,
                    kBytesPerSector,
                    kBytesPerCluster,
                    bytesPerRecord,
                    mftLocator,
                    locatorErrorText))
                {
                    usingMftLocator = true;
                    estimatedMftRecordCount = mftLocator.validRecordCount;
                    const std::uint64_t kMappedRecordCapacity = mftLocator.mappedRecordCapacity();
                    if (kMappedRecordCapacity > 0
                        && (estimatedMftRecordCount == 0
                            || estimatedMftRecordCount > kMappedRecordCapacity))
                    {
                        // The runlist coverage is the true upper limit for readable data; data beyond this range will result in out-of-bounds reads.
                        estimatedMftRecordCount = kMappedRecordCapacity;
                    }
                    if (!locatorErrorText.isEmpty())
                    {
                        fallbackReasonText += QStringLiteral("; MFT映射告警: ") + locatorErrorText;
                    }
                }
                else
                {
                    // When mapping construction fails, fall back to the legacy linear scan, which can only cover the first data segment of $MFT.
                    fallbackReasonText +=
                        QStringLiteral("; 构建$MFT映射失败(退化为线性推进): ") + locatorErrorText;
                }
            }

            // First get volume length to calculate theoretical readable record count.
            std::uint64_t volumeBytes = 0;
            GET_LENGTH_INFORMATION lengthInfo{};
            DWORD returnedBytes = 0;
            if (::DeviceIoControl(
                volumeHandle,
                IOCTL_DISK_GET_LENGTH_INFO,
                nullptr,
                0,
                &lengthInfo,
                static_cast<DWORD>(sizeof(lengthInfo)),
                &returnedBytes,
                nullptr) != FALSE)
            {
                volumeBytes = static_cast<std::uint64_t>(lengthInfo.Length.QuadPart);
            }
            else
            {
                LARGE_INTEGER fallbackLength{};
                if (::GetFileSizeEx(volumeHandle, &fallbackLength) != FALSE)
                {
                    volumeBytes = static_cast<std::uint64_t>(fallbackLength.QuadPart);
                }
            }

            if (volumeBytes == 0 || kMftStartOffset >= volumeBytes)
            {
                ::CloseHandle(volumeHandle);
                errorTextOut = QStringLiteral(
                    "卷级回退失败：无法计算有效 MFT 区间。mftOffset=%1, volumeBytes=%2, reason=%3")
                    .arg(static_cast<qulonglong>(kMftStartOffset))
                    .arg(static_cast<qulonglong>(volumeBytes))
                    .arg(fallbackReasonText);
                return false;
            }

            const std::uint64_t kReadableBytes = volumeBytes - kMftStartOffset;
            const std::uint64_t kFallbackRecordCountByVolume = kReadableBytes / bytesPerRecord;
            if (estimatedMftRecordCount > 0)
            {
                parseCount = std::min(estimatedMftRecordCount, kMaxRecordCount);
            }
            else
            {
                parseCount = std::min(kFallbackRecordCountByVolume, kMaxRecordCount);
            }
            if (parseCount == 0)
            {
                ::CloseHandle(volumeHandle);
                errorTextOut = QStringLiteral(
                    "卷级回退失败：MFT 可读记录数为 0。mftOffset=%1, volumeBytes=%2")
                    .arg(static_cast<qulonglong>(kMftStartOffset))
                    .arg(static_cast<qulonglong>(volumeBytes));
                return false;
            }

            sourceHandle = volumeHandle;
            sourceBaseOffset = kMftStartOffset;

            // Log entry for entering volume offset fallback to help diagnose FSCTL failure causes.
            KLogEvent fallbackEvent;
            info << fallbackEvent
                << "[FileDock] $MFT/FSCTL 均失败，启用卷偏移兜底解析, volume="
                << volumeRoot.toStdString()
                << ", reason="
                << fallbackReasonText.toStdString()
                << ", mftOffset="
                << static_cast<qulonglong>(kMftStartOffset)
                << ", parseCount="
                << static_cast<qulonglong>(parseCount)
                << ", estimatedByMft="
                << static_cast<qulonglong>(estimatedMftRecordCount)
                << ", mftLocator="
                << (usingMftLocator ? "runlist" : "linear")
                << ", mftExtents="
                << mftLocator.extents.size()
                << eol;
        }

        // Generic parsing flow: Read and parse records from sourceHandle by record index.
        std::vector<std::byte> recordBytes(bytesPerRecord);
        std::vector<std::byte> locatorChunkBytes;      // locatorChunkBytes: Record block buffer in runlist mode.
        std::uint64_t locatorChunkFirstRecord = 0;     // locatorChunkFirstRecord: The record number of the first record in the chunk cache.
        std::uint64_t locatorChunkRecordCount = 0;     // locatorChunkRecordCount: Number of records covered by the block cache.
        recordsOut.clear();
        recordsOut.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(parseCount, 200000ULL)));
        std::uint32_t consecutiveReadFailCount = 0;    // Consecutive read failure count: prevents prolonged blocking caused by repeated failures at the end of the volume.
        std::uint32_t consecutiveEmptyCount = 0;       // Consecutive empty record count: Linear advancement mode used to stop invalid scans early.
        std::uint32_t consecutiveInvalidCount = 0;     // Consecutive invalid record count: used in linear progression mode to identify when the process has left the valid MFT range.
        std::uint64_t validRecordCount = 0;            // Count of successfully parsed valid records, used to terminate early when encountering invalid intervals.
        std::uint64_t totalReadFailCount = 0;          // Accumulate read failure count (for diagnostics).
        std::uint64_t totalInvalidCount = 0;           // Accumulated count of parsing failures (for diagnostics).
        std::uint64_t stoppedAtIndex = parseCount;     // Actual stop position (for diagnostics; equals parseCount indicates full traversal).
        QString lastReadFailText;                      // Reason for the last read failure (for diagnostics).
        int lastReportedPercent = -1;                  // lastReportedPercent: The most recently reported percentage for the sequential scan branch.
        for (std::uint64_t indexValue = 0; indexValue < parseCount; ++indexValue)
        {
            if (progressCallback
                && (((indexValue % 4096ULL) == 0) || (indexValue + 1 == parseCount)))
            {
                const int kPercentValue = 10
                    + static_cast<int>(((indexValue + 1ULL) * 70ULL) / std::max<std::uint64_t>(parseCount, 1ULL));
                if (kPercentValue != lastReportedPercent)
                {
                    lastReportedPercent = kPercentValue;
                    progressCallback(
                        kPercentValue,
                        usingMftLocator
                        ? QStringLiteral("按 $MFT runlist 扫描记录")
                        : (usingVolumeFallback
                            ? QStringLiteral("按卷偏移扫描 MFT 记录")
                            : QStringLiteral("按 $MFT 逻辑文件扫描记录")));
                }
            }

            QString readErrorText;
            bool readOk = false;
            if (usingMftLocator)
            {
                // runlist mapping mode: record number → volume-internal physical offset; $MFT fragmentation does not cause misalignment.
                readOk = readNtfsRecordViaLocator(
                    sourceHandle,
                    mftLocator,
                    kBytesPerSector,
                    indexValue,
                    parseCount,
                    locatorChunkBytes,
                    locatorChunkFirstRecord,
                    locatorChunkRecordCount,
                    recordBytes,
                    readErrorText);
            }
            else
            {
                // Linear progression mode: used only when the $MFT logical file is readable or runlist mapping construction fails.
                // The volume handle requires access aligned to logical sectors. Since 1KB records on 4K sectors are not naturally
                // aligned, we uniformly use aligned reads here to prevent ReadFile from directly returning ERROR_INVALID_PARAMETER.
                const std::uint64_t kOffsetValue = sourceBaseOffset + indexValue * bytesPerRecord;
                recordBytes.resize(bytesPerRecord);
                readOk = readBytesAtSectorAlignedOffset(
                    sourceHandle,
                    kOffsetValue,
                    bytesPerRecord,
                    kBytesPerSector,
                    QStringLiteral("线性扫描 MFT 记录"),
                    0,
                    recordBytes.data(),
                    readErrorText);
            }
            if (!readOk)
            {
                ++consecutiveReadFailCount;
                ++totalReadFailCount;
                lastReadFailText = readErrorText;
                if (consecutiveReadFailCount >= 8)
                {
                    stoppedAtIndex = indexValue;
                    break;
                }
                continue;
            }
            consecutiveReadFailCount = 0;

            NtfsRawRecord recordValue{};
            if (!parseNtfsRecord(recordBytes, indexValue, kBytesPerSector, captureResidentData, recordValue))
            {
                ++consecutiveInvalidCount;
                ++totalInvalidCount;

                // If a large block of all-0 bytes is encountered, the linear advancement mode indicates proximity to the end of the valid MFT, allowing for early termination.
                bool allZeroBytes = true;
                for (const std::byte kByteValue : recordBytes)
                {
                    if (kByteValue != std::byte{ 0 })
                    {
                        allZeroBytes = false;
                        break;
                    }
                }
                if (allZeroBytes)
                {
                    ++consecutiveEmptyCount;
                    if (usingVolumeFallback
                        && !usingMftLocator
                        && indexValue > 4096
                        && consecutiveEmptyCount > 2048)
                    {
                        stoppedAtIndex = indexValue;
                        break;
                    }
                }
                else
                {
                    consecutiveEmptyCount = 0;
                }

                // These two early terminations apply only to the linear progression mode: there, consecutive invalid entries indeed indicate exiting the MFT data region.
                // In runlist mapping mode, each record falls within the $MFT's actual data segment; contiguous unused
                // records in the middle are normal. Premature termination would miss the deleted items in the latter half.
                if (usingVolumeFallback
                    && !usingMftLocator
                    && validRecordCount > 1024
                    && indexValue > 8192
                    && consecutiveInvalidCount > 8192)
                {
                    stoppedAtIndex = indexValue;
                    break;
                }
                continue;
            }

            // In runlist mapping mode, verify the MFT record number embedded in the record header (offset 0x2C).
            // If mapping fails, it produces entries with corrupted record numbers, which the recovery process would treat
            // as real targets to read clusters from; therefore, it is better to discard them than to allow them through.
            // Records in NTFS 3.0 and earlier do not have this field; a value of 0 is ignored in the judgment.
            if (usingMftLocator && indexValue != 0 && recordBytes.size() >= 48)
            {
                const std::uint32_t kHeaderRecordIndex = le32(recordBytes.data() + 44);
                if (kHeaderRecordIndex != 0
                    && static_cast<std::uint64_t>(kHeaderRecordIndex) != indexValue)
                {
                    ++consecutiveInvalidCount;
                    continue;
                }
            }

            consecutiveEmptyCount = 0;
            consecutiveInvalidCount = 0;
            validRecordCount += 1;
            if (!keepNamelessRecords
                && recordValue.fileName.isEmpty()
                && recordValue.recordIndex != 5)
            {
                continue;
            }
            // Accidental deletion scanning only requires deleted items, and the directory records needed for the reconstructed path hint (regardless of in-use status).
            // In-use regular files constitute the vast majority of the MFT; retaining all of them would cause memory to grow linearly with MFT size.
            if (kKeepDeletedAndDirectoriesOnly
                && recordValue.inUse
                && !recordValue.isDirectory)
            {
                continue;
            }
            recordsOut.push_back(std::move(recordValue));
        }

        if (mftHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(mftHandle);
        }
        ::CloseHandle(volumeHandle);

        // Scan path diagnostics: report the traversed path, planned vs. actual scan volume, and failure distribution in one go.
        // Multiple causes exist for 'scan completed with 0 items' (early interruption, all records in use, or read
        // failure); result counts alone cannot distinguish them. This log serves as the entry point for diagnosis.
        // Underscore tokens in lowercase are not extracted by i18n audits; no language pack sync is needed for text changes.
        {
            std::uint64_t inUseCount = 0;
            std::uint64_t directoryCount = 0;
            std::uint64_t deletedFileCount = 0;
            for (const NtfsRawRecord& recordValue : recordsOut)
            {
                if (recordValue.inUse)
                {
                    ++inUseCount;
                }
                if (recordValue.isDirectory)
                {
                    ++directoryCount;
                }
                if (!recordValue.inUse && !recordValue.isDirectory)
                {
                    ++deletedFileCount;
                }
            }

            KLogEvent event;
            info << event
                << "ntfs_scan_diag"
                << " volume="
                << volumeRoot.toStdString()
                << " source="
                << (usingMftLocator
                    ? "volume_runlist"
                    : (usingVolumeFallback ? "volume_linear" : "mft_logical_file"))
                << " parsecount="
                << static_cast<qulonglong>(parseCount)
                << " stoppedat="
                << static_cast<qulonglong>(stoppedAtIndex)
                << " records="
                << recordsOut.size()
                << " scanned="
                << static_cast<qulonglong>(validRecordCount)
                << " readfail="
                << static_cast<qulonglong>(totalReadFailCount)
                << " invalid="
                << static_cast<qulonglong>(totalInvalidCount)
                << " inuse="
                << static_cast<qulonglong>(inUseCount)
                << " dir="
                << static_cast<qulonglong>(directoryCount)
                << " deletedfile="
                << static_cast<qulonglong>(deletedFileCount)
                << " bytesperrecord="
                << bytesPerRecord
                << " lastreadfail="
                << lastReadFailText.toStdString()
                << eol;
        }

        if (recordsOut.empty())
        {
            errorTextOut = QStringLiteral("MFT解析结果为空。");
            return false;
        }

        if (kCacheAllowed)
        {
            std::shared_ptr<NtfsCacheEntry> cacheEntry = std::make_shared<NtfsCacheEntry>();
            if (copyRecordsOut)
            {
                cacheEntry->records = recordsOut;
            }
            else
            {
                cacheEntry->records = std::move(recordsOut);
            }
            cacheEntry->loadedMsec = kNowMsec;
            cacheEntry->recordLimit = kMaxRecordCount;
            cacheEntry->fsctlFallbackAllowed = allowFsctlFallback;
            buildNtfsCacheIndex(*cacheEntry);

            std::scoped_lock<std::mutex> lock(gNtfsCacheMutex);
            gNtfsCache[kCacheKey] = cacheEntry;
            if (cacheEntryOut != nullptr)
            {
                *cacheEntryOut = cacheEntry;
            }
            if (!copyRecordsOut)
            {
                recordsOut.clear();
            }
        }
        else if (cacheEntryOut != nullptr)
        {
            std::shared_ptr<NtfsCacheEntry> cacheEntry = std::make_shared<NtfsCacheEntry>();
            if (copyRecordsOut)
            {
                cacheEntry->records = recordsOut;
            }
            else
            {
                cacheEntry->records = std::move(recordsOut);
            }
            cacheEntry->loadedMsec = kNowMsec;
            cacheEntry->recordLimit = kMaxRecordCount;
            cacheEntry->fsctlFallbackAllowed = allowFsctlFallback;
            buildNtfsCacheIndex(*cacheEntry);
            *cacheEntryOut = cacheEntry;
            if (!copyRecordsOut)
            {
                recordsOut.clear();
            }
        }
        return true;
    }

    // resolveNtfsDirectoryIndex purpose: Locates the MFT record number for the target directory based on path segments.
    bool resolveNtfsDirectoryIndex(
        const NtfsCacheEntry& cacheEntry,
        const QStringList& pathSegments,
        std::uint64_t& directoryIndexOut)
    {
        std::uint64_t currentIndex = 5;
        for (const QString& segmentText : pathSegments)
        {
            bool found = false;
            const auto kChildRange = findNtfsDirectoryLinkRange(cacheEntry.directoryLinks, currentIndex);
            for (auto it = kChildRange.first; it != kChildRange.second; ++it)
            {
                const auto kRecordIt = cacheEntry.recordOffsetByIndex.find(it->recordIndex);
                if (kRecordIt == cacheEntry.recordOffsetByIndex.end())
                {
                    continue;
                }

                const NtfsRawRecord& childRecord = cacheEntry.records[kRecordIt->second];
                if (!childRecord.inUse || !childRecord.isDirectory)
                {
                    continue;
                }
                if (it->fileName.compare(segmentText, Qt::CaseInsensitive) == 0)
                {
                    currentIndex = childRecord.recordIndex;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        directoryIndexOut = currentIndex;
        return true;
    }

    // buildNtfsPathHintByName:
    // - Reconstruct the most complete path hint based on "display name + parent directory record number";
    // - Generate more accurate candidate paths for accidental deletion scans in multi FILE_NAME link scenarios.
    QString buildNtfsPathHintByName(
        const QString& volumeRootPath,
        const QString& targetName,
        const std::uint64_t parentIndexValue,
        const std::unordered_map<std::uint64_t, const NtfsRawRecord*>& recordMap)
    {
        QStringList segments;
        segments.push_front(targetName);
        std::uint64_t parentIndex = parentIndexValue;
        int depthGuard = 0;
        while (parentIndex != 0 && parentIndex != 5 && depthGuard < 64)
        {
            const auto kParentIt = recordMap.find(parentIndex);
            if (kParentIt == recordMap.end() || kParentIt->second == nullptr)
            {
                break;
            }
            const NtfsRawRecord* parentRecord = kParentIt->second;
            if (parentRecord->fileName.isEmpty())
            {
                break;
            }
            segments.push_front(parentRecord->fileName);
            parentIndex = parentRecord->parentIndex;
            ++depthGuard;
        }

        QString pathText = QDir::toNativeSeparators(volumeRootPath);
        if (!pathText.endsWith('\\'))
        {
            pathText += '\\';
        }
        pathText += segments.join('\\');
        return pathText;
    }

    // buildNtfsPathHint: Reconstructs a readable path from the record's default name and parent chain.
    QString buildNtfsPathHint(
        const QString& volumeRootPath,
        const NtfsRawRecord& targetRecord,
        const std::unordered_map<std::uint64_t, const NtfsRawRecord*>& recordMap)
    {
        return buildNtfsPathHintByName(
            volumeRootPath,
            targetRecord.fileName,
            targetRecord.parentIndex,
            recordMap);
    }

    // tryReadNtfsSingleRecordByFsctl:
    // - Read a single NTFS MFT record by record number.
    // - Used to read resident data on-demand during export to avoid caching large amounts of file content during the scanning phase.
    bool tryReadNtfsSingleRecordByFsctl(
        const HANDLE volumeHandle,
        const std::uint64_t fileReference,
        const std::uint16_t bytesPerSectorHint,
        const std::uint32_t bytesPerRecordHint,
        NtfsRawRecord& recordOut,
        QString& errorTextOut)
    {
        NTFS_VOLUME_DATA_BUFFER volumeData{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            nullptr,
            0,
            &volumeData,
            static_cast<DWORD>(sizeof(volumeData)),
            &returnedBytes,
            nullptr) == FALSE)
        {
            errorTextOut = QStringLiteral("FSCTL_GET_NTFS_VOLUME_DATA失败, code=%1").arg(::GetLastError());
            return false;
        }

        std::uint32_t bytesPerRecord = volumeData.BytesPerFileRecordSegment;
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            bytesPerRecord = bytesPerRecordHint;
        }
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            errorTextOut = QStringLiteral("读取单条记录失败：MFT记录大小异常, bytesPerRecord=%1").arg(bytesPerRecord);
            return false;
        }

        const std::size_t kOutputHeaderBytes = offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer);
        const std::size_t kOutputBufferBytes = kOutputHeaderBytes + static_cast<std::size_t>(bytesPerRecord) + 16ULL;
        std::vector<std::uint8_t> outputBuffer(kOutputBufferBytes);

        NTFS_FILE_RECORD_INPUT_BUFFER inputBuffer{};
        inputBuffer.FileReferenceNumber.QuadPart = static_cast<LONGLONG>(fileReference);
        returnedBytes = 0;
        if (::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_FILE_RECORD,
            &inputBuffer,
            static_cast<DWORD>(sizeof(inputBuffer)),
            outputBuffer.data(),
            static_cast<DWORD>(outputBuffer.size()),
            &returnedBytes,
            nullptr) == FALSE)
        {
            errorTextOut = QStringLiteral("FSCTL_GET_NTFS_FILE_RECORD失败, code=%1").arg(::GetLastError());
            return false;
        }
        if (returnedBytes <= kOutputHeaderBytes)
        {
            errorTextOut = QStringLiteral("FSCTL_GET_NTFS_FILE_RECORD返回长度不足。");
            return false;
        }

        NTFS_FILE_RECORD_OUTPUT_BUFFER* outputRecord =
            reinterpret_cast<NTFS_FILE_RECORD_OUTPUT_BUFFER*>(outputBuffer.data());
        const std::uint64_t kActualRecordIndex =
            static_cast<std::uint64_t>(outputRecord->FileReferenceNumber.QuadPart & 0x0000FFFFFFFFFFFFULL);
        const std::uint32_t kFileRecordLength = outputRecord->FileRecordLength;
        if (kActualRecordIndex != fileReference)
        {
            errorTextOut = QStringLiteral("目标记录不存在或已被替换, expect=%1, actual=%2")
                .arg(static_cast<qulonglong>(fileReference))
                .arg(static_cast<qulonglong>(kActualRecordIndex));
            return false;
        }
        if (kFileRecordLength < 64
            || kFileRecordLength > bytesPerRecord
            || kOutputHeaderBytes + kFileRecordLength > returnedBytes
            || kOutputHeaderBytes + kFileRecordLength > outputBuffer.size())
        {
            errorTextOut = QStringLiteral("单条记录长度异常, recordLength=%1").arg(kFileRecordLength);
            return false;
        }

        std::vector<std::byte> recordBytes(kFileRecordLength);
        std::memcpy(recordBytes.data(), outputBuffer.data() + kOutputHeaderBytes, kFileRecordLength);
        if (!parseNtfsRecord(recordBytes, fileReference, bytesPerSectorHint, true, recordOut))
        {
            errorTextOut = QStringLiteral("单条记录解析失败。");
            return false;
        }
        return true;
    }

    // loadNtfsSingleRecord:
    // - Read specific MFT records on demand for single-file recovery.
    // - Prefer FSCTL for precise retrieval; fall back to direct $MFT/volume offset read on failure.
    bool loadNtfsSingleRecord(
        const QString& volumeRoot,
        const std::uint64_t fileReference,
        NtfsRawRecord& recordOut,
        QString& errorTextOut)
    {
        errorTextOut.clear();
        const QString kVolumeDevicePath = buildVolumeDevicePath(volumeRoot);
        QString openVolumeErrorText;
        HANDLE volumeHandle = openReadHandle(kVolumeDevicePath, openVolumeErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openVolumeErrorText;
            return false;
        }

        std::array<std::byte, 512> bootBytes{};
        if (!readBytesAtOffset(volumeHandle, 0, 512, bootBytes.data(), errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }

        const std::uint16_t kBytesPerSector = le16(bootBytes.data() + 11);
        const std::uint8_t kSectorsPerCluster = static_cast<std::uint8_t>(bootBytes[13]);
        if (kBytesPerSector == 0 || kSectorsPerCluster == 0)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("NTFS 引导参数异常：扇区或簇大小为 0。");
            return false;
        }

        const std::uint64_t kBytesPerCluster =
            static_cast<std::uint64_t>(kBytesPerSector) *
            static_cast<std::uint64_t>(kSectorsPerCluster);
        const std::uint64_t kMftStartCluster = le64(bootBytes.data() + 0x30);
        if (kMftStartCluster >
            std::numeric_limits<std::uint64_t>::max() / kBytesPerCluster)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("MFT 起始簇换算发生溢出。");
            return false;
        }
        const std::uint64_t kMftStartOffset = kMftStartCluster * kBytesPerCluster;
        const std::int8_t kClustersPerRecord = static_cast<std::int8_t>(bootBytes[64]);
        std::uint32_t bytesPerRecord = 1024;
        if (kClustersPerRecord < 0)
        {
            const int kRecordSizeExponent =
                -static_cast<int>(kClustersPerRecord);
            bytesPerRecord = kRecordSizeExponent < 32
                ? (1u << kRecordSizeExponent)
                : 0U;
        }
        else
        {
            bytesPerRecord =
                static_cast<std::uint32_t>(kBytesPerSector) *
                static_cast<std::uint32_t>(kSectorsPerCluster) *
                static_cast<std::uint32_t>(kClustersPerRecord);
        }
        if (bytesPerRecord < 512 || bytesPerRecord > 16384)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("MFT记录大小异常: %1").arg(bytesPerRecord);
            return false;
        }
        const bool kRecordByteOffsetValid =
            fileReference <=
                std::numeric_limits<std::uint64_t>::max() /
                    static_cast<std::uint64_t>(bytesPerRecord);
        const std::uint64_t kRecordByteOffset = kRecordByteOffsetValid
            ? fileReference * static_cast<std::uint64_t>(bytesPerRecord)
            : 0ULL;

        QString fsctlErrorText;
        if (tryReadNtfsSingleRecordByFsctl(volumeHandle, fileReference, kBytesPerSector, bytesPerRecord, recordOut, fsctlErrorText))
        {
            ::CloseHandle(volumeHandle);
            return true;
        }

        const QString kMftPath = QStringLiteral("\\\\.\\%1\\$MFT").arg(volumeRoot.left(2).toUpper());
        QString openMftErrorText;
        HANDLE mftHandle = openReadHandle(kMftPath, openMftErrorText);
        if (mftHandle != INVALID_HANDLE_VALUE)
        {
            std::vector<std::byte> recordBytes(bytesPerRecord);
            QString readErrorText;
            if (kRecordByteOffsetValid &&
                readBytesAtOffset(
                mftHandle,
                kRecordByteOffset,
                bytesPerRecord,
                recordBytes.data(),
                readErrorText)
                && parseNtfsRecord(recordBytes, fileReference, kBytesPerSector, true, recordOut))
            {
                ::CloseHandle(mftHandle);
                ::CloseHandle(volumeHandle);
                return true;
            }
            if (!readErrorText.isEmpty())
            {
                fsctlErrorText += QStringLiteral("; $MFT直读失败: ") + readErrorText;
            }
            else
            {
                fsctlErrorText += QStringLiteral("; $MFT直读失败: 记录解析失败");
            }
            ::CloseHandle(mftHandle);
        }
        else if (!openMftErrorText.isEmpty())
        {
            fsctlErrorText += QStringLiteral("; 打开$MFT失败: ") + openMftErrorText;
        }

        if (!kRecordByteOffsetValid ||
            kRecordByteOffset >
                std::numeric_limits<std::uint64_t>::max() -
                    kMftStartOffset)
        {
            ::CloseHandle(volumeHandle);
            errorTextOut = QStringLiteral("卷偏移记录解析失败。");
            return false;
        }

        // Volume offset rollback prioritizes locating via the $MFT's own runlist:
        // Using 'MFT start offset + record number * record length' is only valid when $MFT is fully contiguous; with fragmentation,
        // it may land on data belonging to other files, causing entries that clearly exist in the scan list to become unrecoverable.
        std::uint64_t rawRecordOffset = kMftStartOffset + kRecordByteOffset;
        {
            NtfsMftLocator mftLocator;
            QString locatorErrorText;
            std::uint64_t mappedOffset = 0;
            std::uint64_t mappedContiguousBytes = 0;
            if (loadNtfsMftLocator(
                volumeHandle,
                kMftStartOffset,
                kBytesPerSector,
                kBytesPerCluster,
                bytesPerRecord,
                mftLocator,
                locatorErrorText)
                && mftLocator.tryMapRecordRange(
                    fileReference,
                    mappedOffset,
                    mappedContiguousBytes))
            {
                rawRecordOffset = mappedOffset;
            }
            else if (!locatorErrorText.isEmpty())
            {
                fsctlErrorText += QStringLiteral("; $MFT映射不可用: ") + locatorErrorText;
            }
        }

        std::vector<std::byte> recordBytes(bytesPerRecord);
        if (!readBytesAtSectorAlignedOffset(
            volumeHandle,
            rawRecordOffset,
            bytesPerRecord,
            kBytesPerSector,
            QStringLiteral("卷偏移读取单条记录"),
            0,
            recordBytes.data(),
            errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            if (!fsctlErrorText.isEmpty())
            {
                errorTextOut = fsctlErrorText + QStringLiteral("; 卷偏移直读失败: ") + errorTextOut;
            }
            return false;
        }
        ::CloseHandle(volumeHandle);

        // Regardless of whether mapping or linear offset is used, the MFT record number in the record header
        // must be verified to prevent treating other records at the same physical offset as the recovery target.
        const std::uint32_t kActualRawRecordIndex =
            recordBytes.size() >= 48
            ? le32(recordBytes.data() + 44)
            : std::numeric_limits<std::uint32_t>::max();
        if (fileReference >
                static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()) ||
            kActualRawRecordIndex !=
                static_cast<std::uint32_t>(fileReference))
        {
            errorTextOut = QStringLiteral(
                "目标记录不存在或已被替换, expect=%1, actual=%2")
                .arg(static_cast<qulonglong>(fileReference))
                .arg(kActualRawRecordIndex);
            return false;
        }
        if (!parseNtfsRecord(recordBytes, fileReference, kBytesPerSector, true, recordOut))
        {
            errorTextOut = fsctlErrorText.isEmpty()
                ? QStringLiteral("卷偏移记录解析失败。")
                : (fsctlErrorText + QStringLiteral("; 卷偏移记录解析失败。"));
            return false;
        }
        return true;
    }

    // queryNtfsFileReferenceByPath:
    // - Opens the target directory and reads the stable NTFS file reference number;
    // - When the directory record number exceeds the fast MFT window, avoid misjudging 'not scanned' as directory non-existence.
    bool queryNtfsFileReferenceByPath(
        const QString& directoryPath,
        std::uint64_t& fileReferenceOut,
        QString& errorTextOut)
    {
        fileReferenceOut = 0;
        const std::wstring kPathWide = toWide(
            QDir::toNativeSeparators(QDir::cleanPath(directoryPath)));
        HANDLE directoryHandle = ::CreateFileW(
            kPathWide.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (directoryHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = QStringLiteral(
                "读取 NTFS 目录引用号失败, code=%1")
                .arg(::GetLastError());
            return false;
        }

        BY_HANDLE_FILE_INFORMATION fileInfo{};
        const BOOL kQueryOk =
            ::GetFileInformationByHandle(directoryHandle, &fileInfo);
        const DWORD kQueryError = kQueryOk != FALSE
            ? ERROR_SUCCESS
            : ::GetLastError();
        ::CloseHandle(directoryHandle);
        if (kQueryOk == FALSE)
        {
            errorTextOut = QStringLiteral(
                "读取 NTFS 目录引用号失败, code=%1")
                .arg(kQueryError);
            return false;
        }

        const std::uint64_t kRawFileReference =
            (static_cast<std::uint64_t>(fileInfo.nFileIndexHigh) << 32ULL) |
            static_cast<std::uint64_t>(fileInfo.nFileIndexLow);
        fileReferenceOut =
            kRawFileReference & 0x0000FFFFFFFFFFFFULL;
        return true;
    }

    // supplementNtfsDirectoryEntriesByMftEnumeration:
    // - Use FSCTL_ENUM_USN_DATA to iterate active MFT records, collecting only direct children of the target parent directory.
    // - For matched records, use FSCTL_GET_NTFS_FILE_RECORD to read the original FILE_NAME, size, and timestamps.
    // - This path does not rely on QDir/FindFirstFile enumeration; it specifically supplements high-numbered records outside the fast window.
    bool supplementNtfsDirectoryEntriesByMftEnumeration(
        const QString& volumeRoot,
        const QString& currentPath,
        const std::uint64_t directoryFileReference,
        std::vector<ks::file::ManualDirectoryEntry>& entriesInOut,
        std::size_t& addedCountOut,
        QString& errorTextOut)
    {
        struct DirectoryCandidate
        {
            std::uint64_t fileReference = 0; // fileReference: 48-bit MFT record number of the candidate child.
            QString fileName;                // fileName: Current link name returned by USN/MFT enumeration.
            std::uint32_t fileAttributes = 0;// fileAttributes: Low-cost fallback source for directory flags.
        };

        addedCountOut = 0;
        errorTextOut.clear();
        QString openErrorText;
        HANDLE volumeHandle =
            openReadHandle(buildVolumeDevicePath(volumeRoot), openErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        NTFS_VOLUME_DATA_BUFFER volumeData{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            nullptr,
            0,
            &volumeData,
            static_cast<DWORD>(sizeof(volumeData)),
            &returnedBytes,
            nullptr) == FALSE)
        {
            errorTextOut = QStringLiteral(
                "FSCTL_GET_NTFS_VOLUME_DATA失败, code=%1")
                .arg(::GetLastError());
            ::CloseHandle(volumeHandle);
            return false;
        }

        // MFT_ENUM_DATA returns only compact USN/MFT metadata, making it more suitable for directory completion than reading and caching millions of full MFT records.
        constexpr DWORD kEnumerationBufferBytes = 1024UL * 1024UL;
        std::vector<std::uint8_t> enumerationBuffer(
            static_cast<std::size_t>(kEnumerationBufferBytes));
        std::vector<DirectoryCandidate> candidateList;
        QSet<QString> candidateKeySet;

        MFT_ENUM_DATA enumerationData{};
        enumerationData.StartFileReferenceNumber = 0;
        enumerationData.LowUsn = 0;
        enumerationData.HighUsn =
            std::numeric_limits<USN>::max();

        bool enumerationFinished = false;
        while (!enumerationFinished)
        {
            returnedBytes = 0;
            const BOOL kEnumerateOk = ::DeviceIoControl(
                volumeHandle,
                FSCTL_ENUM_USN_DATA,
                &enumerationData,
                static_cast<DWORD>(sizeof(enumerationData)),
                enumerationBuffer.data(),
                kEnumerationBufferBytes,
                &returnedBytes,
                nullptr);
            if (kEnumerateOk == FALSE)
            {
                const DWORD kEnumerateError = ::GetLastError();
                if (kEnumerateError == ERROR_HANDLE_EOF)
                {
                    break;
                }

                errorTextOut = QStringLiteral(
                    "FSCTL_ENUM_USN_DATA失败, code=%1")
                    .arg(kEnumerateError);
                ::CloseHandle(volumeHandle);
                return false;
            }
            if (returnedBytes <= sizeof(DWORDLONG))
            {
                break;
            }

            DWORDLONG nextFileReference = 0;
            std::memcpy(
                &nextFileReference,
                enumerationBuffer.data(),
                sizeof(nextFileReference));
            std::size_t recordOffset = sizeof(DWORDLONG);
            while (recordOffset + sizeof(USN_RECORD_COMMON_HEADER) <= returnedBytes)
            {
                const USN_RECORD_COMMON_HEADER* commonHeader =
                    reinterpret_cast<const USN_RECORD_COMMON_HEADER*>(
                        enumerationBuffer.data() + recordOffset);
                const std::uint32_t kRecordLength = commonHeader->RecordLength;
                if (kRecordLength < sizeof(USN_RECORD_COMMON_HEADER) ||
                    recordOffset + kRecordLength > returnedBytes)
                {
                    errorTextOut = QStringLiteral(
                        "FSCTL_ENUM_USN_DATA返回了损坏的记录。");
                    ::CloseHandle(volumeHandle);
                    return false;
                }

                // NTFS's FSCTL_ENUM_USN_DATA currently returns V2 records; skip other versions instead of reading them with an incorrect layout.
                if (commonHeader->MajorVersion == 2 &&
                    kRecordLength >= offsetof(USN_RECORD_V2, FileName))
                {
                    const USN_RECORD_V2* usnRecord =
                        reinterpret_cast<const USN_RECORD_V2*>(commonHeader);
                    const std::size_t kFileNameEnd =
                        static_cast<std::size_t>(usnRecord->FileNameOffset) +
                        static_cast<std::size_t>(usnRecord->FileNameLength);
                    const std::uint64_t kParentFileReference =
                        static_cast<std::uint64_t>(
                            usnRecord->ParentFileReferenceNumber) &
                        0x0000FFFFFFFFFFFFULL;
                    if (kParentFileReference == directoryFileReference &&
                        usnRecord->FileNameLength > 0 &&
                        kFileNameEnd <= kRecordLength)
                    {
                        DirectoryCandidate candidate{};
                        candidate.fileReference =
                            static_cast<std::uint64_t>(
                                usnRecord->FileReferenceNumber) &
                            0x0000FFFFFFFFFFFFULL;
                        candidate.fileName = QString::fromWCharArray(
                            reinterpret_cast<const wchar_t*>(
                                reinterpret_cast<const std::uint8_t*>(usnRecord) +
                                usnRecord->FileNameOffset),
                            static_cast<qsizetype>(
                                usnRecord->FileNameLength / sizeof(wchar_t)));
                        candidate.fileAttributes = usnRecord->FileAttributes;

                        const QString kCandidateKey =
                            QStringLiteral("%1|%2")
                            .arg(static_cast<qulonglong>(
                                candidate.fileReference))
                            .arg(candidate.fileName.toCaseFolded());
                        if (!candidate.fileName.isEmpty() &&
                            !candidateKeySet.contains(kCandidateKey))
                        {
                            candidateKeySet.insert(kCandidateKey);
                            candidateList.push_back(std::move(candidate));
                        }
                    }
                }
                recordOffset += kRecordLength;
            }

            const std::uint64_t kCurrentStart =
                static_cast<std::uint64_t>(
                    enumerationData.StartFileReferenceNumber);
            if (nextFileReference <= kCurrentStart)
            {
                enumerationFinished = true;
            }
            else
            {
                enumerationData.StartFileReferenceNumber =
                    nextFileReference;
            }
        }

        QSet<QString> existingNameSet;
        existingNameSet.reserve(
            static_cast<int>(entriesInOut.size() * 2ULL + 16ULL));
        for (const ks::file::ManualDirectoryEntry& entryValue : entriesInOut)
        {
            existingNameSet.insert(entryValue.name.toCaseFolded());
        }

        const std::uint16_t kBytesPerSector =
            static_cast<std::uint16_t>(volumeData.BytesPerSector);
        const std::uint32_t kBytesPerRecord =
            volumeData.BytesPerFileRecordSegment;
        for (const DirectoryCandidate& candidate : candidateList)
        {
            NtfsRawRecord recordValue{};
            QString recordErrorText;
            const bool kRecordOk = tryReadNtfsSingleRecordByFsctl(
                volumeHandle,
                candidate.fileReference,
                kBytesPerSector,
                kBytesPerRecord,
                recordValue,
                recordErrorText);

            // appendEntry: Deduplicate entries uniformly by name; NTFS does not allow two names in the same directory that collapse to the same value case-insensitively.
            const auto kAppendEntry =
                [&entriesInOut,
                 &existingNameSet,
                 &currentPath,
                 &candidate](
                    const QString& fileName,
                    const bool isDirectory,
                    const std::uint64_t sizeBytes,
                    const std::uint64_t modifiedTime100ns)
                {
                    const QString kNormalizedName = fileName;
                    const QString kNormalizedKey =
                        kNormalizedName.toCaseFolded();
                    if (kNormalizedName.isEmpty() ||
                        existingNameSet.contains(kNormalizedKey))
                    {
                        return false;
                    }

                    ks::file::ManualDirectoryEntry itemValue{};
                    itemValue.name = kNormalizedName;
                    itemValue.absolutePath =
                        QDir(currentPath).filePath(kNormalizedName);
                    itemValue.isDirectory = isDirectory;
                    itemValue.sizeBytes =
                        isDirectory ? 0 : sizeBytes;
                    itemValue.modifiedTime =
                        fileTimeToLocal(modifiedTime100ns);
                    itemValue.typeText =
                        buildTypeText(kNormalizedName, isDirectory);
                    itemValue.ntfsFileReference =
                        candidate.fileReference;
                    existingNameSet.insert(kNormalizedKey);
                    entriesInOut.push_back(std::move(itemValue));
                    return true;
                };

            bool appendedExactLink = false;
            if (kRecordOk && recordValue.inUse)
            {
                for (const NtfsNameLink& nameLink : recordValue.nameLinks)
                {
                    if (nameLink.parentIndex !=
                        directoryFileReference)
                    {
                        continue;
                    }
                    appendedExactLink =
                        kAppendEntry(
                            nameLink.fileName,
                            recordValue.isDirectory,
                            recordValue.sizeBytes,
                            recordValue.modifiedTime100ns) ||
                        appendedExactLink;
                }
            }

            // The volume may change during enumeration; if exact MFT re-read fails, retain the name and directory flag provided by the active USN log record.
            if (!appendedExactLink)
            {
                const bool kIsDirectory =
                    (candidate.fileAttributes &
                        FILE_ATTRIBUTE_DIRECTORY) != 0;
                appendedExactLink = kAppendEntry(
                    candidate.fileName,
                    kIsDirectory,
                    0,
                    0);
            }
            if (appendedExactLink)
            {
                addedCountOut += 1;
            }
        }

        ::CloseHandle(volumeHandle);
        return true;
    }

    // decodeFatDateTime purpose: Convert FAT date and time to QDateTime.
    QDateTime decodeFatDateTime(const std::uint16_t dateValue, const std::uint16_t timeValue)
    {
        const int kYearValue = 1980 + ((dateValue >> 9) & 0x7F);
        const int kMonthValue = (dateValue >> 5) & 0x0F;
        const int kDayValue = dateValue & 0x1F;
        const int kHourValue = (timeValue >> 11) & 0x1F;
        const int kMinuteValue = (timeValue >> 5) & 0x3F;
        const int kSecondValue = (timeValue & 0x1F) * 2;
        if (kMonthValue <= 0 || kMonthValue > 12 || kDayValue <= 0 || kDayValue > 31)
        {
            return QDateTime();
        }
        const QDate kDateObj(kYearValue, kMonthValue, kDayValue);
        const QTime kTimeObj(kHourValue, kMinuteValue, kSecondValue);
        return (kDateObj.isValid() && kTimeObj.isValid())
            ? QDateTime(kDateObj, kTimeObj, QTimeZone::systemTimeZone())
            : QDateTime();
    }

    // decodeFatLongNamePart: Parses the 13 UTF-16 characters of an LFN entry.
    QString decodeFatLongNamePart(const std::byte* entryPtr)
    {
        const std::array<int, 13> kOffsets{
            1, 3, 5, 7, 9,
            14, 16, 18, 20, 22, 24,
            28, 30
        };
        QString textOut;
        textOut.reserve(13);
        for (int offsetValue : kOffsets)
        {
            const char16_t kCh = static_cast<char16_t>(le16(entryPtr + offsetValue));
            if (kCh == u'\0' || kCh == u'\xFFFF')
            {
                break;
            }
            textOut.append(QChar(kCh));
        }
        return textOut;
    }

    // decodeFatShortName: Converts an 8.3 name to a common string.
    QString decodeFatShortName(const std::byte* entryPtr)
    {
        QByteArray nameText(reinterpret_cast<const char*>(entryPtr), 8);
        QByteArray extText(reinterpret_cast<const char*>(entryPtr + 8), 3);
        nameText = nameText.trimmed();
        extText = extText.trimmed();
        const QString kBaseText = QString::fromLatin1(nameText);
        const QString kExtPart = QString::fromLatin1(extText);
        return kExtPart.isEmpty() ? kBaseText : (kBaseText + QStringLiteral(".") + kExtPart);
    }

    // readFat32BootInfo: Reads the FAT32 BPB and calculates key offsets.
    bool readFat32BootInfo(const HANDLE volumeHandle, Fat32BootInfo& infoOut, QString& errorTextOut)
    {
        std::array<std::byte, 512> bootBytes{};
        if (!readBytesAtOffset(volumeHandle, 0, 512, bootBytes.data(), errorTextOut))
        {
            return false;
        }

        const QByteArray kFsText(reinterpret_cast<const char*>(bootBytes.data() + 82), 8);
        if (!kFsText.startsWith("FAT32"))
        {
            errorTextOut = QStringLiteral("不是 FAT32 卷。");
            return false;
        }

        infoOut.bytesPerSector = le16(bootBytes.data() + 11);
        infoOut.sectorsPerCluster = static_cast<std::uint8_t>(bootBytes[13]);
        infoOut.reservedSectors = le16(bootBytes.data() + 14);
        infoOut.fatCount = static_cast<std::uint8_t>(bootBytes[16]);
        infoOut.sectorsPerFat = le32(bootBytes.data() + 36);
        infoOut.rootCluster = le32(bootBytes.data() + 44);
        if (infoOut.bytesPerSector == 0 || infoOut.sectorsPerCluster == 0 || infoOut.sectorsPerFat == 0)
        {
            errorTextOut = QStringLiteral("FAT32 BPB 参数异常。");
            return false;
        }

        infoOut.bytesPerCluster =
            static_cast<std::uint32_t>(infoOut.bytesPerSector) *
            static_cast<std::uint32_t>(infoOut.sectorsPerCluster);
        infoOut.fatOffset =
            static_cast<std::uint64_t>(infoOut.reservedSectors) *
            static_cast<std::uint64_t>(infoOut.bytesPerSector);
        const std::uint64_t kDataStartSector =
            static_cast<std::uint64_t>(infoOut.reservedSectors) +
            static_cast<std::uint64_t>(infoOut.fatCount) * static_cast<std::uint64_t>(infoOut.sectorsPerFat);
        infoOut.dataOffset = kDataStartSector * static_cast<std::uint64_t>(infoOut.bytesPerSector);
        return true;
    }

    // clusterOffset: Converts cluster number to byte offset within the volume.
    std::uint64_t clusterOffset(const Fat32BootInfo& infoValue, const std::uint32_t clusterValue)
    {
        const std::uint64_t kIndexValue = (clusterValue <= 2) ? 0 : static_cast<std::uint64_t>(clusterValue - 2);
        return infoValue.dataOffset + kIndexValue * static_cast<std::uint64_t>(infoValue.bytesPerCluster);
    }

    // Purpose of readFatNextCluster: Read the next cluster number in the FAT table.
    bool readFatNextCluster(
        const HANDLE volumeHandle,
        const Fat32BootInfo& infoValue,
        const std::uint32_t clusterValue,
        std::uint32_t& nextOut,
        QString& errorTextOut)
    {
        const std::uint64_t kEntryOffset = infoValue.fatOffset + static_cast<std::uint64_t>(clusterValue) * 4ULL;
        std::array<std::byte, 4> entryBytes{};
        if (!readBytesAtSectorAlignedOffset(
            volumeHandle,
            kEntryOffset,
            4,
            infoValue.bytesPerSector,
            QStringLiteral("FAT32 FAT entry"),
            clusterValue,
            entryBytes.data(),
            errorTextOut))
        {
            return false;
        }
        nextOut = (le32(entryBytes.data()) & 0x0FFFFFFF);
        return true;
    }

    // loadClusterChain: Reads the directory cluster sequence following the FAT chain.
    bool loadClusterChain(
        const HANDLE volumeHandle,
        const Fat32BootInfo& infoValue,
        const std::uint32_t firstCluster,
        std::vector<std::uint32_t>& chainOut,
        QString& errorTextOut)
    {
        chainOut.clear();
        if (firstCluster < 2)
        {
            return false;
        }

        std::uint32_t currentCluster = firstCluster;
        constexpr std::size_t kMaxClusterCount = 262144;
        for (std::size_t i = 0; i < kMaxClusterCount; ++i)
        {
            chainOut.push_back(currentCluster);
            std::uint32_t nextCluster = 0;
            if (!readFatNextCluster(volumeHandle, infoValue, currentCluster, nextCluster, errorTextOut))
            {
                return false;
            }
            if (nextCluster >= 0x0FFFFFF8 || nextCluster == 0 || nextCluster == currentCluster)
            {
                break;
            }
            currentCluster = nextCluster;
        }
        return !chainOut.empty();
    }

    // enumerateFatDirectoryByCluster: Parses directory entries under a specific directory cluster chain.
    bool enumerateFatDirectoryByCluster(
        const HANDLE volumeHandle,
        const Fat32BootInfo& infoValue,
        const std::uint32_t dirCluster,
        std::vector<Fat32Entry>& entriesOut,
        QString& errorTextOut)
    {
        entriesOut.clear();
        std::vector<std::uint32_t> chainList;
        if (!loadClusterChain(volumeHandle, infoValue, dirCluster, chainList, errorTextOut))
        {
            return false;
        }

        std::vector<std::byte> clusterBytes(infoValue.bytesPerCluster);
        std::vector<QString> lfnParts;
        for (std::uint32_t clusterValue : chainList)
        {
            if (!readBytesAtOffset(
                volumeHandle,
                clusterOffset(infoValue, clusterValue),
                infoValue.bytesPerCluster,
                clusterBytes.data(),
                errorTextOut))
            {
                return false;
            }

            for (std::size_t off = 0; off + 32 <= clusterBytes.size(); off += 32)
            {
                const std::byte* entryPtr = clusterBytes.data() + off;
                const std::uint8_t kFirstByte = static_cast<std::uint8_t>(entryPtr[0]);
                const std::uint8_t kAttrByte = static_cast<std::uint8_t>(entryPtr[11]);
                if (kFirstByte == 0x00)
                {
                    return true;
                }
                if (kFirstByte == 0xE5)
                {
                    lfnParts.clear();
                    continue;
                }
                if (kAttrByte == 0x0F)
                {
                    lfnParts.push_back(decodeFatLongNamePart(entryPtr));
                    continue;
                }
                if ((kAttrByte & 0x08) != 0)
                {
                    lfnParts.clear();
                    continue;
                }

                QString entryName;
                if (!lfnParts.empty())
                {
                    for (auto it = lfnParts.rbegin(); it != lfnParts.rend(); ++it)
                    {
                        entryName += *it;
                    }
                }
                else
                {
                    entryName = decodeFatShortName(entryPtr);
                }
                lfnParts.clear();
                if (entryName == QStringLiteral(".") || entryName == QStringLiteral(".."))
                {
                    continue;
                }

                const std::uint16_t kClusterHigh = le16(entryPtr + 20);
                const std::uint16_t kClusterLow = le16(entryPtr + 26);
                const std::uint32_t kFirstClusterValue =
                    (static_cast<std::uint32_t>(kClusterHigh) << 16) |
                    static_cast<std::uint32_t>(kClusterLow);
                const std::uint32_t kFileSize = le32(entryPtr + 28);
                const std::uint16_t kModTime = le16(entryPtr + 22);
                const std::uint16_t kModDate = le16(entryPtr + 24);

                Fat32Entry itemValue{};
                itemValue.name = entryName;
                itemValue.firstCluster = kFirstClusterValue;
                itemValue.sizeBytes = kFileSize;
                itemValue.isDirectory = ((kAttrByte & 0x10) != 0);
                itemValue.modifiedTime = decodeFatDateTime(kModDate, kModTime);
                entriesOut.push_back(std::move(itemValue));
            }
        }
        return true;
    }

    // resolveFatDirectoryCluster: Locates the target directory cluster number by path.
    bool resolveFatDirectoryCluster(
        const HANDLE volumeHandle,
        const Fat32BootInfo& infoValue,
        const QStringList& pathSegments,
        std::uint32_t& clusterOut,
        QString& errorTextOut)
    {
        std::uint32_t currentCluster = infoValue.rootCluster;
        for (const QString& segmentText : pathSegments)
        {
            std::vector<Fat32Entry> children;
            if (!enumerateFatDirectoryByCluster(volumeHandle, infoValue, currentCluster, children, errorTextOut))
            {
                return false;
            }
            bool found = false;
            for (const Fat32Entry& childItem : children)
            {
                if (!childItem.isDirectory)
                {
                    continue;
                }
                if (childItem.name.compare(segmentText, Qt::CaseInsensitive) == 0)
                {
                    currentCluster = childItem.firstCluster < 2 ? infoValue.rootCluster : childItem.firstCluster;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                errorTextOut = QStringLiteral("FAT32目录不存在：%1").arg(segmentText);
                return false;
            }
        }
        clusterOut = currentCluster;
        return true;
    }

    // readExFatBootInfo:
    // - Read the exFAT Boot Sector and calculate the base offsets for FAT/ClusterHeap;
    // - Returns false and populates errorTextOut with a displayable error message.
    bool readExFatBootInfo(const HANDLE volumeHandle, ExFatBootInfo& infoOut, QString& errorTextOut)
    {
        std::array<std::byte, 512> bootBytes{};
        if (!readBytesAtOffset(volumeHandle, 0, 512, bootBytes.data(), errorTextOut))
        {
            return false;
        }

        const QByteArray kFsText(reinterpret_cast<const char*>(bootBytes.data() + 3), 8);
        if (kFsText != QByteArrayLiteral("EXFAT   "))
        {
            errorTextOut = QStringLiteral("不是 exFAT 卷。");
            return false;
        }

        const std::uint8_t kBytesPerSectorShift = static_cast<std::uint8_t>(bootBytes[108]);
        const std::uint8_t kSectorsPerClusterShift = static_cast<std::uint8_t>(bootBytes[109]);
        if (kBytesPerSectorShift < 9 || kBytesPerSectorShift > 12 || kSectorsPerClusterShift > 25)
        {
            errorTextOut = QStringLiteral("exFAT Boot Sector 参数异常。");
            return false;
        }

        infoOut.bytesPerSector = 1UL << kBytesPerSectorShift;
        infoOut.sectorsPerCluster = 1UL << kSectorsPerClusterShift;
        infoOut.bytesPerCluster = infoOut.bytesPerSector * infoOut.sectorsPerCluster;
        infoOut.fatOffsetBytes = le32(bootBytes.data() + 80) * static_cast<std::uint64_t>(infoOut.bytesPerSector);
        infoOut.clusterHeapOffsetBytes = le32(bootBytes.data() + 88) * static_cast<std::uint64_t>(infoOut.bytesPerSector);
        infoOut.clusterCount = le32(bootBytes.data() + 92);
        infoOut.rootDirectoryCluster = le32(bootBytes.data() + 96);
        if (infoOut.clusterCount == 0 ||
            infoOut.rootDirectoryCluster < 2 ||
            infoOut.rootDirectoryCluster >= infoOut.clusterCount + 2ULL ||
            infoOut.bytesPerCluster == 0)
        {
            errorTextOut = QStringLiteral("exFAT 簇参数异常。");
            return false;
        }
        return true;
    }

    // exFatClusterOffset function: Converts an exFAT cluster number to a byte offset within the volume.
    std::uint64_t exFatClusterOffset(const ExFatBootInfo& infoValue, const std::uint32_t clusterValue)
    {
        const std::uint64_t kClusterIndex = (clusterValue <= 2U) ? 0ULL : static_cast<std::uint64_t>(clusterValue - 2U);
        return infoValue.clusterHeapOffsetBytes + kClusterIndex * static_cast<std::uint64_t>(infoValue.bytesPerCluster);
    }

    // readExFatNextCluster: Read the next cluster number from the exFAT FAT table.
    bool readExFatNextCluster(
        const HANDLE volumeHandle,
        const ExFatBootInfo& infoValue,
        const std::uint32_t clusterValue,
        std::uint32_t& nextOut,
        QString& errorTextOut)
    {
        const std::uint64_t kEntryOffset = infoValue.fatOffsetBytes + static_cast<std::uint64_t>(clusterValue) * 4ULL;
        std::array<std::byte, 4> entryBytes{};
        if (!readBytesAtSectorAlignedOffset(
            volumeHandle,
            kEntryOffset,
            4,
            infoValue.bytesPerSector,
            QStringLiteral("exFAT FAT entry"),
            clusterValue,
            entryBytes.data(),
            errorTextOut))
        {
            return false;
        }
        nextOut = le32(entryBytes.data());
        return true;
    }

    // loadExFatClusterChain:
    // - Read the exFAT directory cluster chain.
    // - When noFatChain=true, read as a contiguous cluster chain, common in directories with the NoFatChain flag.
    bool loadExFatClusterChain(
        const HANDLE volumeHandle,
        const ExFatBootInfo& infoValue,
        const std::uint32_t firstCluster,
        const std::uint64_t dataLength,
        const bool noFatChain,
        std::vector<std::uint32_t>& chainOut,
        QString& errorTextOut)
    {
        chainOut.clear();
        if (firstCluster < 2 || firstCluster >= infoValue.clusterCount + 2ULL)
        {
            return false;
        }

        const std::uint64_t kRequestedClusters = dataLength == 0
            ? 1ULL
            : ((dataLength + infoValue.bytesPerCluster - 1ULL) / infoValue.bytesPerCluster);
        const std::uint64_t kMaxClusters = std::min<std::uint64_t>(std::max<std::uint64_t>(kRequestedClusters, 1ULL), 262144ULL);
        std::uint32_t currentCluster = firstCluster;
        for (std::uint64_t index = 0; index < kMaxClusters; ++index)
        {
            if (currentCluster < 2 || currentCluster >= infoValue.clusterCount + 2ULL)
            {
                break;
            }
            chainOut.push_back(currentCluster);
            if (noFatChain)
            {
                currentCluster += 1U;
                continue;
            }

            std::uint32_t nextCluster = 0;
            if (!readExFatNextCluster(volumeHandle, infoValue, currentCluster, nextCluster, errorTextOut))
            {
                return false;
            }
            if (nextCluster >= 0xFFFFFFF8UL || nextCluster == 0 || nextCluster == currentCluster)
            {
                break;
            }
            currentCluster = nextCluster;
        }
        return !chainOut.empty();
    }

    // decodeExFatNamePart purpose: Parses the UTF-16 name fragment within the secondary directory entry of an exFAT filename.
    QString decodeExFatNamePart(const std::byte* entryPtr, const std::uint8_t maxChars)
    {
        QString textOut;
        const std::uint8_t kCharsToRead = std::min<std::uint8_t>(maxChars, 15U);
        for (std::uint8_t i = 0; i < kCharsToRead; ++i)
        {
            const char16_t kCh = static_cast<char16_t>(le16(entryPtr + 2 + (i * 2)));
            if (kCh == 0x0000 || kCh == 0xFFFF)
            {
                break;
            }
            textOut.append(QChar(kCh));
        }
        return textOut;
    }

    // enumerateExFatDirectoryByCluster: Parse directory entries under the exFAT directory cluster chain.
    bool enumerateExFatDirectoryByCluster(
        const HANDLE volumeHandle,
        const ExFatBootInfo& infoValue,
        const std::uint32_t dirCluster,
        const std::uint64_t dirDataLength,
        const bool noFatChain,
        std::vector<ExFatEntry>& entriesOut,
        QString& errorTextOut)
    {
        entriesOut.clear();
        std::vector<std::uint32_t> chainList;
        if (!loadExFatClusterChain(volumeHandle, infoValue, dirCluster, dirDataLength, noFatChain, chainList, errorTextOut))
        {
            return false;
        }

        std::vector<std::byte> clusterBytes(infoValue.bytesPerCluster);
        std::vector<std::byte> directoryBytes;
        directoryBytes.reserve(chainList.size() * static_cast<std::size_t>(infoValue.bytesPerCluster));
        for (std::uint32_t clusterValue : chainList)
        {
            if (!readBytesAtOffset(
                volumeHandle,
                exFatClusterOffset(infoValue, clusterValue),
                infoValue.bytesPerCluster,
                clusterBytes.data(),
                errorTextOut))
            {
                return false;
            }
            directoryBytes.insert(directoryBytes.end(), clusterBytes.begin(), clusterBytes.end());
            if (dirDataLength > 0 && directoryBytes.size() >= dirDataLength)
            {
                break;
            }
        }

        for (std::size_t off = 0; off + 32 <= directoryBytes.size(); off += 32)
        {
            const std::byte* entryPtr = directoryBytes.data() + off;
            const std::uint8_t kEntryType = static_cast<std::uint8_t>(entryPtr[0]);
            if (kEntryType == 0x00)
            {
                break;
            }
            if (kEntryType != 0x85)
            {
                continue;
            }

            const std::uint8_t kSecondaryCount = static_cast<std::uint8_t>(entryPtr[1]);
            if (kSecondaryCount == 0 || off + (static_cast<std::size_t>(kSecondaryCount) + 1ULL) * 32ULL > directoryBytes.size())
            {
                continue;
            }

            const std::uint16_t kAttributes = le16(entryPtr + 4);
            bool streamSeen = false;
            std::uint8_t nameLength = 0;
            std::uint32_t firstCluster = 0;
            std::uint64_t dataLength = 0;
            bool childNoFatChain = false;
            QString nameText;
            for (std::uint8_t subIndex = 1; subIndex <= kSecondaryCount; ++subIndex)
            {
                const std::byte* secondaryPtr = directoryBytes.data() + off + static_cast<std::size_t>(subIndex) * 32ULL;
                const std::uint8_t kSecondaryType = static_cast<std::uint8_t>(secondaryPtr[0]);
                if (kSecondaryType == 0xC0)
                {
                    streamSeen = true;
                    childNoFatChain = (static_cast<std::uint8_t>(secondaryPtr[1]) & 0x02U) != 0;
                    nameLength = static_cast<std::uint8_t>(secondaryPtr[3]);
                    firstCluster = le32(secondaryPtr + 20);
                    dataLength = le64(secondaryPtr + 24);
                    continue;
                }
                if (kSecondaryType == 0xC1 && streamSeen)
                {
                    const std::uint8_t kRemainingChars = static_cast<std::uint8_t>(
                        nameLength > static_cast<std::uint8_t>(nameText.size())
                        ? (nameLength - static_cast<std::uint8_t>(nameText.size()))
                        : 0U);
                    nameText += decodeExFatNamePart(secondaryPtr, kRemainingChars);
                }
            }
            if (nameText.isEmpty())
            {
                continue;
            }

            ExFatEntry itemValue{};
            itemValue.name = nameText;
            itemValue.firstCluster = firstCluster;
            itemValue.sizeBytes = dataLength;
            itemValue.isDirectory = (kAttributes & 0x10U) != 0;
            itemValue.noFatChain = childNoFatChain;
            entriesOut.push_back(std::move(itemValue));
        }
        return true;
    }

    // resolveExFatDirectory: Locate the cluster number and directory stream length of the target exFAT directory by path.
    bool resolveExFatDirectory(
        const HANDLE volumeHandle,
        const ExFatBootInfo& infoValue,
        const QStringList& pathSegments,
        std::uint32_t& clusterOut,
        std::uint64_t& dataLengthOut,
        bool& noFatChainOut,
        QString& errorTextOut)
    {
        clusterOut = infoValue.rootDirectoryCluster;
        dataLengthOut = 0;
        noFatChainOut = false;
        for (const QString& segmentText : pathSegments)
        {
            std::vector<ExFatEntry> children;
            if (!enumerateExFatDirectoryByCluster(volumeHandle, infoValue, clusterOut, dataLengthOut, noFatChainOut, children, errorTextOut))
            {
                return false;
            }
            bool found = false;
            for (const ExFatEntry& childItem : children)
            {
                if (!childItem.isDirectory)
                {
                    continue;
                }
                if (childItem.name.compare(segmentText, Qt::CaseInsensitive) == 0)
                {
                    clusterOut = childItem.firstCluster;
                    dataLengthOut = childItem.sizeBytes;
                    noFatChainOut = childItem.noFatChain;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                errorTextOut = QStringLiteral("exFAT目录不存在：%1").arg(segmentText);
                return false;
            }
        }
        return true;
    }
}

ks::file::ManualFsType ks::file::ManualFileSystemParser::detectFileSystemType(const QString& pathText)
{
    const QString kVolumeRoot = trimVolumeRoot(pathText);
    if (kVolumeRoot.isEmpty())
    {
        return ManualFsType::kUnknown;
    }

    wchar_t fsName[MAX_PATH] = {};
    const std::wstring kRootWide = toWide(kVolumeRoot);
    if (::GetVolumeInformationW(kRootWide.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fsName, MAX_PATH) == FALSE)
    {
        return ManualFsType::kUnknown;
    }

    const QString kFsText = QString::fromWCharArray(fsName).trimmed().toUpper();
    if (kFsText == QStringLiteral("NTFS"))
    {
        return ManualFsType::kNtfs;
    }
    if (kFsText == QStringLiteral("FAT32"))
    {
        return ManualFsType::kFat32;
    }
    if (kFsText == QStringLiteral("EXFAT"))
    {
        return ManualFsType::kExFat;
    }
    return ManualFsType::kUnknown;
}

bool ks::file::ManualFileSystemParser::enumerateDirectory(
    const QString& pathText,
    std::vector<ManualDirectoryEntry>& entriesOut,
    ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool* usedWinApiFallbackOut,
    const ManualFsType requestedFsType,
    const bool strictMftOnly)
{
    entriesOut.clear();
    errorTextOut.clear();
    if (usedWinApiFallbackOut != nullptr)
    {
        *usedWinApiFallbackOut = false;
    }
    fsTypeOut = requestedFsType == ManualFsType::kUnknown
        ? detectFileSystemType(pathText)
        : requestedFsType;

    if (fsTypeOut == ManualFsType::kNtfs)
    {
        const QString kVolumeRoot = trimVolumeRoot(pathText);
        std::vector<NtfsRawRecord> recordsValue;
        std::shared_ptr<const NtfsCacheEntry> cacheSnapshot;
        constexpr std::uint64_t kDirectoryRetryMaxRecords = 1200000ULL; // Extend the scan limit when directory location fails to avoid missing high-numbered directory entries.
        // Strict MFT mode also starts with a fast window.
        // Scanning 1.2 million records immediately may seem more complete, but its cost is unacceptable:
        // The cache key for this mode differs from the normal mode (allowFsctlFallback=false), so it never hits
        // the cache left by the normal mode; thus, switching to this mode requires a full rescan every time.
        // Parsing 1.2 million records uses hundreds of MB of memory. The dropdown stays disabled
        // throughout the scan, making the UI appear frozen as soon as this mode is selected.
        // If the fast scan window cannot locate the target directory, the retry below expands
        // automatically to 1.2 million records; completeness does not depend on this initial value.
        const std::uint64_t kDirectoryListMaxRecords = 250000ULL;
        // allowFsctlFallback must be disabled in strict mode: FSCTL_GET_NTFS_FILE_RECORD is handled by the
        // file system driver, which traverses the entire filter chain—the exact path this mode aims to bypass.
        if (!loadNtfsRecords(kVolumeRoot, recordsValue, errorTextOut, kDirectoryListMaxRecords, !strictMftOnly, true, false, false, false, NtfsRecordKeepPolicy::kAll, {}, &cacheSnapshot))
        {
            return false;
        }

        const QStringList kPathSegments = splitRelativeSegments(pathText);
        std::uint64_t dirIndex = 5;
        bool usedFullRangeScan = false; // usedFullRangeScan: Whether this run has already performed the expanded scan of 1.2 million records.
        bool resolveOk = (cacheSnapshot != nullptr)
            && resolveNtfsDirectoryIndex(*cacheSnapshot, kPathSegments, dirIndex);
        // The fast MFT window may not contain the target directory itself; obtain the real file reference number directly from the directory handle and continue with pure NTFS enumeration.
        // This fallback opens a directory handle using a Windows API path; it must be skipped in strict MFT mode.
        if (!resolveOk && !strictMftOnly)
        {
            std::uint64_t pathFileReference = 0;
            QString referenceErrorText;
            if (queryNtfsFileReferenceByPath(
                pathText,
                pathFileReference,
                referenceErrorText))
            {
                dirIndex = pathFileReference;
                resolveOk = true;
                errorTextOut.clear();

                KLogEvent event;
                info << event
                    << "[FileDock] 目标目录超出快速MFT窗口，已通过目录文件引用继续枚举, path="
                    << QDir::toNativeSeparators(
                        QDir::cleanPath(pathText)).toStdString()
                    << ", fileReference="
                    << static_cast<qulonglong>(dirIndex)
                    << eol;
            }
        }
        if (!resolveOk && strictMftOnly)
        {
            // In strict mode, there is no WinAPI fallback available, leaving only the option to 'expand the scan window':
            // The MFT record number of the target directory may exceed the fast window. Retry once here with
            // a full scan instead of deferring the retry to the 'result is empty' branch, which requires a
            // successful prior location and cannot be reached in strict mode if the location fails.
            std::vector<NtfsRawRecord> retryRecords;
            QString retryErrorText;
            std::shared_ptr<const NtfsCacheEntry> retrySnapshot;
            if (loadNtfsRecords(kVolumeRoot, retryRecords, retryErrorText, kDirectoryRetryMaxRecords, false, true, false, false, false, NtfsRecordKeepPolicy::kAll, {}, &retrySnapshot))
            {
                std::uint64_t retryDirIndex = 5;
                if (retrySnapshot != nullptr &&
                    resolveNtfsDirectoryIndex(*retrySnapshot, kPathSegments, retryDirIndex))
                {
                    recordsValue.swap(retryRecords);
                    cacheSnapshot = retrySnapshot;
                    dirIndex = retryDirIndex;
                    resolveOk = true;
                    usedFullRangeScan = true;
                    errorTextOut.clear();

                    KLogEvent event;
                    info << event
                        << "[FileDock] 纯MFT解析扩大扫描后定位到目录, path="
                        << QDir::toNativeSeparators(QDir::cleanPath(pathText)).toStdString()
                        << ", fileReference="
                        << static_cast<qulonglong>(dirIndex)
                        << eol;
                }
            }
        }
        if (!resolveOk && strictMftOnly)
        {
            // If the target is still not found after expanding the scan, prefer returning an error rather than rolling
            // back. Returning a list containing WinAPI lines would completely invalidate the 'MFT-only entry' judgment.
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "纯MFT解析未能在 $MFT 中定位该目录（扫描窗口不足或目录记录已损坏）。");
            }
            return false;
        }
        if (!resolveOk)
        {
            // Fallback strategy: If the directory exists but MFT link resolution fails, fall back to
            // WinAPI enumeration to prevent manual mode from returning 'empty' or 'unavailable' errors.
            if (enumerateDirectoryByWinApi(pathText, entriesOut))
            {
                if (usedWinApiFallbackOut != nullptr)
                {
                    *usedWinApiFallbackOut = true;
                }

                KLogEvent event;
                warn << event
                    << "[FileDock] NTFS链路定位失败，回退WinAPI枚举, path="
                    << QDir::toNativeSeparators(QDir::cleanPath(pathText)).toStdString()
                    << ", rows="
                    << entriesOut.size()
                    << eol;
                errorTextOut.clear();
                return true;
            }

            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral("NTFS目录不存在或不可访问。");
            }
            return false;
        }

        const QString kCurrentPath = QDir::toNativeSeparators(QDir::cleanPath(pathText));
        auto appendEntriesByDirectoryIndex =
            [&entriesOut, &kCurrentPath, &cacheSnapshot](const std::uint64_t targetDirectoryIndex)
            {
                entriesOut.clear();
                if (cacheSnapshot == nullptr)
                {
                    return;
                }

                const auto kChildRange = findNtfsDirectoryLinkRange(cacheSnapshot->directoryLinks, targetDirectoryIndex);
                for (auto it = kChildRange.first; it != kChildRange.second; ++it)
                {
                    const auto kRecordIt = cacheSnapshot->recordOffsetByIndex.find(it->recordIndex);
                    if (kRecordIt == cacheSnapshot->recordOffsetByIndex.end())
                    {
                        continue;
                    }

                    const NtfsRawRecord& recordValue = cacheSnapshot->records[kRecordIt->second];
                    if (!recordValue.inUse || it->fileName.isEmpty())
                    {
                        continue;
                    }

                    ManualDirectoryEntry itemValue{};
                    itemValue.name = it->fileName;
                    itemValue.absolutePath = QDir(kCurrentPath).filePath(it->fileName);
                    itemValue.isDirectory = recordValue.isDirectory;
                    itemValue.sizeBytes = recordValue.isDirectory ? 0 : recordValue.sizeBytes;
                    itemValue.modifiedTime = fileTimeToLocal(recordValue.modifiedTime100ns);
                    itemValue.typeText = buildTypeText(it->fileName, recordValue.isDirectory);
                    itemValue.ntfsFileReference = recordValue.recordIndex;
                    entriesOut.push_back(std::move(itemValue));
                }
            };

        appendEntriesByDirectoryIndex(dirIndex);

        // WinAPI results serve only as integrity verification: if missing entries are found, use FSCTL_ENUM_USN_DATA to target and fill high-numbered MFT records.
        // Only residual items that NTFS-directed enumeration still cannot retrieve are allowed to copy WinAPI lines and mark the true fallback source.
        // Strict MFT mode skips this block entirely: both USN-based completion and WinAPI merging would mix
        // 'entries the filesystem is willing to show' into the pure MFT view, breaking hidden-item detection.
        std::vector<ManualDirectoryEntry> winApiEntries;
        if (!strictMftOnly && enumerateDirectoryByWinApi(pathText, winApiEntries))
        {
            const auto kBuildExistingNameSet =
                [&entriesOut]()
                {
                    QSet<QString> nameSet;
                    nameSet.reserve(
                        static_cast<int>(
                            entriesOut.size() * 2ULL + 16ULL));
                    for (const ManualDirectoryEntry& itemValue : entriesOut)
                    {
                        nameSet.insert(itemValue.name.toCaseFolded());
                    }
                    return nameSet;
                };

            QSet<QString> existingNameSet =
                kBuildExistingNameSet();
            std::size_t missingBeforeMftCount = 0;
            for (const ManualDirectoryEntry& winApiItem : winApiEntries)
            {
                if (!existingNameSet.contains(
                    winApiItem.name.toCaseFolded()))
                {
                    missingBeforeMftCount += 1;
                }
            }

            if (missingBeforeMftCount > 0)
            {
                std::size_t mftAddedCount = 0;
                QString mftEnumerationErrorText;
                const bool kMftEnumerationOk =
                    supplementNtfsDirectoryEntriesByMftEnumeration(
                        kVolumeRoot,
                        kCurrentPath,
                        dirIndex,
                        entriesOut,
                        mftAddedCount,
                        mftEnumerationErrorText);
                if (kMftEnumerationOk)
                {
                    existingNameSet = kBuildExistingNameSet();

                    KLogEvent event;
                    info << event
                        << "[FileDock] NTFS定向MFT枚举完成, path="
                        << kCurrentPath.toStdString()
                        << ", missingBefore="
                        << static_cast<qulonglong>(
                            missingBeforeMftCount)
                        << ", mftAdded="
                        << static_cast<qulonglong>(mftAddedCount)
                        << eol;
                }
                else
                {
                    KLogEvent event;
                    warn << event
                        << "[FileDock] NTFS定向MFT枚举失败，保留WinAPI最终兜底, path="
                        << kCurrentPath.toStdString()
                        << ", error="
                        << mftEnumerationErrorText.toStdString()
                        << eol;
                }
            }

            std::size_t mergedCount = 0;
            for (const ManualDirectoryEntry& fallbackItem : winApiEntries)
            {
                const QString kNormalizedName =
                    fallbackItem.name.toCaseFolded();
                if (existingNameSet.contains(kNormalizedName))
                {
                    continue;
                }

                existingNameSet.insert(kNormalizedName);
                entriesOut.push_back(fallbackItem);
                mergedCount += 1;
            }

            if (mergedCount > 0)
            {
                if (usedWinApiFallbackOut != nullptr)
                {
                    *usedWinApiFallbackOut = true;
                }

                KLogEvent event;
                warn << event
                    << "[FileDock] NTFS定向MFT枚举后仍有缺项，已使用WinAPI兜底, path="
                    << QDir::toNativeSeparators(
                        QDir::cleanPath(pathText)).toStdString()
                    << ", mftRows="
                    << static_cast<qulonglong>(
                        entriesOut.size() - mergedCount)
                    << ", fallbackRows="
                    << static_cast<qulonglong>(mergedCount)
                    << ", winApiRows="
                    << static_cast<qulonglong>(winApiEntries.size())
                    << eol;
            }
        }

        // Execute an expanded scan only once when the directory is located but the manual path returns empty, balancing 'speed priority' with 'extreme directory availability'.
        if (entriesOut.empty() && !usedFullRangeScan && kDirectoryListMaxRecords < kDirectoryRetryMaxRecords)
        {
            std::vector<NtfsRawRecord> retryRecords;
            QString retryErrorText;
            std::shared_ptr<const NtfsCacheEntry> retrySnapshot;
            if (loadNtfsRecords(kVolumeRoot, retryRecords, retryErrorText, kDirectoryRetryMaxRecords, !strictMftOnly, true, false, false, false, NtfsRecordKeepPolicy::kAll, {}, &retrySnapshot))
            {
                std::uint64_t retryDirIndex = 5;
                if (retrySnapshot != nullptr && resolveNtfsDirectoryIndex(*retrySnapshot, kPathSegments, retryDirIndex))
                {
                    recordsValue.swap(retryRecords);
                    cacheSnapshot = retrySnapshot;
                    dirIndex = retryDirIndex;
                    appendEntriesByDirectoryIndex(dirIndex);
                }
            }
        }
    }
    else if (fsTypeOut == ManualFsType::kFat32)
    {
        const QString kVolumeRoot = trimVolumeRoot(pathText);
        QString openErrorText;
        HANDLE volumeHandle = openReadHandle(buildVolumeDevicePath(kVolumeRoot), openErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        Fat32BootInfo bootInfo{};
        if (!readFat32BootInfo(volumeHandle, bootInfo, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }

        std::uint32_t dirCluster = bootInfo.rootCluster;
        const QStringList kPathSegments = splitRelativeSegments(pathText);
        if (!resolveFatDirectoryCluster(volumeHandle, bootInfo, kPathSegments, dirCluster, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }

        std::vector<Fat32Entry> fatEntries;
        if (!enumerateFatDirectoryByCluster(volumeHandle, bootInfo, dirCluster, fatEntries, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }
        ::CloseHandle(volumeHandle);

        const QString kCurrentPath = QDir::toNativeSeparators(QDir::cleanPath(pathText));
        for (const Fat32Entry& fatItem : fatEntries)
        {
            ManualDirectoryEntry itemValue{};
            itemValue.name = fatItem.name;
            itemValue.absolutePath = QDir(kCurrentPath).filePath(fatItem.name);
            itemValue.isDirectory = fatItem.isDirectory;
            itemValue.sizeBytes = fatItem.isDirectory ? 0 : fatItem.sizeBytes;
            itemValue.modifiedTime = fatItem.modifiedTime;
            itemValue.typeText = buildTypeText(fatItem.name, fatItem.isDirectory);
            entriesOut.push_back(std::move(itemValue));
        }
    }
    else if (fsTypeOut == ManualFsType::kExFat)
    {
        const QString kVolumeRoot = trimVolumeRoot(pathText);
        QString openErrorText;
        HANDLE volumeHandle = openReadHandle(buildVolumeDevicePath(kVolumeRoot), openErrorText);
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        ExFatBootInfo bootInfo{};
        if (!readExFatBootInfo(volumeHandle, bootInfo, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }

        std::uint32_t dirCluster = bootInfo.rootDirectoryCluster;
        std::uint64_t dirDataLength = 0;
        bool dirNoFatChain = false;
        const QStringList kPathSegments = splitRelativeSegments(pathText);
        if (!resolveExFatDirectory(volumeHandle, bootInfo, kPathSegments, dirCluster, dirDataLength, dirNoFatChain, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }

        std::vector<ExFatEntry> exFatEntries;
        if (!enumerateExFatDirectoryByCluster(volumeHandle, bootInfo, dirCluster, dirDataLength, dirNoFatChain, exFatEntries, errorTextOut))
        {
            ::CloseHandle(volumeHandle);
            return false;
        }
        ::CloseHandle(volumeHandle);

        const QString kCurrentPath = QDir::toNativeSeparators(QDir::cleanPath(pathText));
        for (const ExFatEntry& exFatItem : exFatEntries)
        {
            ManualDirectoryEntry itemValue{};
            itemValue.name = exFatItem.name;
            itemValue.absolutePath = QDir(kCurrentPath).filePath(exFatItem.name);
            itemValue.isDirectory = exFatItem.isDirectory;
            itemValue.sizeBytes = exFatItem.isDirectory ? 0 : exFatItem.sizeBytes;
            itemValue.typeText = buildTypeText(exFatItem.name, exFatItem.isDirectory);
            entriesOut.push_back(std::move(itemValue));
        }
    }
    else
    {
        errorTextOut = QStringLiteral("当前卷不是 NTFS/FAT32/exFAT，无法手动解析。");
        return false;
    }

    if (entriesOut.empty())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 手动解析结果为空, path="
            << QDir::toNativeSeparators(pathText).toStdString()
            << ", fsType="
            << (fsTypeOut == ManualFsType::kNtfs
                ? "NTFS"
                : (fsTypeOut == ManualFsType::kFat32 ? "FAT32" : (fsTypeOut == ManualFsType::kExFat ? "exFAT" : "Unknown")))
            << eol;
    }

    std::sort(
        entriesOut.begin(),
        entriesOut.end(),
        [](const ManualDirectoryEntry& left, const ManualDirectoryEntry& right) {
            if (left.isDirectory != right.isDirectory)
            {
                return left.isDirectory && !right.isDirectory;
            }
            return QString::compare(left.name, right.name, Qt::CaseInsensitive) < 0;
        });
    return true;
}

bool ks::file::ManualFileSystemParser::enumerateDirectoryByMft(
    const QString& pathText,
    std::vector<ManualDirectoryEntry>& entriesOut,
    QString& errorTextOut,
    MftScanDiagnostics* diagnosticsOut)
{
    entriesOut.clear();
    errorTextOut.clear();
    if (diagnosticsOut != nullptr)
    {
        *diagnosticsOut = MftScanDiagnostics{};
    }

    const ManualFsType kDetectedType = detectFileSystemType(pathText);
    if (kDetectedType != ManualFsType::kNtfs)
    {
        errorTextOut = QStringLiteral(
            "纯MFT解析仅适用于 NTFS 卷，当前卷类型为 %1。")
            .arg(kDetectedType == ManualFsType::kFat32
                ? QStringLiteral("FAT32")
                : (kDetectedType == ManualFsType::kExFat
                    ? QStringLiteral("exFAT")
                    : QStringLiteral("未知")));
        return false;
    }

    ManualFsType resolvedType = ManualFsType::kNtfs;
    bool usedWinApiFallback = false;
    // strictMftOnly=true: Results must come entirely from direct byte reads of the $MFT at volume offsets.
    if (!enumerateDirectory(
            pathText,
            entriesOut,
            resolvedType,
            errorTextOut,
            &usedWinApiFallback,
            ManualFsType::kNtfs,
            true))
    {
        return false;
    }

    if (diagnosticsOut == nullptr)
    {
        return true;
    }
    diagnosticsOut->mftEntryCount = static_cast<int>(entriesOut.size());

    /*
     * The comparison view is used for comparison only and is never merged into the results. The two directions of the difference set have different meanings:
     * - mftOnly: entries present in $MFT but not visible via directory enumeration are a typical characteristic of a filtering layer or hidden files in directory indexes.
     * - winApiOnly: If the directory enumeration is visible but the $MFT scan window shows nothing,
     *   this is typically due to scan limits or directory changes during scanning, not an anomaly.
     */
    std::vector<ManualDirectoryEntry> winApiEntries;
    if (!enumerateDirectoryByWinApi(pathText, winApiEntries))
    {
        return true;
    }
    diagnosticsOut->comparisonAvailable = true;
    diagnosticsOut->winApiEntryCount = static_cast<int>(winApiEntries.size());

    QSet<QString> mftNameSet;
    mftNameSet.reserve(static_cast<int>(entriesOut.size()) + 16);
    for (const ManualDirectoryEntry& itemValue : entriesOut)
    {
        mftNameSet.insert(itemValue.name.toCaseFolded());
    }
    QSet<QString> winApiNameSet;
    winApiNameSet.reserve(static_cast<int>(winApiEntries.size()) + 16);
    for (const ManualDirectoryEntry& itemValue : winApiEntries)
    {
        winApiNameSet.insert(itemValue.name.toCaseFolded());
    }

    for (const ManualDirectoryEntry& itemValue : entriesOut)
    {
        if (!winApiNameSet.contains(itemValue.name.toCaseFolded()))
        {
            diagnosticsOut->mftOnlyNames.append(itemValue.name);
        }
    }
    for (const ManualDirectoryEntry& itemValue : winApiEntries)
    {
        if (!mftNameSet.contains(itemValue.name.toCaseFolded()))
        {
            diagnosticsOut->winApiOnlyNames.append(itemValue.name);
        }
    }

    if (!diagnosticsOut->mftOnlyNames.isEmpty())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 纯MFT解析发现目录枚举不可见的条目, path="
            << QDir::toNativeSeparators(QDir::cleanPath(pathText)).toStdString()
            << ", mftRows="
            << diagnosticsOut->mftEntryCount
            << ", winApiRows="
            << diagnosticsOut->winApiEntryCount
            << ", mftOnly="
            << diagnosticsOut->mftOnlyNames.size()
            << eol;
    }
    return true;
}

bool ks::file::ManualFileSystemParser::enumerateNtfsDeletedFiles(
    const QString& volumeRootPath,
    std::vector<NtfsDeletedFileEntry>& deletedOut,
    QString& errorTextOut,
    const std::function<void(int, const QString&)>& progressCallback)
{
    deletedOut.clear();
    errorTextOut.clear();
    if (progressCallback)
    {
        progressCallback(1, QStringLiteral("准备误删扫描"));
    }
    if (detectFileSystemType(volumeRootPath) != ManualFsType::kNtfs)
    {
        errorTextOut = QStringLiteral("仅 NTFS 卷支持误删扫描。");
        return false;
    }

    std::vector<NtfsRawRecord> recordsValue;
    const QString kVolumeRoot = trimVolumeRoot(volumeRootPath);
    // 0 means no additional limit: must cover all valid records in $MFT.
    // NTFS preferentially reuses low-numbered free records; records marked "deleted but unreused" are almost entirely at the end of the MFT.
    // Previously, scanning was limited to the first 1.5 million records. On large volumes those records were all in use, consistently producing 0 results.
    constexpr std::uint64_t kDeletedScanMaxRecords = 0ULL;
    // Since recovery prioritizes retaining deleted records, disable the FSCTL path here and instead scan via $MFT/volume offset.
    if (!loadNtfsRecords(
        kVolumeRoot,
        recordsValue,
        errorTextOut,
        kDeletedScanMaxRecords,
        false,
        false,
        true,
        false,
        true,
        NtfsRecordKeepPolicy::kDeletedAndDirectories,
        progressCallback,
        nullptr))
    {
        return false;
    }
    if (progressCallback)
    {
        progressCallback(82, QStringLiteral("MFT 扫描完成，开始过滤删除项"));
    }

    // bitmapSnapshot: The volume bitmap snapshot is used solely for completeness estimation; loading failure does not affect the main scanning flow.
    NtfsVolumeBitmapSnapshot bitmapSnapshot{};
    const NtfsVolumeBitmapSnapshot* bitmapSnapshotPtr = nullptr;
    QString bitmapErrorText;
    if (loadNtfsVolumeBitmapSnapshot(kVolumeRoot, bitmapSnapshot, bitmapErrorText))
    {
        bitmapSnapshotPtr = &bitmapSnapshot;
        if (progressCallback)
        {
            progressCallback(86, QStringLiteral("已读取卷位图，开始估算完整度"));
        }
        // Success with warning flags indicates the bitmap only covers the first segment of the volume; completeness for the remaining portion remains 'unknown'.
        if (!bitmapErrorText.isEmpty())
        {
            KLogEvent event;
            warn << event
                << "[FileDock] 误删扫描仅取到部分卷位图, volume="
                << kVolumeRoot.toStdString()
                << ", detail="
                << bitmapErrorText.toStdString()
                << eol;
        }
    }
    else if (!bitmapErrorText.isEmpty())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 误删扫描未能加载卷位图，完整度估算将退化为未知, volume="
            << kVolumeRoot.toStdString()
            << ", error="
            << bitmapErrorText.toStdString()
            << eol;
    }

    std::unordered_map<std::uint64_t, const NtfsRawRecord*> recordMap;
    recordMap.reserve(recordsValue.size());
    for (const NtfsRawRecord& recordValue : recordsValue)
    {
        recordMap.emplace(recordValue.recordIndex, &recordValue);
    }

    // emittedKeySet: Prevents adding duplicate path hints for the same record to the results.
    QSet<QString> emittedKeySet;

    // Limit for recovered scan results:
    // 1) Directory-level tables still use QTableWidget; large result sets significantly slow down the UI.
    // 2) Temporarily raise the limit to 80,000 to balance coverage with the UI's acceptable range.
    constexpr std::size_t kMaxDeletedRecords = 80000;
    std::size_t scannedDeletedCandidateCount = 0; // scannedDeletedCandidateCount: Number of deleted candidate records evaluated.
    for (const NtfsRawRecord& recordValue : recordsValue)
    {
        if (recordValue.inUse || recordValue.isDirectory)
        {
            continue;
        }
        scannedDeletedCandidateCount += 1;
        if (progressCallback
            && ((scannedDeletedCandidateCount % 2048U) == 0))
        {
            const int kPercentValue = 86
                + static_cast<int>((scannedDeletedCandidateCount * 10ULL)
                    / std::max<std::size_t>(recordsValue.size(), static_cast<std::size_t>(1)));
            progressCallback(std::min(kPercentValue, 96), QStringLiteral("过滤删除项并估算完整度"));
        }

        auto appendDeletedItem =
            [&deletedOut, &emittedKeySet, &recordValue, &recordMap, &kVolumeRoot, bitmapSnapshotPtr](
                const QString& fileNameValue,
                const std::uint64_t parentIndexValue,
                const bool hasOriginalName)
            {
                const QString kNormalizedFileName = fileNameValue.trimmed();
                if (kNormalizedFileName.isEmpty())
                {
                    return;
                }

                const QString kDedupeKey = QStringLiteral("%1|%2|%3")
                    .arg(static_cast<qulonglong>(recordValue.recordIndex))
                    .arg(static_cast<qulonglong>(parentIndexValue))
                    .arg(kNormalizedFileName.toCaseFolded());
                if (emittedKeySet.contains(kDedupeKey))
                {
                    return;
                }
                emittedKeySet.insert(kDedupeKey);

                NtfsDeletedFileEntry itemValue{};
                itemValue.fileName = kNormalizedFileName;
                itemValue.pathHint = buildNtfsPathHintByName(kVolumeRoot, kNormalizedFileName, parentIndexValue, recordMap);
                itemValue.sizeBytes = recordValue.sizeBytes;
                itemValue.modifiedTime = fileTimeToLocal(recordValue.modifiedTime100ns);
                itemValue.fileReference = recordValue.recordIndex;
                itemValue.sequenceNumber = recordValue.sequenceNumber;
                itemValue.estimatedIntegrityPercent =
                    estimateDeletedRecordIntegrityPercent(recordValue, bitmapSnapshotPtr);
                itemValue.hasOriginalName = hasOriginalName;
                itemValue.residentDataReady = recordValue.residentReady;
                itemValue.recoveryCapability = deletedRecordRecoveryCapability(
                    recordValue,
                    itemValue.estimatedIntegrityPercent);
                deletedOut.push_back(std::move(itemValue));
            };

        if (!recordValue.nameLinks.empty())
        {
            for (const NtfsNameLink& nameLink : recordValue.nameLinks)
            {
                appendDeletedItem(nameLink.fileName, nameLink.parentIndex, true);
                if (deletedOut.size() >= kMaxDeletedRecords)
                {
                    break;
                }
            }
        }
        else
        {
            if (!recordValue.fileName.isEmpty())
            {
                appendDeletedItem(recordValue.fileName, recordValue.parentIndex, true);
            }
            else if (recordValue.hasPrimaryDataStream || recordValue.sizeBytes > 0 || recordValue.residentReady)
            {
                appendDeletedItem(buildSyntheticDeletedFileName(recordValue), recordValue.parentIndex, false);
            }
        }

        if (deletedOut.size() >= kMaxDeletedRecords)
        {
            break;
        }
    }

    // Explicitly notify when the limit is reached: fixing the $MFT mapping significantly improves coverage; silent truncation
    // misleads users into thinking 'this is all deleted items', causing them to miss files they actually want to recover.
    const bool kTruncatedByDisplayLimit = (deletedOut.size() >= kMaxDeletedRecords);
    if (kTruncatedByDisplayLimit)
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 误删扫描结果已达显示上限，结果被截断, volume="
            << kVolumeRoot.toStdString()
            << ", limit="
            << kMaxDeletedRecords
            << eol;
    }

    std::sort(
        deletedOut.begin(),
        deletedOut.end(),
        [](const NtfsDeletedFileEntry& left, const NtfsDeletedFileEntry& right) {
            // Priority by completeness:
            // 1) First, sort resident and non-resident items that can be safely recovered.
            // 2) Sort by known completeness in descending order;
            // 3) Prioritize original filename, timestamp, and size last.
            const auto kCapabilityRank = [](const NtfsRecoveryCapability capability) -> int {
                switch (capability)
                {
                case NtfsRecoveryCapability::kResident:
                    return 4;
                case NtfsRecoveryCapability::kNonResidentIntact:
                    return 3;
                case NtfsRecoveryCapability::kNonResidentAtRisk:
                    return 2;
                case NtfsRecoveryCapability::kUnsupportedStream:
                    return 1;
                case NtfsRecoveryCapability::kMetadataOnly:
                default:
                    return 0;
                }
            };
            const int kLeftCapabilityRank = kCapabilityRank(left.recoveryCapability);
            const int kRightCapabilityRank = kCapabilityRank(right.recoveryCapability);
            if (kLeftCapabilityRank != kRightCapabilityRank)
            {
                return kLeftCapabilityRank > kRightCapabilityRank;
            }
            const bool kLeftIntegrityKnown = (left.estimatedIntegrityPercent >= 0);
            const bool kRightIntegrityKnown = (right.estimatedIntegrityPercent >= 0);
            if (kLeftIntegrityKnown != kRightIntegrityKnown)
            {
                return kLeftIntegrityKnown;
            }
            if (kLeftIntegrityKnown
                && kRightIntegrityKnown
                && left.estimatedIntegrityPercent != right.estimatedIntegrityPercent)
            {
                return left.estimatedIntegrityPercent > right.estimatedIntegrityPercent;
            }
            if (left.hasOriginalName != right.hasOriginalName)
            {
                return left.hasOriginalName;
            }
            if (left.residentDataReady != right.residentDataReady)
            {
                return left.residentDataReady;
            }
            if (left.modifiedTime.isValid() && right.modifiedTime.isValid())
            {
                return left.modifiedTime > right.modifiedTime;
            }
            if (left.modifiedTime.isValid() != right.modifiedTime.isValid())
            {
                return left.modifiedTime.isValid();
            }
            if (left.sizeBytes != right.sizeBytes)
            {
                return left.sizeBytes > right.sizeBytes;
            }
            return QString::compare(left.fileName, right.fileName, Qt::CaseInsensitive) < 0;
        });
    if (progressCallback)
    {
        progressCallback(
            100,
            kTruncatedByDisplayLimit
            ? QStringLiteral("删除项排序完成（已达显示上限，结果被截断）")
            : QStringLiteral("删除项排序完成"));
    }
    return true;
}

bool ks::file::ManualFileSystemParser::recoverNtfsDeletedFile(
    const QString& volumeRootPath,
    const NtfsDeletedFileEntry& deletedEntry,
    const QString& targetFilePath,
    QString& errorTextOut,
    const std::function<void(int, const QString&)>& progressCallback)
{
    errorTextOut.clear();
    const auto kReportProgress =
        [&progressCallback](const int percentValue, const QString& stageText)
        {
            if (progressCallback)
            {
                progressCallback(std::clamp(percentValue, 0, 100), stageText);
            }
        };
    kReportProgress(1, QStringLiteral("正在校验恢复参数"));

    // Only accept the two candidate types proven safe during the scanning phase.
    // Crucially, entries marked as 'cluster previously detected as reused' must not become recoverable again after the owner
    // deletes them, because current free status does not prove the cluster content still belongs to the original file.
    if (deletedEntry.recoveryCapability !=
            NtfsRecoveryCapability::kResident &&
        deletedEntry.recoveryCapability !=
            NtfsRecoveryCapability::kNonResidentIntact)
    {
        errorTextOut = QStringLiteral(
            "选中项均不满足安全恢复条件；请查看“恢复能力”和“完整度”列。");
        return false;
    }

    const QString kVolumeRoot = trimVolumeRoot(volumeRootPath);
    if (kVolumeRoot.isEmpty())
    {
        errorTextOut = QStringLiteral("卷根路径无效。");
        return false;
    }
    const QString kNormalizedTargetPath =
        QDir::cleanPath(targetFilePath.trimmed());
    if (kNormalizedTargetPath.isEmpty() ||
        !QDir::isAbsolutePath(kNormalizedTargetPath))
    {
        errorTextOut = QStringLiteral("目标文件路径为空或不是绝对路径。");
        return false;
    }
    if (QFileInfo::exists(kNormalizedTargetPath))
    {
        errorTextOut = QStringLiteral("目标文件已存在，恢复器不会覆盖现有文件：%1")
            .arg(QDir::toNativeSeparators(kNormalizedTargetPath));
        return false;
    }
    const QFileInfo kTargetInfo(kNormalizedTargetPath);
    const QDir kTargetDirectory = kTargetInfo.dir();
    if (!kTargetDirectory.exists())
    {
        errorTextOut = QStringLiteral("目标目录不存在：%1")
            .arg(QDir::toNativeSeparators(kTargetDirectory.absolutePath()));
        return false;
    }

    // Must re-read the MFT record by record number before restoration to avoid relying on a scan snapshot from minutes ago.
    kReportProgress(6, QStringLiteral("正在重新读取 MFT 记录"));
    NtfsRawRecord recordValue{};
    QString readRecordErrorText;
    if (!loadNtfsSingleRecord(
        kVolumeRoot,
        deletedEntry.fileReference,
        recordValue,
        readRecordErrorText))
    {
        errorTextOut = QStringLiteral("恢复前回读 MFT 记录失败：%1")
            .arg(readRecordErrorText);
        return false;
    }
    if (recordValue.inUse)
    {
        errorTextOut = QStringLiteral("该 MFT 记录已重新被占用，无法安全恢复。");
        return false;
    }
    if (deletedEntry.sequenceNumber != 0 &&
        recordValue.sequenceNumber != deletedEntry.sequenceNumber)
    {
        errorTextOut = QStringLiteral(
            "MFT 序列号已变化（扫描时 %1，当前 %2），记录可能被复用。")
            .arg(deletedEntry.sequenceNumber)
            .arg(recordValue.sequenceNumber);
        return false;
    }
    if (recordValue.sizeBytes != deletedEntry.sizeBytes)
    {
        errorTextOut = QStringLiteral(
            "MFT 数据长度已变化（扫描时 %1，当前 %2），已停止恢复。")
            .arg(static_cast<qulonglong>(deletedEntry.sizeBytes))
            .arg(static_cast<qulonglong>(recordValue.sizeBytes));
        return false;
    }
    if (!recordValue.hasPrimaryDataStream)
    {
        errorTextOut = QStringLiteral("该记录当前没有可恢复的未命名主数据流。");
        return false;
    }
    const bool kExpectedNonResident =
        deletedEntry.recoveryCapability ==
        NtfsRecoveryCapability::kNonResidentIntact;
    if (recordValue.nonResidentData != kExpectedNonResident)
    {
        errorTextOut = kExpectedNonResident
            ? QStringLiteral("该记录当前没有可恢复的未命名主数据流。")
            : QStringLiteral("该记录当前已不是 resident 主数据流。");
        return false;
    }

    // For non-resident recovery, perform position and layout pre-checks before creating any output temporary files.
    // Otherwise, cluster allocation for temporary files on the same volume may overwrite the data to be recovered.
    if (recordValue.nonResidentData)
    {
        const QString kSourceVolumeIdentity =
            queryExistingPathVolumeIdentity(kVolumeRoot);
        const QString kTargetVolumeIdentity =
            queryExistingPathVolumeIdentity(kTargetDirectory.absolutePath());
        if (kSourceVolumeIdentity.isEmpty() ||
            kTargetVolumeIdentity.isEmpty())
        {
            errorTextOut = QStringLiteral(
                "无法确认源卷或目标目录的真实卷身份，已停止非驻留恢复。");
            return false;
        }
        if (kSourceVolumeIdentity.compare(
                kTargetVolumeIdentity,
                Qt::CaseInsensitive) == 0)
        {
            errorTextOut = QStringLiteral(
                "非驻留文件不能恢复到源卷 %1，请选择其它卷或网络目录，避免输出文件覆盖待恢复簇。")
                .arg(kVolumeRoot);
            return false;
        }
        if (recordValue.unsupportedDataStream ||
            recordValue.hasAttributeList ||
            recordValue.dataRuns.empty())
        {
            errorTextOut = QStringLiteral(
                "该非驻留流使用压缩、加密或跨记录属性布局，当前无法安全重建。");
            return false;
        }
    }

    // Temporary files are always created in the target directory; QTemporaryFile::rename performs only the underlying
    // atomic rename, without falling back to copy/delete like QFile, and does not overwrite an existing target.
    QTemporaryFile targetFile(
        kTargetDirectory.filePath(
            QStringLiteral(".ksword-recovery-XXXXXX.tmp")));
    targetFile.setAutoRemove(true);
    if (!targetFile.open())
    {
        errorTextOut = QStringLiteral("无法创建恢复临时文件：%1")
            .arg(QDir::toNativeSeparators(kNormalizedTargetPath));
        return false;
    }
    const auto kCancelTargetWrite = [&targetFile]()
        {
            targetFile.close();
            targetFile.remove();
        };
    const auto kWriteExact =
        [&targetFile, &errorTextOut](const char* dataPointer, const qint64 byteCount) -> bool
        {
            if (byteCount <= 0)
            {
                return true;
            }
            const qint64 kWrittenBytes = targetFile.write(dataPointer, byteCount);
            if (kWrittenBytes != byteCount)
            {
                errorTextOut = QStringLiteral(
                    "恢复临时文件写入不完整（期望 %1，实际 %2）。")
                    .arg(byteCount)
                    .arg(kWrittenBytes);
                return false;
            }
            return true;
        };
    const auto kCommitTargetWithoutOverwrite =
        [&targetFile,
         &kCancelTargetWrite,
         &kNormalizedTargetPath,
         &errorTextOut]() -> bool
        {
            if (!targetFile.flush())
            {
                const QString kFlushError = targetFile.errorString();
                kCancelTargetWrite();
                errorTextOut = QStringLiteral("提交恢复文件失败：%1")
                    .arg(kFlushError);
                return false;
            }

            targetFile.close();
            if (QFileInfo::exists(kNormalizedTargetPath))
            {
                targetFile.remove();
                errorTextOut = QStringLiteral(
                    "恢复期间目标路径被其它程序创建，已拒绝覆盖：%1")
                    .arg(QDir::toNativeSeparators(kNormalizedTargetPath));
                return false;
            }

            // QTemporaryFile::rename does not perform copy/delete rollback; Windows atomic
            // rename fails if the target already exists, so the above check remains the
            // final, non-overridable safety gate even if a race condition occurs.
            if (!targetFile.rename(kNormalizedTargetPath))
            {
                const QString kRenameError = targetFile.errorString();
                const bool kTargetNowExists =
                    QFileInfo::exists(kNormalizedTargetPath);
                targetFile.remove();
                errorTextOut = kTargetNowExists
                    ? QStringLiteral(
                        "恢复期间目标路径被其它程序创建，已拒绝覆盖：%1")
                        .arg(QDir::toNativeSeparators(kNormalizedTargetPath))
                    : QStringLiteral("提交恢复文件失败：%1")
                        .arg(kRenameError);
                return false;
            }

            // After a successful rename, the QTemporaryFile's internal path is the final target;
            // auto-removal must be disabled, otherwise the destructor will delete the just-restored file.
            targetFile.setAutoRemove(false);
            return true;
        };

    if (!recordValue.nonResidentData)
    {
        kReportProgress(30, QStringLiteral("正在提取驻留数据"));
        if (recordValue.unsupportedDataStream || !recordValue.residentReady)
        {
            kCancelTargetWrite();
            errorTextOut = QStringLiteral("驻留主数据流使用了当前不支持的属性编码。");
            return false;
        }
        if (recordValue.sizeBytes >
            static_cast<std::uint64_t>(std::numeric_limits<int>::max()) ||
            recordValue.residentData.size() !=
                static_cast<int>(recordValue.sizeBytes))
        {
            kCancelTargetWrite();
            errorTextOut = QStringLiteral("驻留数据长度异常，已取消恢复。");
            return false;
        }
        if (!kWriteExact(
            recordValue.residentData.constData(),
            recordValue.residentData.size()))
        {
            kCancelTargetWrite();
            return false;
        }
        kReportProgress(90, QStringLiteral("正在原子提交恢复文件"));
        if (!kCommitTargetWithoutOverwrite())
        {
            return false;
        }
        kReportProgress(100, QStringLiteral("驻留文件恢复完成"));
        return true;
    }

    kReportProgress(12, QStringLiteral("正在校验非驻留数据簇"));
    NtfsVolumeBitmapSnapshot bitmapBefore{};
    QString bitmapErrorText;
    if (!loadNtfsVolumeBitmapSnapshot(
        kVolumeRoot,
        bitmapBefore,
        bitmapErrorText) ||
        !validateDeletedDataRunsUnallocated(
            recordValue,
            bitmapBefore,
            errorTextOut))
    {
        kCancelTargetWrite();
        if (errorTextOut.isEmpty())
        {
            errorTextOut = QStringLiteral("恢复前卷位图校验失败：%1")
                .arg(bitmapErrorText);
        }
        return false;
    }

    QString openVolumeErrorText;
    HANDLE volumeHandle =
        openReadHandle(buildVolumeDevicePath(kVolumeRoot), openVolumeErrorText);
    if (volumeHandle == INVALID_HANDLE_VALUE)
    {
        kCancelTargetWrite();
        errorTextOut = QStringLiteral("无法打开源卷读取数据簇：%1")
            .arg(openVolumeErrorText);
        return false;
    }

    std::array<std::byte, 512> bootBytes{};
    if (!readBytesAtOffset(
        volumeHandle,
        0,
        static_cast<std::uint32_t>(bootBytes.size()),
        bootBytes.data(),
        errorTextOut))
    {
        ::CloseHandle(volumeHandle);
        kCancelTargetWrite();
        return false;
    }
    const QByteArray kOemText(
        reinterpret_cast<const char*>(bootBytes.data() + 3),
        8);
    const std::uint16_t kBytesPerSector =
        le16(bootBytes.data() + 11);
    const std::uint8_t kSectorsPerCluster =
        static_cast<std::uint8_t>(bootBytes[13]);
    if (!kOemText.startsWith("NTFS") ||
        kBytesPerSector == 0 ||
        kSectorsPerCluster == 0)
    {
        ::CloseHandle(volumeHandle);
        kCancelTargetWrite();
        errorTextOut = QStringLiteral("源卷 NTFS 引导参数无效。");
        return false;
    }
    const std::uint64_t kBytesPerCluster =
        static_cast<std::uint64_t>(kBytesPerSector) *
        static_cast<std::uint64_t>(kSectorsPerCluster);
    constexpr std::uint64_t kMaximumReadChunkBytes =
        4ULL * 1024ULL * 1024ULL;
    const std::uint64_t kMaximumChunkClusters =
        std::max<std::uint64_t>(
            1ULL,
            kMaximumReadChunkBytes / kBytesPerCluster);

    std::uint64_t totalRunCapacity = 0;
    for (const NtfsDataRun& runValue : recordValue.dataRuns)
    {
        if (runValue.clusterCount >
            std::numeric_limits<std::uint64_t>::max() / kBytesPerCluster ||
            totalRunCapacity >
            std::numeric_limits<std::uint64_t>::max() -
                runValue.clusterCount * kBytesPerCluster)
        {
            ::CloseHandle(volumeHandle);
            kCancelTargetWrite();
            errorTextOut = QStringLiteral("非驻留数据段容量溢出。");
            return false;
        }
        totalRunCapacity += runValue.clusterCount * kBytesPerCluster;
    }
    if (totalRunCapacity < recordValue.sizeBytes)
    {
        ::CloseHandle(volumeHandle);
        kCancelTargetWrite();
        errorTextOut = QStringLiteral(
            "非驻留 runlist 仅覆盖 %1 字节，小于文件长度 %2，可能缺少外部数据段。")
            .arg(static_cast<qulonglong>(totalRunCapacity))
            .arg(static_cast<qulonglong>(recordValue.sizeBytes));
        return false;
    }

    kReportProgress(18, QStringLiteral("正在读取非驻留数据簇"));
    std::uint64_t logicalBytesWritten = 0;
    std::vector<std::byte> rawReadBuffer;
    QByteArray sparseZeroBuffer;
    for (const NtfsDataRun& runValue : recordValue.dataRuns)
    {
        if (logicalBytesWritten >= recordValue.sizeBytes)
        {
            break;
        }
        const std::uint64_t kRunCapacityBytes =
            runValue.clusterCount * kBytesPerCluster;
        const std::uint64_t kLogicalBytesInRun =
            std::min<std::uint64_t>(
                kRunCapacityBytes,
                recordValue.sizeBytes - logicalBytesWritten);
        std::uint64_t runBytesProcessed = 0;
        while (runBytesProcessed < kLogicalBytesInRun)
        {
            const std::uint64_t kRemainingRunBytes =
                kLogicalBytesInRun - runBytesProcessed;
            const std::uint64_t kLogicalChunkBytes =
                std::min<std::uint64_t>(
                    kRemainingRunBytes,
                    kMaximumChunkClusters * kBytesPerCluster);
            const std::uint64_t kInitializedChunkBytes =
                logicalBytesWritten < recordValue.initializedSizeBytes
                ? std::min<std::uint64_t>(
                    kLogicalChunkBytes,
                    recordValue.initializedSizeBytes - logicalBytesWritten)
                : 0;
            const std::uint64_t kChunkClusters =
                (std::max<std::uint64_t>(
                    kInitializedChunkBytes,
                    1ULL) +
                    kBytesPerCluster - 1ULL) /
                kBytesPerCluster;
            const std::uint64_t kAlignedChunkBytes =
                kChunkClusters * kBytesPerCluster;
            if (kAlignedChunkBytes >
                static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()))
            {
                ::CloseHandle(volumeHandle);
                kCancelTargetWrite();
                errorTextOut = QStringLiteral("单次簇读取长度超过系统限制。");
                return false;
            }

            if (runValue.isSparse || kInitializedChunkBytes == 0)
            {
                sparseZeroBuffer.fill(
                    '\0',
                    static_cast<qsizetype>(kLogicalChunkBytes));
                if (!kWriteExact(
                    sparseZeroBuffer.constData(),
                    sparseZeroBuffer.size()))
                {
                    ::CloseHandle(volumeHandle);
                    kCancelTargetWrite();
                    return false;
                }
            }
            else
            {
                const std::uint64_t kRunClusterOffset =
                    runBytesProcessed / kBytesPerCluster;
                if (runValue.startLcn >
                    std::numeric_limits<std::uint64_t>::max() -
                        kRunClusterOffset ||
                    runValue.startLcn + kRunClusterOffset >
                    std::numeric_limits<std::uint64_t>::max() /
                        kBytesPerCluster)
                {
                    ::CloseHandle(volumeHandle);
                    kCancelTargetWrite();
                    errorTextOut = QStringLiteral("非驻留数据簇偏移溢出。");
                    return false;
                }
                const std::uint64_t kRawOffset =
                    (runValue.startLcn + kRunClusterOffset) *
                    kBytesPerCluster;
                rawReadBuffer.resize(
                    static_cast<std::size_t>(kAlignedChunkBytes));
                QString rawReadErrorText;
                if (!readBytesAtOffset(
                    volumeHandle,
                    kRawOffset,
                    static_cast<std::uint32_t>(kAlignedChunkBytes),
                    rawReadBuffer.data(),
                    rawReadErrorText))
                {
                    ::CloseHandle(volumeHandle);
                    kCancelTargetWrite();
                    errorTextOut = QStringLiteral(
                        "读取删除数据簇失败（LCN %1）：%2")
                        .arg(static_cast<qulonglong>(
                            runValue.startLcn + kRunClusterOffset))
                        .arg(rawReadErrorText);
                    return false;
                }
                if (!kWriteExact(
                    reinterpret_cast<const char*>(rawReadBuffer.data()),
                    static_cast<qint64>(kInitializedChunkBytes)))
                {
                    ::CloseHandle(volumeHandle);
                    kCancelTargetWrite();
                    return false;
                }
                const std::uint64_t kUninitializedChunkBytes =
                    kLogicalChunkBytes - kInitializedChunkBytes;
                if (kUninitializedChunkBytes > 0)
                {
                    sparseZeroBuffer.fill(
                        '\0',
                        static_cast<qsizetype>(kUninitializedChunkBytes));
                    if (!kWriteExact(
                        sparseZeroBuffer.constData(),
                        sparseZeroBuffer.size()))
                    {
                        ::CloseHandle(volumeHandle);
                        kCancelTargetWrite();
                        return false;
                    }
                }
            }

            runBytesProcessed += kLogicalChunkBytes;
            logicalBytesWritten += kLogicalChunkBytes;
            const int kReadPercent =
                recordValue.sizeBytes == 0
                ? 80
                : 18 + static_cast<int>(
                    (static_cast<long double>(logicalBytesWritten) * 62.0L) /
                    static_cast<long double>(recordValue.sizeBytes));
            kReportProgress(
                std::min(kReadPercent, 80),
                QStringLiteral("正在读取非驻留数据簇"));
        }
    }
    ::CloseHandle(volumeHandle);

    if (logicalBytesWritten != recordValue.sizeBytes)
    {
        kCancelTargetWrite();
        errorTextOut = QStringLiteral(
            "非驻留数据读取不完整（期望 %1，实际 %2）。")
            .arg(static_cast<qulonglong>(recordValue.sizeBytes))
            .arg(static_cast<qulonglong>(logicalBytesWritten));
        return false;
    }

    // Re-read the volume bitmap and MFT before commit: any cluster allocation or record change during recovery invalidates temporary files.
    kReportProgress(84, QStringLiteral("正在执行提交前二次校验"));
    NtfsVolumeBitmapSnapshot bitmapAfter{};
    bitmapErrorText.clear();
    if (!loadNtfsVolumeBitmapSnapshot(
        kVolumeRoot,
        bitmapAfter,
        bitmapErrorText) ||
        !validateDeletedDataRunsUnallocated(
            recordValue,
            bitmapAfter,
            errorTextOut))
    {
        kCancelTargetWrite();
        if (errorTextOut.isEmpty())
        {
            errorTextOut = QStringLiteral("恢复后卷位图校验失败：%1")
                .arg(bitmapErrorText);
        }
        return false;
    }

    NtfsRawRecord finalRecordValue{};
    readRecordErrorText.clear();
    if (!loadNtfsSingleRecord(
        kVolumeRoot,
        deletedEntry.fileReference,
        finalRecordValue,
        readRecordErrorText) ||
        finalRecordValue.inUse ||
        !sameDeletedDataRunLayout(recordValue, finalRecordValue))
    {
        kCancelTargetWrite();
        errorTextOut = readRecordErrorText.isEmpty()
            ? QStringLiteral("恢复过程中 MFT 记录或 runlist 已变化，临时文件未提交。")
            : QStringLiteral("提交前回读 MFT 失败：%1").arg(readRecordErrorText);
        return false;
    }

    kReportProgress(94, QStringLiteral("正在原子提交恢复文件"));
    if (!kCommitTargetWithoutOverwrite())
    {
        return false;
    }
    kReportProgress(100, QStringLiteral("非驻留文件恢复完成"));
    return true;
}

bool ks::file::ManualFileSystemParser::recoverNtfsResidentFile(
    const QString& volumeRootPath,
    const NtfsDeletedFileEntry& deletedEntry,
    const QString& targetFilePath,
    QString& errorTextOut)
{
    // If the old entry lacks the recovery capability enum, allow it to retain its original Resident recovery semantics.
    NtfsDeletedFileEntry residentEntry = deletedEntry;
    if (residentEntry.recoveryCapability ==
            NtfsRecoveryCapability::kMetadataOnly &&
        residentEntry.residentDataReady)
    {
        residentEntry.recoveryCapability =
            NtfsRecoveryCapability::kResident;
    }
    return recoverNtfsDeletedFile(
        volumeRootPath,
        residentEntry,
        targetFilePath,
        errorTextOut);
}
