#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        const std::array<DWORD, 6>& FileDetailDialog::editableFileAttributeMasks()
        {
            // Only exposes attributes that can be directly and reversibly toggled via SetFileInformationByHandle(FileBasicInfo).
            // Structural flags like DIRECTORY/REPARSE_POINT/COMPRESSED/ENCRYPTED/SPARSE must use their dedicated APIs.
            static const std::array<DWORD, 6> kMasks{
                FILE_ATTRIBUTE_READONLY,
                FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_ARCHIVE,
                FILE_ATTRIBUTE_TEMPORARY,
                FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
            };
            return kMasks;
        }

        DWORD FileDetailDialog::editableFileAttributeMask()
        {
            DWORD mask = 0U;
            for (const DWORD kAttributeMask : editableFileAttributeMasks())
            {
                mask |= kAttributeMask;
            }
            return mask;
        }

        HANDLE FileDetailDialog::openFileMetadataHandle(
            const QString& filePath,
            const DWORD desiredAccess,
            DWORD& errorOut)
        {
            // OPEN_REPARSE_POINT ensures that when modifying a link, the leaf node is the link itself rather than silently following to the target.
            // BACKUP_SEMANTICS also allows directory handles; shared deletion avoids unnecessary conflicts with the file explorer.
            const std::wstring kNativePath = QDir::toNativeSeparators(filePath).toStdWString();
            if (kNativePath.empty())
            {
                errorOut = ERROR_INVALID_PARAMETER;
                return INVALID_HANDLE_VALUE;
            }

            HANDLE fileHandle = ::CreateFileW(
                kNativePath.c_str(),
                desiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            errorOut = fileHandle == INVALID_HANDLE_VALUE ? ::GetLastError() : ERROR_SUCCESS;
            return fileHandle;
        }

        FileDetailDialog::FileMetadataSnapshot FileDetailDialog::readFileMetadataSnapshot(
            const QString& filePath,
            const DWORD desiredAccess )
        {
            FileMetadataSnapshot snapshot;
            HANDLE fileHandle = openFileMetadataHandle(filePath, desiredAccess, snapshot.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return snapshot;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &snapshot.basicInfo,
                    sizeof(snapshot.basicInfo)) == FALSE)
            {
                snapshot.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return snapshot;
            }

            snapshot.ok = true;
            snapshot.win32Error = ERROR_SUCCESS;
            BY_HANDLE_FILE_INFORMATION identityInfo{};
            if (::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE)
            {
                snapshot.identityAvailable = true;
                snapshot.volumeSerialNumber = identityInfo.dwVolumeSerialNumber;
                snapshot.fileIndex =
                    (static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow);
            }
            closeWin32Handle(fileHandle);
            return snapshot;
        }

        QDateTime FileDetailDialog::fileMetadataTimeToLocalDateTime(const LARGE_INTEGER timeValue)
        {
            // Windows time counts in 100ns intervals from 1601-01-01 UTC; Qt uses milliseconds from 1970-01-01.
            constexpr qint64 kWindowsEpochOffset100ns = 116444736000000000LL;
            if (timeValue.QuadPart <= 0)
            {
                return {};
            }
            const qint64 kMillisecondsSinceUnixEpoch =
                (timeValue.QuadPart - kWindowsEpochOffset100ns) / 10000LL;
            return QDateTime::fromMSecsSinceEpoch(kMillisecondsSinceUnixEpoch, QTimeZone::UTC).toLocalTime();
        }

        LARGE_INTEGER FileDetailDialog::localDateTimeToFileMetadataTime(const QDateTime& dateTime)
        {
            constexpr qint64 kWindowsEpochOffset100ns = 116444736000000000LL;
            LARGE_INTEGER timeValue{};
            if (!dateTime.isValid())
            {
                return timeValue;
            }
            timeValue.QuadPart =
                dateTime.toUTC().toMSecsSinceEpoch() * 10000LL + kWindowsEpochOffset100ns;
            return timeValue;
        }

        std::array<LARGE_INTEGER, 4> FileDetailDialog::fileMetadataTimes(const FILE_BASIC_INFO& basicInfo)
        {
            return {
                basicInfo.CreationTime,
                basicInfo.LastAccessTime,
                basicInfo.LastWriteTime,
                basicInfo.ChangeTime
            };
        }

        FileDetailDialog::FileMetadataUpdateResult FileDetailDialog::writeFileMetadata(
            const QString& filePath,
            const FileMetadataUpdateRequest& request)
        {
            FileMetadataUpdateResult result;
            HANDLE fileHandle = openFileMetadataHandle(
                filePath,
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                result.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return result;
            }

            FILE_BASIC_INFO currentInfo{};
            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &currentInfo,
                    sizeof(currentInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            BY_HANDLE_FILE_INFORMATION identityInfo{};
            const bool kIdentityAvailable =
                ::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE;
            const std::uint64_t kCurrentFileIndex = kIdentityAvailable
                ? ((static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow))
                : 0U;
            if (request.validateIdentity)
            {
                if (!kIdentityAvailable)
                {
                    result.win32Error = ::GetLastError();
                    closeWin32Handle(fileHandle);
                    return result;
                }
                if (identityInfo.dwVolumeSerialNumber != request.expectedVolumeSerialNumber ||
                    kCurrentFileIndex != request.expectedFileIndex)
                {
                    result.win32Error = ERROR_FILE_INVALID;
                    closeWin32Handle(fileHandle);
                    return result;
                }
            }

            // Merge based on the latest value after a second read on the same handle to prevent external attribute changes from overwriting data during the edit page's stay.
            // Time fields with value 0 in FILE_BASIC_INFO and FileAttributes both indicate "no modification". Therefore, only fill in times explicitly
            // selected by the user. If attributes remain unchanged, keep them as 0 to avoid rewriting structural states like encryption or compression.
            FILE_BASIC_INFO updatedInfo{};
            if (request.updateTime[0]) updatedInfo.CreationTime = request.timeValue[0];
            if (request.updateTime[1]) updatedInfo.LastAccessTime = request.timeValue[1];
            if (request.updateTime[2]) updatedInfo.LastWriteTime = request.timeValue[2];
            if (request.updateTime[3]) updatedInfo.ChangeTime = request.timeValue[3];
            if (request.updateAttributes)
            {
                updatedInfo.FileAttributes = currentInfo.FileAttributes;
                updatedInfo.FileAttributes &= ~editableFileAttributeMask();
                updatedInfo.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
                updatedInfo.FileAttributes |=
                    request.editableAttributes & editableFileAttributeMask();
                if (updatedInfo.FileAttributes == 0U)
                {
                    updatedInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                }
            }

            if (::SetFileInformationByHandle(
                    fileHandle,
                    FileBasicInfo,
                    &updatedInfo,
                    sizeof(updatedInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &result.snapshot.basicInfo,
                    sizeof(result.snapshot.basicInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }
            closeWin32Handle(fileHandle);

            result.snapshot.ok = true;
            result.snapshot.win32Error = ERROR_SUCCESS;
            result.snapshot.identityAvailable = kIdentityAvailable;
            result.snapshot.volumeSerialNumber = kIdentityAvailable
                ? identityInfo.dwVolumeSerialNumber
                : 0U;
            result.snapshot.fileIndex = kCurrentFileIndex;
            result.ok = true;
            result.win32Error = ERROR_SUCCESS;
            result.verificationMatched = true;
            const std::array<LARGE_INTEGER, 4> kActualTimes =
                fileMetadataTimes(result.snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < request.updateTime.size(); ++timeIndex)
            {
                if (request.updateTime[timeIndex] &&
                    kActualTimes[timeIndex].QuadPart != request.timeValue[timeIndex].QuadPart)
                {
                    // Filesystems like FAT/exFAT may round timestamps to their own granularity; the write still succeeds, but the UI must display the re-read value.
                    result.verificationMatched = false;
                }
            }
            if (request.updateAttributes &&
                (result.snapshot.basicInfo.FileAttributes & editableFileAttributeMask()) !=
                    (request.editableAttributes & editableFileAttributeMask()))
            {
                result.verificationMatched = false;
            }
            return result;
        }
}
