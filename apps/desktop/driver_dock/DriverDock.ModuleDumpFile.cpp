#include "DriverDock.ModuleDumpFile.h"

#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace ksword::driver_dock_internal
{
    namespace
    {
        constexpr unsigned int kTemporaryFileCreateAttempts = 128U;

        // extendedWin32Path: Input is a standard absolute path; output is a Win32 path compatible with long paths and UNC.
        QString extendedWin32Path(const QString& rawPath)
        {
            QString nativePath = QDir::toNativeSeparators(rawPath);
            if (nativePath.startsWith(QStringLiteral("\\\\?\\")))
            {
                return nativePath;
            }
            if (nativePath.startsWith(QStringLiteral("\\\\")))
            {
                return QStringLiteral("\\\\?\\UNC\\") + nativePath.mid(2);
            }
            return QStringLiteral("\\\\?\\") + nativePath;
        }

        // closeHandle: accepts a nullable Win32 handle reference; resets it uniformly after closing to prevent double-free.
        void closeHandle(HANDLE& handleValue) noexcept
        {
            if (handleValue != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handleValue);
                handleValue = INVALID_HANDLE_VALUE;
            }
        }
    }

    DriverModuleDumpFile::~DriverModuleDumpFile() noexcept
    {
        discard();
    }

    bool DriverModuleDumpFile::create(const QString& targetPath)
    {
        // Each instance can correspond to only one target to prevent old handles or old diagnostic strings from entering the next dump.
        if (fileHandle_ != INVALID_HANDLE_VALUE ||
            !temporaryPath_.isEmpty())
        {
            return fail(
                DriverModuleDumpFileError::kCreate,
                ERROR_INVALID_STATE,
                QString::fromLatin1("The module dump file object was already initialized."));
        }

        const QFileInfo kTargetInformation(targetPath);
        const QDir kTargetDirectory = kTargetInformation.dir();
        targetPath_ = QDir::toNativeSeparators(
            kTargetInformation.absoluteFilePath());
        if (!kTargetInformation.isAbsolute() ||
            !kTargetDirectory.exists() ||
            targetPath_.isEmpty())
        {
            return fail(
                DriverModuleDumpFileError::kCreate,
                ERROR_PATH_NOT_FOUND,
                QString::fromLatin1("The module dump destination directory is unavailable."));
        }

        // DELETE permission is retained until commit; scanners opening the temporary file must share DELETE access,
        // preventing them from seizing the rename window after QTemporaryFile closes and causing Win32 error 32.
        const unsigned long kProcessId = ::GetCurrentProcessId();
        const unsigned long kThreadId = ::GetCurrentThreadId();
        const unsigned long long kTickCount = ::GetTickCount64();
        for (unsigned int attempt = 0U;
             attempt < kTemporaryFileCreateAttempts;
             ++attempt)
        {
            const QString kTemporaryFileName = QString::fromLatin1(
                ".ksword-module-dump-%1-%2-%3-%4.tmp")
                .arg(kProcessId)
                .arg(kThreadId)
                .arg(kTickCount)
                .arg(attempt);
            temporaryPath_ = kTargetDirectory.filePath(kTemporaryFileName);
            const QString kTemporaryExtendedPath =
                extendedWin32Path(temporaryPath_);
            fileHandle_ = ::CreateFileW(
                reinterpret_cast<LPCWSTR>(kTemporaryExtendedPath.utf16()),
                GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (fileHandle_ != INVALID_HANDLE_VALUE)
            {
                error_ = DriverModuleDumpFileError::kNone;
                win32Error_ = ERROR_SUCCESS;
                technicalDetail_.clear();
                return true;
            }

            const unsigned long kCreateError = ::GetLastError();
            if (kCreateError != ERROR_FILE_EXISTS &&
                kCreateError != ERROR_ALREADY_EXISTS)
            {
                temporaryPath_.clear();
                return fail(
                    DriverModuleDumpFileError::kCreate,
                    kCreateError,
                    QString::fromLatin1("Creating the protected sibling temporary file failed."));
            }
        }

        temporaryPath_.clear();
        return fail(
            DriverModuleDumpFileError::kCreate,
            ERROR_FILE_EXISTS,
            QString::fromLatin1("All protected temporary file names were already in use."));
    }

    bool DriverModuleDumpFile::write(
        const std::uint8_t* dataPointer,
        const std::size_t byteCount)
    {
        if (fileHandle_ == INVALID_HANDLE_VALUE ||
            (dataPointer == nullptr && byteCount != 0U))
        {
            return fail(
                DriverModuleDumpFileError::kWrite,
                ERROR_INVALID_HANDLE,
                QString::fromLatin1("The protected module dump file handle is invalid."));
        }

        // WriteFile uses DWORD length; loop handles large buffers and partial valid writes.
        std::size_t writtenTotal = 0U;
        const std::size_t kMaximumWriteBytes =
            static_cast<std::size_t>((std::numeric_limits<unsigned long>::max)());
        while (writtenTotal < byteCount)
        {
            const unsigned long kRequestedBytes = static_cast<unsigned long>(
                (std::min)(byteCount - writtenTotal, kMaximumWriteBytes));
            unsigned long writtenBytes = 0U;
            const bool kWriteSucceeded = ::WriteFile(
                fileHandle_,
                dataPointer + writtenTotal,
                kRequestedBytes,
                &writtenBytes,
                nullptr) != FALSE;
            if (!kWriteSucceeded || writtenBytes == 0U)
            {
                const unsigned long kWriteError =
                    kWriteSucceeded ? ERROR_WRITE_FAULT : ::GetLastError();
                return fail(
                    DriverModuleDumpFileError::kWrite,
                    kWriteError,
                    QString::fromLatin1("Writing the protected module dump temporary file failed."));
            }
            writtenTotal += writtenBytes;
        }
        return true;
    }

    bool DriverModuleDumpFile::commit(const std::uint64_t expectedFileBytes)
    {
        if (fileHandle_ == INVALID_HANDLE_VALUE)
        {
            return fail(
                DriverModuleDumpFileError::kCommit,
                ERROR_INVALID_HANDLE,
                QString::fromLatin1("The protected module dump commit handles are invalid."));
        }

        // Verify length and refresh data using the same handle before renaming; any failure preserves the 'no target file' semantics.
        LARGE_INTEGER actualFileBytes{};
        if (!::GetFileSizeEx(fileHandle_, &actualFileBytes))
        {
            return fail(
                DriverModuleDumpFileError::kFlush,
                ::GetLastError(),
                QString::fromLatin1("Querying the protected module dump temporary file size failed."));
        }
        if (actualFileBytes.QuadPart < 0 ||
            static_cast<std::uint64_t>(actualFileBytes.QuadPart) != expectedFileBytes)
        {
            return fail(
                DriverModuleDumpFileError::kFlush,
                ERROR_WRITE_FAULT,
                QString::fromLatin1("The protected module dump temporary file size is incomplete."));
        }
        if (!::FlushFileBuffers(fileHandle_))
        {
            return fail(
                DriverModuleDumpFileError::kFlush,
                ::GetLastError(),
                QString::fromLatin1("FlushFileBuffers failed before the handle-based atomic commit."));
        }

        // FileRenameInfo uses a full absolute path; RootDirectory=nullptr is a common compatibility form per Win32 documentation.
        const std::size_t kTargetNameBytes =
            static_cast<std::size_t>(targetPath_.size()) * sizeof(wchar_t);
        // Windows requires the buffer to be at least the structure body plus the full filename; it cannot be allocated based solely on the FileName offset.
        const std::size_t kRenameInformationBytes =
            sizeof(FILE_RENAME_INFO) + kTargetNameBytes;
        if (kTargetNameBytes == 0U ||
            kTargetNameBytes > (std::numeric_limits<unsigned long>::max)() ||
            kRenameInformationBytes > (std::numeric_limits<unsigned long>::max)())
        {
            return fail(
                DriverModuleDumpFileError::kCommit,
                ERROR_FILENAME_EXCED_RANGE,
                QString::fromLatin1("The module dump destination file name is too long."));
        }

        std::vector<std::uint8_t> renameBuffer(kRenameInformationBytes, 0U);
        auto* renameInformation =
            reinterpret_cast<FILE_RENAME_INFO*>(renameBuffer.data());
        renameInformation->ReplaceIfExists = FALSE;
        renameInformation->RootDirectory = nullptr;
        renameInformation->FileNameLength =
            static_cast<unsigned long>(kTargetNameBytes);
        std::memcpy(
            renameInformation->FileName,
            targetPath_.utf16(),
            kTargetNameBytes);
        if (!::SetFileInformationByHandle(
                fileHandle_,
                FileRenameInfo,
                renameInformation,
                static_cast<unsigned long>(kRenameInformationBytes)))
        {
            const unsigned long kRenameError = ::GetLastError();
            return fail(
                kRenameError == ERROR_FILE_EXISTS ||
                    kRenameError == ERROR_ALREADY_EXISTS
                    ? DriverModuleDumpFileError::kTargetExists
                    : DriverModuleDumpFileError::kCommit,
                kRenameError,
                QString::fromLatin1("The handle-based atomic no-replace commit failed."));
        }

        committed_ = true;
        closeHandle(fileHandle_);
        temporaryPath_.clear();
        error_ = DriverModuleDumpFileError::kNone;
        win32Error_ = ERROR_SUCCESS;
        technicalDetail_.clear();
        return true;
    }

    DriverModuleDumpFileError DriverModuleDumpFile::error() const noexcept
    {
        return error_;
    }

    unsigned long DriverModuleDumpFile::win32Error() const noexcept
    {
        return win32Error_;
    }

    QString DriverModuleDumpFile::technicalDetail() const
    {
        return technicalDetail_;
    }

    bool DriverModuleDumpFile::fail(
        const DriverModuleDumpFileError errorValue,
        const unsigned long win32ErrorValue,
        const QString& technicalDetailValue)
    {
        error_ = errorValue;
        win32Error_ = win32ErrorValue;
        technicalDetail_ = technicalDetailValue;
        return false;
    }

    void DriverModuleDumpFile::discard() noexcept
    {
        if (fileHandle_ != INVALID_HANDLE_VALUE)
        {
            // DELETE permission comes from the same handle used at creation; the file can be marked for deletion even while a scanner is reading it.
            if (!committed_)
            {
                FILE_DISPOSITION_INFO dispositionInformation{};
                dispositionInformation.DeleteFile = TRUE;
                ::SetFileInformationByHandle(
                    fileHandle_,
                    FileDispositionInfo,
                    &dispositionInformation,
                    sizeof(dispositionInformation));
            }
            closeHandle(fileHandle_);
        }

        if (!committed_ && !temporaryPath_.isEmpty())
        {
            const QString kTemporaryExtendedPath =
                extendedWin32Path(temporaryPath_);
            ::DeleteFileW(
                reinterpret_cast<LPCWSTR>(kTemporaryExtendedPath.utf16()));
        }
        temporaryPath_.clear();
    }
}
