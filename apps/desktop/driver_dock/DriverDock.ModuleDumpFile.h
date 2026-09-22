#pragma once

// ============================================================
// DriverDock.ModuleDumpFile.h
// Purpose:
// - Create and hold a temporary file handle with DELETE permissions in the target directory;
// - Performs atomic refresh and non-overwriting rename using the same handle.
// - On failure, delete the temporary file by handle to avoid leaving an incomplete kernel image.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <QString>

#include <cstddef>
#include <cstdint>

namespace ksword::driver_dock_internal
{
    // DriverModuleDumpFileError: Distinguishes failure stages during the temporary file
    // lifecycle, allowing the caller to map them to localized error messages for DriverDock.
    enum class DriverModuleDumpFileError : std::uint32_t
    {
        kNone = 0U,
        kCreate,
        kWrite,
        kFlush,
        kTargetExists,
        kCommit
    };

    class DriverModuleDumpFile final
    {
    public:
        // After construction, call create first, then call write any number of times, and finally call commit.
        DriverModuleDumpFile() noexcept = default;
        ~DriverModuleDumpFile() noexcept;

        DriverModuleDumpFile(const DriverModuleDumpFile&) = delete;
        DriverModuleDumpFile& operator=(const DriverModuleDumpFile&) = delete;
        DriverModuleDumpFile(DriverModuleDumpFile&&) = delete;
        DriverModuleDumpFile& operator=(DriverModuleDumpFile&&) = delete;

        // create: Input final target path; output indicates whether a protected temporary file has already been created in the same directory.
        bool create(const QString& targetPath);

        // write: Input memory block address and length; Output indicates whether the data was fully written to the current temporary file.
        bool write(const std::uint8_t* dataPointer, std::size_t byteCount);

        // commit: Input expected file size; flushes data and renames via the original handle without overwriting.
        bool commit(std::uint64_t expectedFileBytes);

        DriverModuleDumpFileError error() const noexcept;
        unsigned long win32Error() const noexcept;
        QString technicalDetail() const;

    private:
        // fail: Centralizes recording of the failure stage, Win32 error code, and internal diagnostic text.
        bool fail(
            DriverModuleDumpFileError errorValue,
            unsigned long win32ErrorValue,
            const QString& technicalDetailValue);

        // discard: On failure or early return, prefer deleting the temporary file via the still-held DELETE handle.
        void discard() noexcept;

        HANDLE fileHandle_ = INVALID_HANDLE_VALUE; // m_fileHandle: Handle for temporary file read/write, deletion, and renaming.
        QString temporaryPath_; // m_temporaryPath: Absolute path for temporary files used during exception cleanup.
        QString targetPath_; // m_targetPath: The final absolute path used by FileRenameInfo.
        bool committed_ = false; // m_committed: Prevent the destructor from deleting the final file after a successful rename.
        DriverModuleDumpFileError error_ = DriverModuleDumpFileError::kNone; // m_error: Last failed stage.
        unsigned long win32Error_ = ERROR_SUCCESS; // m_win32Error: Last Win32 error code.
        QString technicalDetail_; // m_technicalDetail: Internal diagnostics for failure popups and logs.
    };
}
