#include "AtomicFilePatch.h"

// ============================================================
// ksword/scanner/atomic_file_patch.cpp
// Purpose:
// - Implement compare-before-write and range checks over an ordinary file.
// - Copy the complete source to a unique sibling temporary file.
// - Flush and commit with ReplaceFileW, optionally retaining a backup.
//
// ReplaceFileW failure is returned to the caller; there is intentionally no
// delete-and-rename fallback because that would weaken atomic replacement.
// The source lock is retained through temporary-file flush and final verification.
// Win32 still requires releasing a non-delete-shared source handle immediately
// before ReplaceFileW, leaving a documented, irreducible path-name race window.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <string>
#include <vector>

namespace ks::scanner
{
    namespace
    {
        struct FileIdentity
        {
            DWORD volumeSerial = 0;
            DWORD fileIndexHigh = 0;
            DWORD fileIndexLow = 0;
        };

        std::wstring systemErrorText(const DWORD errorCode)
        {
            wchar_t* messageBuffer = nullptr;
            const DWORD kLength = ::FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errorCode,
                0,
                reinterpret_cast<wchar_t*>(&messageBuffer),
                0,
                nullptr);
            std::wstring message;
            if (kLength != 0 && messageBuffer != nullptr)
            {
                message.assign(messageBuffer, messageBuffer + kLength);
                while (!message.empty() &&
                    (message.back() == L'\r' ||
                     message.back() == L'\n' ||
                     message.back() == L' '))
                {
                    message.pop_back();
                }
            }
            if (messageBuffer != nullptr)
            {
                ::LocalFree(messageBuffer);
            }
            if (message.empty())
            {
                message = L"Win32 error " + std::to_wstring(errorCode);
            }
            return message;
        }

        AtomicPatchResult failure(
            const std::wstring& action,
            const DWORD errorCode,
            const std::wstring& backupPath = {})
        {
            AtomicPatchResult result{};
            result.systemError = errorCode;
            result.backupPath = backupPath;
            result.errorText = action;
            if (errorCode != ERROR_SUCCESS)
            {
                result.errorText += L": " + systemErrorText(errorCode);
            }
            return result;
        }

        bool readExactly(
            const HANDLE handle,
            std::uint8_t* destination,
            std::size_t byteCount,
            DWORD& errorOut)
        {
            std::size_t totalRead = 0;
            while (totalRead < byteCount)
            {
                const DWORD kRequested = static_cast<DWORD>(std::min<std::size_t>(
                    byteCount - totalRead,
                    1024U * 1024U));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        handle,
                        destination + totalRead,
                        kRequested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    errorOut = ::GetLastError();
                    return false;
                }
                if (bytesRead == 0)
                {
                    errorOut = ERROR_HANDLE_EOF;
                    return false;
                }
                totalRead += bytesRead;
            }
            return true;
        }

        bool writeExactly(
            const HANDLE handle,
            const std::uint8_t* source,
            std::size_t byteCount,
            DWORD& errorOut)
        {
            std::size_t totalWritten = 0;
            while (totalWritten < byteCount)
            {
                const DWORD kRequested = static_cast<DWORD>(std::min<std::size_t>(
                    byteCount - totalWritten,
                    1024U * 1024U));
                DWORD bytesWritten = 0;
                if (::WriteFile(
                        handle,
                        source + totalWritten,
                        kRequested,
                        &bytesWritten,
                        nullptr) == FALSE)
                {
                    errorOut = ::GetLastError();
                    return false;
                }
                if (bytesWritten == 0)
                {
                    errorOut = ERROR_WRITE_FAULT;
                    return false;
                }
                totalWritten += bytesWritten;
            }
            return true;
        }

        bool seekAbsolute(
            const HANDLE handle,
            const std::uint64_t offset,
            DWORD& errorOut)
        {
            if (offset > static_cast<std::uint64_t>(
                    std::numeric_limits<LONGLONG>::max()))
            {
                errorOut = ERROR_ARITHMETIC_OVERFLOW;
                return false;
            }
            LARGE_INTEGER distance{};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (::SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            return true;
        }

        // verifyTemporarySnapshot compares the complete locked source with the
        // flushed temporary image. Outside the patch range every byte must match;
        // inside it the source must still equal currentBytes and the temporary
        // file must contain replacementBytes. This catches ordinary writes and
        // most pre-existing writable-mapping changes that raced the copy pass.
        bool verifyTemporarySnapshot(
            const HANDLE sourceHandle,
            const HANDLE temporaryHandle,
            const std::uint64_t fileSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& currentBytes,
            const std::vector<std::uint8_t>& replacementBytes,
            DWORD& errorOut)
        {
            if (!seekAbsolute(sourceHandle, 0, errorOut) ||
                !seekAbsolute(temporaryHandle, 0, errorOut))
            {
                return false;
            }

            constexpr std::size_t kVerificationChunkBytes = 1024U * 1024U;
            std::vector<std::uint8_t> sourceBuffer(kVerificationChunkBytes);
            std::vector<std::uint8_t> temporaryBuffer(kVerificationChunkBytes);
            const std::uint64_t kPatchEnd =
                patchOffset + static_cast<std::uint64_t>(replacementBytes.size());
            std::uint64_t verifiedOffset = 0;

            while (verifiedOffset < fileSize)
            {
                const std::size_t kChunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        fileSize - verifiedOffset,
                        kVerificationChunkBytes));
                if (!readExactly(
                        sourceHandle,
                        sourceBuffer.data(),
                        kChunk,
                        errorOut) ||
                    !readExactly(
                        temporaryHandle,
                        temporaryBuffer.data(),
                        kChunk,
                        errorOut))
                {
                    return false;
                }

                for (std::size_t index = 0; index < kChunk; ++index)
                {
                    const std::uint64_t kAbsoluteOffset =
                        verifiedOffset + static_cast<std::uint64_t>(index);
                    if (kAbsoluteOffset >= patchOffset &&
                        kAbsoluteOffset < kPatchEnd)
                    {
                        const std::size_t kPatchIndex = static_cast<std::size_t>(
                            kAbsoluteOffset - patchOffset);
                        if (sourceBuffer[index] != currentBytes[kPatchIndex] ||
                            temporaryBuffer[index] != replacementBytes[kPatchIndex])
                        {
                            errorOut = ERROR_REVISION_MISMATCH;
                            return false;
                        }
                    }
                    else if (sourceBuffer[index] != temporaryBuffer[index])
                    {
                        errorOut = ERROR_REVISION_MISMATCH;
                        return false;
                    }
                }
                verifiedOffset += kChunk;
            }
            return true;
        }

        // queryOrdinaryFileIdentity performs handle-authoritative checks after
        // CreateFileW. FILE_FLAG_OPEN_REPARSE_POINT ensures a raced-in link is
        // inspected as a link instead of silently following it.
        bool queryOrdinaryFileIdentity(
            const HANDLE handle,
            const bool rejectReparsePoints,
            FileIdentity& identityOut,
            DWORD& errorOut)
        {
            BY_HANDLE_FILE_INFORMATION information{};
            if (::GetFileInformationByHandle(handle, &information) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            FILE_ATTRIBUTE_TAG_INFO tagInformation{};
            if (::GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfo,
                    &tagInformation,
                    sizeof(tagInformation)) == FALSE)
            {
                errorOut = ::GetLastError();
                return false;
            }
            if ((tagInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                errorOut = ERROR_DIRECTORY;
                return false;
            }
            if (rejectReparsePoints &&
                ((tagInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                 tagInformation.ReparseTag != 0))
            {
                errorOut = ERROR_REPARSE_TAG_INVALID;
                return false;
            }
            identityOut.volumeSerial = information.dwVolumeSerialNumber;
            identityOut.fileIndexHigh = information.nFileIndexHigh;
            identityOut.fileIndexLow = information.nFileIndexLow;
            return true;
        }

        bool sameIdentity(
            const FileIdentity& left,
            const FileIdentity& right) noexcept
        {
            return left.volumeSerial == right.volumeSerial &&
                left.fileIndexHigh == right.fileIndexHigh &&
                left.fileIndexLow == right.fileIndexLow;
        }

        HANDLE createSiblingTemporaryFile(
            const std::wstring& filePath,
            std::wstring& temporaryPathOut,
            DWORD& errorOut)
        {
            const DWORD kProcessId = ::GetCurrentProcessId();
            const ULONGLONG kTick = ::GetTickCount64();
            for (unsigned int attempt = 0; attempt < 128; ++attempt)
            {
                temporaryPathOut =
                    filePath +
                    L".ksword.tmp." +
                    std::to_wstring(kProcessId) +
                    L"." +
                    std::to_wstring(kTick) +
                    L"." +
                    std::to_wstring(attempt);
                HANDLE handle = ::CreateFileW(
                    temporaryPathOut.c_str(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    0,
                    nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
                if (handle != INVALID_HANDLE_VALUE)
                {
                    return handle;
                }
                errorOut = ::GetLastError();
                if (errorOut != ERROR_FILE_EXISTS &&
                    errorOut != ERROR_ALREADY_EXISTS)
                {
                    return INVALID_HANDLE_VALUE;
                }
            }
            errorOut = ERROR_FILE_EXISTS;
            return INVALID_HANDLE_VALUE;
        }

        // verifyRecoveredTarget confirms that an ambiguous ReplaceFileW failure
        // was repaired by moving the already-flushed temporary image back to the
        // requested path. It never follows a raced-in reparse point.
        bool verifyRecoveredTarget(
            const std::wstring& filePath,
            const bool rejectReparsePoints,
            const std::uint64_t expectedSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& replacementBytes,
            DWORD& errorOut)
        {
            HANDLE recoveredHandle = ::CreateFileW(
                filePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            if (recoveredHandle == INVALID_HANDLE_VALUE)
            {
                errorOut = ::GetLastError();
                return false;
            }

            FileIdentity recoveredIdentity{};
            LARGE_INTEGER recoveredSize{};
            std::vector<std::uint8_t> recoveredBytes(replacementBytes.size());
            bool verified = queryOrdinaryFileIdentity(
                recoveredHandle,
                rejectReparsePoints,
                recoveredIdentity,
                errorOut);
            if (verified && ::GetFileSizeEx(recoveredHandle, &recoveredSize) == FALSE)
            {
                errorOut = ::GetLastError();
                verified = false;
            }
            if (verified &&
                (recoveredSize.QuadPart < 0 ||
                 static_cast<std::uint64_t>(recoveredSize.QuadPart) != expectedSize))
            {
                errorOut = ERROR_REVISION_MISMATCH;
                verified = false;
            }
            if (verified &&
                (!seekAbsolute(recoveredHandle, patchOffset, errorOut) ||
                 !readExactly(
                     recoveredHandle,
                     recoveredBytes.data(),
                     recoveredBytes.size(),
                     errorOut) ||
                 recoveredBytes != replacementBytes))
            {
                if (errorOut == ERROR_SUCCESS)
                {
                    errorOut = ERROR_REVISION_MISMATCH;
                }
                verified = false;
            }
            ::CloseHandle(recoveredHandle);
            return verified;
        }

        // handleReplaceFailure follows the documented 1175/1176/1177 state
        // transitions. In the two ambiguous cases the temporary image may be the
        // only recoverable replacement, so it is moved to the missing target or
        // deliberately preserved for manual recovery instead of being deleted.
        AtomicPatchResult handleReplaceFailure(
            const std::wstring& filePath,
            const std::wstring& temporaryPath,
            const std::wstring& backupPath,
            const bool createBackup,
            const bool rejectReparsePoints,
            const std::uint64_t expectedSize,
            const std::uint64_t patchOffset,
            const std::vector<std::uint8_t>& replacementBytes,
            const DWORD replaceError)
        {
            const bool kTargetMayBeMissing =
                (replaceError == ERROR_UNABLE_TO_MOVE_REPLACEMENT &&
                 !createBackup) ||
                replaceError == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2;
            if (!kTargetMayBeMissing)
            {
                AtomicPatchResult result = failure(
                    L"Atomic ReplaceFileW commit failed",
                    replaceError,
                    backupPath);
                if (::DeleteFileW(temporaryPath.c_str()) == FALSE &&
                    ::GetFileAttributesW(temporaryPath.c_str()) !=
                        INVALID_FILE_ATTRIBUTES)
                {
                    result.errorText +=
                        L"; the replacement file was preserved at: " +
                        temporaryPath;
                }
                return result;
            }

            // Do not use MOVEFILE_REPLACE_EXISTING: an unexpectedly present
            // target means the documented partial-state assumptions no longer
            // hold, and preserving both paths is safer than overwriting either.
            if (::MoveFileExW(
                    temporaryPath.c_str(),
                    filePath.c_str(),
                    MOVEFILE_WRITE_THROUGH) != FALSE)
            {
                DWORD verificationError = ERROR_SUCCESS;
                if (verifyRecoveredTarget(
                        filePath,
                        rejectReparsePoints,
                        expectedSize,
                        patchOffset,
                        replacementBytes,
                        verificationError))
                {
                    AtomicPatchResult result{};
                    result.success = true;
                    result.changed = true;
                    result.recoveredAfterReplaceFailure = true;
                    result.backupPath = backupPath;
                    return result;
                }

                AtomicPatchResult result = failure(
                    L"ReplaceFileW entered a partial state; the replacement was restored to the target path but verification failed",
                    verificationError,
                    backupPath);
                result.errorText +=
                    L"; original ReplaceFileW error: " +
                    std::to_wstring(replaceError);
                return result;
            }

            const DWORD kRecoveryError = ::GetLastError();
            AtomicPatchResult result = failure(
                L"ReplaceFileW entered a partial state and automatic recovery failed",
                kRecoveryError,
                backupPath);
            result.errorText +=
                L"; original ReplaceFileW error: " +
                std::to_wstring(replaceError) +
                L"; the replacement file was preserved at: " +
                temporaryPath;
            return result;
        }
    }

    AtomicPatchResult patchFileAtOffsetAtomic(
        const std::wstring& filePath,
        const std::uint64_t offset,
        const std::vector<std::uint8_t>& replacementBytes,
        const AtomicPatchOptions& options)
    {
        if (filePath.empty())
        {
            return failure(L"The file path is empty", ERROR_INVALID_PARAMETER);
        }
        if (options.maxFileBytes == 0 ||
            options.maxPatchBytes == 0 ||
            replacementBytes.size() > options.maxPatchBytes)
        {
            return failure(L"Patch limits are invalid or exceeded", ERROR_INVALID_PARAMETER);
        }
        if (!options.expectedBytes.empty() &&
            options.expectedBytes.size() != replacementBytes.size())
        {
            return failure(
                L"expectedBytes must be empty or match replacementBytes size",
                ERROR_INVALID_PARAMETER);
        }
        if (replacementBytes.empty())
        {
            AtomicPatchResult result{};
            result.success = true;
            result.changed = false;
            return result;
        }

        const DWORD kAttributes = ::GetFileAttributesW(filePath.c_str());
        if (kAttributes == INVALID_FILE_ATTRIBUTES)
        {
            return failure(L"GetFileAttributesW failed", ::GetLastError());
        }
        if ((kAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            return failure(L"The target is a directory", ERROR_DIRECTORY);
        }
        if (options.rejectReparsePoints &&
            (kAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return failure(
                L"Reparse-point targets are rejected by policy",
                ERROR_REPARSE_TAG_INVALID);
        }

        const std::wstring kBackupPath = options.createBackup
            ? (options.backupPath.empty()
                ? filePath + L".ksword.bak"
                : options.backupPath)
            : std::wstring();
        if (options.createBackup &&
            _wcsicmp(kBackupPath.c_str(), filePath.c_str()) == 0)
        {
            return failure(
                L"The backup path must differ from the target",
                ERROR_INVALID_PARAMETER,
                kBackupPath);
        }
        if (options.createBackup &&
            !options.overwriteBackup &&
            ::GetFileAttributesW(kBackupPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            return failure(
                L"The backup path already exists",
                ERROR_FILE_EXISTS,
                kBackupPath);
        }

        HANDLE sourceHandle = ::CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL |
                FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (sourceHandle == INVALID_HANDLE_VALUE)
        {
            return failure(
                L"Opening the target failed",
                ::GetLastError(),
                kBackupPath);
        }

        DWORD error = ERROR_SUCCESS;
        FileIdentity initialIdentity{};
        if (!queryOrdinaryFileIdentity(
                sourceHandle,
                options.rejectReparsePoints,
                initialIdentity,
                error))
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"Handle-level target validation failed",
                error,
                kBackupPath);
        }

        LARGE_INTEGER fileSize{};
        if (::GetFileSizeEx(sourceHandle, &fileSize) == FALSE ||
            fileSize.QuadPart < 0)
        {
            const DWORD kSizeError = ::GetLastError();
            ::CloseHandle(sourceHandle);
            return failure(L"Reading the target size failed", kSizeError, kBackupPath);
        }
        const std::uint64_t kUnsignedSize =
            static_cast<std::uint64_t>(fileSize.QuadPart);
        if (kUnsignedSize > options.maxFileBytes)
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"The target exceeds maxFileBytes",
                ERROR_FILE_TOO_LARGE,
                kBackupPath);
        }
        if (offset > kUnsignedSize ||
            replacementBytes.size() > kUnsignedSize - offset)
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"The patch range is outside the file",
                ERROR_INVALID_PARAMETER,
                kBackupPath);
        }

        std::vector<std::uint8_t> currentBytes(replacementBytes.size());
        if (!seekAbsolute(sourceHandle, offset, error) ||
            !readExactly(
                sourceHandle,
                currentBytes.data(),
                currentBytes.size(),
                error))
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"Reading the target patch range failed",
                error,
                kBackupPath);
        }
        if (!options.expectedBytes.empty() &&
            currentBytes != options.expectedBytes)
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"The target bytes do not match expectedBytes",
                ERROR_REVISION_MISMATCH,
                kBackupPath);
        }
        if (currentBytes == replacementBytes)
        {
            ::CloseHandle(sourceHandle);
            AtomicPatchResult result{};
            result.success = true;
            result.changed = false;
            result.backupPath = kBackupPath;
            return result;
        }
        if (!seekAbsolute(sourceHandle, 0, error))
        {
            ::CloseHandle(sourceHandle);
            return failure(L"Rewinding the target failed", error, kBackupPath);
        }

        std::wstring temporaryPath;
        HANDLE temporaryHandle =
            createSiblingTemporaryFile(filePath, temporaryPath, error);
        if (temporaryHandle == INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(sourceHandle);
            return failure(
                L"Creating the sibling temporary file failed",
                error,
                kBackupPath);
        }

        bool copySucceeded = true;
        std::vector<std::uint8_t> copyBuffer(1024U * 1024U);
        std::uint64_t remaining = kUnsignedSize;
        while (remaining != 0)
        {
            const std::size_t kChunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, copyBuffer.size()));
            if (!readExactly(sourceHandle, copyBuffer.data(), kChunk, error) ||
                !writeExactly(temporaryHandle, copyBuffer.data(), kChunk, error))
            {
                copySucceeded = false;
                break;
            }
            remaining -= kChunk;
        }

        if (copySucceeded &&
            (!seekAbsolute(temporaryHandle, offset, error) ||
             !writeExactly(
                 temporaryHandle,
                 replacementBytes.data(),
                 replacementBytes.size(),
                 error)))
        {
            copySucceeded = false;
        }
        if (copySucceeded && ::FlushFileBuffers(temporaryHandle) == FALSE)
        {
            error = ::GetLastError();
            copySucceeded = false;
        }

        if (!copySucceeded)
        {
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return failure(
                L"Building the replacement file failed",
                error,
                kBackupPath);
        }

        // Revalidate the still-locked source after the replacement bytes and all
        // unchanged bytes have reached the temporary file. This closes the prior
        // TOCTOU window in which the source handle was released before Flush.
        LARGE_INTEGER verifiedSize{};
        FileIdentity verifiedIdentity{};
        bool finalVerificationSucceeded = true;
        if (::GetFileSizeEx(sourceHandle, &verifiedSize) == FALSE)
        {
            error = ::GetLastError();
            finalVerificationSucceeded = false;
        }
        else if (verifiedSize.QuadPart != fileSize.QuadPart)
        {
            error = ERROR_REVISION_MISMATCH;
            finalVerificationSucceeded = false;
        }
        if (finalVerificationSucceeded &&
            (!queryOrdinaryFileIdentity(
                sourceHandle,
                options.rejectReparsePoints,
                verifiedIdentity,
                error) ||
             !sameIdentity(initialIdentity, verifiedIdentity) ||
             !verifyTemporarySnapshot(
                 sourceHandle,
                 temporaryHandle,
                 kUnsignedSize,
                 offset,
                 currentBytes,
                 replacementBytes,
                 error)))
        {
            finalVerificationSucceeded = false;
        }
        if (!finalVerificationSucceeded)
        {
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_REVISION_MISMATCH;
            }
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return failure(
                L"The target changed during replacement preparation",
                error,
                kBackupPath);
        }

        // Confirm that resolving the path still reaches the same file identity.
        // The original handle denies delete sharing, so the path cannot be swapped
        // while this verification handle is opened.
        HANDLE pathVerificationHandle = ::CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        FileIdentity pathIdentity{};
        if (pathVerificationHandle == INVALID_HANDLE_VALUE ||
            !queryOrdinaryFileIdentity(
                pathVerificationHandle,
                options.rejectReparsePoints,
                pathIdentity,
                error) ||
            !sameIdentity(initialIdentity, pathIdentity))
        {
            if (pathVerificationHandle == INVALID_HANDLE_VALUE)
            {
                error = ::GetLastError();
            }
            else
            {
                ::CloseHandle(pathVerificationHandle);
            }
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_REVISION_MISMATCH;
            }
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return failure(
                L"The target path identity changed",
                error,
                kBackupPath);
        }
        ::CloseHandle(pathVerificationHandle);

        if (options.createBackup &&
            options.overwriteBackup &&
            ::GetFileAttributesW(kBackupPath.c_str()) != INVALID_FILE_ATTRIBUTES &&
            ::DeleteFileW(kBackupPath.c_str()) == FALSE)
        {
            error = ::GetLastError();
            ::CloseHandle(temporaryHandle);
            ::CloseHandle(sourceHandle);
            ::DeleteFileW(temporaryPath.c_str());
            return failure(
                L"Removing the previous backup failed",
                error,
                kBackupPath);
        }

        // ReplaceFileW cannot commit while the non-delete-shared source handle is
        // open. Release both handles only after all identity/content checks, then
        // commit in the immediately following call.
        ::CloseHandle(temporaryHandle);
        ::CloseHandle(sourceHandle);
        if (::ReplaceFileW(
                filePath.c_str(),
                temporaryPath.c_str(),
                options.createBackup ? kBackupPath.c_str() : nullptr,
                0,
                nullptr,
                nullptr) == FALSE)
        {
            error = ::GetLastError();
            return handleReplaceFailure(
                filePath,
                temporaryPath,
                kBackupPath,
                options.createBackup,
                options.rejectReparsePoints,
                kUnsignedSize,
                offset,
                replacementBytes,
                error);
        }

        AtomicPatchResult result{};
        result.success = true;
        result.changed = true;
        result.backupPath = kBackupPath;
        return result;
    }
}
