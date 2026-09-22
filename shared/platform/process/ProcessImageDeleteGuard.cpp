#include "ProcessImageDeleteGuard.h"

#include "Process.h"

#include <array>
#include <iomanip>
#include <sstream>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // formatWin32Error: converts Win32 error codes into stable log text.
    std::string formatWin32Error(const DWORD errorCode)
    {
        std::array<wchar_t, 512> messageBuffer{};
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS |
                FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr,
            errorCode,
            0,
            messageBuffer.data(),
            static_cast<DWORD>(messageBuffer.size()),
            nullptr);

        std::ostringstream stream;
        stream << "Win32Error=" << errorCode;
        if (kMessageLength != 0U)
        {
            const int kUtf8Bytes = ::WideCharToMultiByte(
                CP_UTF8,
                0,
                messageBuffer.data(),
                static_cast<int>(kMessageLength),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (kUtf8Bytes > 0)
            {
                std::string utf8Text(static_cast<std::size_t>(kUtf8Bytes), '\0');
                (void)::WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    messageBuffer.data(),
                    static_cast<int>(kMessageLength),
                    utf8Text.data(),
                    kUtf8Bytes,
                    nullptr,
                    nullptr);
                stream << " (" << utf8Text << ")";
            }
        }
        return stream.str();
    }

    // utf8ToWide: ProcessRecord uses UTF-8 std::string; this function is used only for real-time path conversion.
    bool utf8ToWide(const std::string& sourceText, std::wstring& wideTextOut)
    {
        wideTextOut.clear();
        if (sourceText.empty())
        {
            return false;
        }

        const int kRequiredChars = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            sourceText.data(),
            static_cast<int>(sourceText.size()),
            nullptr,
            0);
        if (kRequiredChars <= 0)
        {
            return false;
        }

        wideTextOut.resize(static_cast<std::size_t>(kRequiredChars));
        const int kConvertedChars = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            sourceText.data(),
            static_cast<int>(sourceText.size()),
            wideTextOut.data(),
            kRequiredChars);
        if (kConvertedChars != kRequiredChars)
        {
            wideTextOut.clear();
            return false;
        }
        return true;
    }

    // queryFileIdentity: Reads the stable volume serial number and 64-bit file index.
    bool queryFileIdentity(
        const HANDLE fileHandle,
        std::uint32_t& volumeSerialOut,
        std::uint64_t& fileIdentityOut,
        bool& directoryOut,
        DWORD& errorOut)
    {
        BY_HANDLE_FILE_INFORMATION fileInformation{};
        if (::GetFileInformationByHandle(fileHandle, &fileInformation) == FALSE)
        {
            errorOut = ::GetLastError();
            return false;
        }

        volumeSerialOut = fileInformation.dwVolumeSerialNumber;
        fileIdentityOut =
            (static_cast<std::uint64_t>(fileInformation.nFileIndexHigh) << 32U) |
            static_cast<std::uint64_t>(fileInformation.nFileIndexLow);
        directoryOut = (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U;
        errorOut = ERROR_SUCCESS;
        return true;
    }

    // queryFinalPath: retrieves the canonical path from an open handle; on failure, returns empty without affecting file identity locking.
    std::wstring queryFinalPath(const HANDLE fileHandle)
    {
        const DWORD kRequiredChars = ::GetFinalPathNameByHandleW(
            fileHandle,
            nullptr,
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (kRequiredChars == 0U)
        {
            return std::wstring();
        }

        std::wstring pathBuffer(static_cast<std::size_t>(kRequiredChars), L'\0');
        const DWORD kCopiedChars = ::GetFinalPathNameByHandleW(
            fileHandle,
            pathBuffer.data(),
            kRequiredChars,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (kCopiedChars == 0U || kCopiedChars >= kRequiredChars)
        {
            return std::wstring();
        }
        pathBuffer.resize(static_cast<std::size_t>(kCopiedChars));
        return pathBuffer;
    }

    // sameFileObject: Compares two paths to determine if they point to the same file object using volume serial number and file index.
    bool sameFileObject(
        const HANDLE leftHandle,
        const HANDLE rightHandle,
        DWORD& errorOut)
    {
        std::uint32_t leftVolume = 0;
        std::uint32_t rightVolume = 0;
        std::uint64_t leftIdentity = 0;
        std::uint64_t rightIdentity = 0;
        bool leftDirectory = false;
        bool rightDirectory = false;
        if (!queryFileIdentity(
                leftHandle,
                leftVolume,
                leftIdentity,
                leftDirectory,
                errorOut))
        {
            return false;
        }
        if (!queryFileIdentity(
                rightHandle,
                rightVolume,
                rightIdentity,
                rightDirectory,
                errorOut))
        {
            return false;
        }
        errorOut = ERROR_SUCCESS;
        return !leftDirectory && !rightDirectory &&
            leftVolume == rightVolume && leftIdentity == rightIdentity;
    }

    // setDeleteDispositionOnce: Prioritizes the modern interface that ignores read-only attributes, falling back to the classic interface.
    bool setDeleteDispositionOnce(
        const HANDLE fileHandle,
        DWORD& extendedErrorOut,
        DWORD& legacyErrorOut)
    {
        FILE_DISPOSITION_INFO_EX extendedDisposition{};
        extendedDisposition.Flags =
            FILE_DISPOSITION_FLAG_DELETE |
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfoEx,
                &extendedDisposition,
                sizeof(extendedDisposition)) != FALSE)
        {
            extendedErrorOut = ERROR_SUCCESS;
            legacyErrorOut = ERROR_SUCCESS;
            return true;
        }
        extendedErrorOut = ::GetLastError();

        FILE_DISPOSITION_INFO legacyDisposition{};
        legacyDisposition.DeleteFile = TRUE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfo,
                &legacyDisposition,
                sizeof(legacyDisposition)) != FALSE)
        {
            legacyErrorOut = ERROR_SUCCESS;
            return true;
        }
        legacyErrorOut = ::GetLastError();
        return false;
    }
}

ks::process::CapturedProcessImageDeleteTarget::~CapturedProcessImageDeleteTarget()
{
    close();
}

ks::process::CapturedProcessImageDeleteTarget::CapturedProcessImageDeleteTarget(
    CapturedProcessImageDeleteTarget&& other) noexcept
    : fileHandle_(std::exchange(other.fileHandle_, nullptr)),
      finalPath_(std::move(other.finalPath_)),
      fileIdentity_(std::exchange(other.fileIdentity_, 0U)),
      volumeSerialNumber_(std::exchange(other.volumeSerialNumber_, 0U))
{
}

ks::process::CapturedProcessImageDeleteTarget&
ks::process::CapturedProcessImageDeleteTarget::operator=(
    CapturedProcessImageDeleteTarget&& other) noexcept
{
    if (this != &other)
    {
        close();
        fileHandle_ = std::exchange(other.fileHandle_, nullptr);
        finalPath_ = std::move(other.finalPath_);
        fileIdentity_ = std::exchange(other.fileIdentity_, 0U);
        volumeSerialNumber_ = std::exchange(other.volumeSerialNumber_, 0U);
    }
    return *this;
}

bool ks::process::CapturedProcessImageDeleteTarget::valid() const noexcept
{
    return fileHandle_ != nullptr && fileHandle_ != INVALID_HANDLE_VALUE;
}

const std::wstring& ks::process::CapturedProcessImageDeleteTarget::finalPath() const noexcept
{
    return finalPath_;
}

std::uint64_t ks::process::CapturedProcessImageDeleteTarget::fileIdentity() const noexcept
{
    return fileIdentity_;
}

std::uint32_t ks::process::CapturedProcessImageDeleteTarget::volumeSerialNumber() const noexcept
{
    return volumeSerialNumber_;
}

void ks::process::CapturedProcessImageDeleteTarget::close() noexcept
{
    if (valid())
    {
        (void)::CloseHandle(static_cast<HANDLE>(fileHandle_));
    }
    fileHandle_ = nullptr;
    finalPath_.clear();
    fileIdentity_ = 0U;
    volumeSerialNumber_ = 0U;
}

bool ks::process::captureProcessImageDeleteTarget(
    const std::uint32_t processId,
    const std::uint64_t expectedCreationTime100ns,
    const std::wstring& expectedImagePath,
    CapturedProcessImageDeleteTarget* const targetOut,
    std::string* const detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }
    if (targetOut == nullptr || processId == 0U || expectedCreationTime100ns == 0U || expectedImagePath.empty())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "invalid process image deletion target";
        }
        return false;
    }
    targetOut->close();

    std::uint64_t currentCreationTime100ns = 0U;
    std::string identityDetail;
    if (!queryProcessCreationTimeByPid(processId, &currentCreationTime100ns, &identityDetail) ||
        currentCreationTime100ns != expectedCreationTime100ns)
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = currentCreationTime100ns != 0U
                ? "PID creation time changed; refusing to target a reused PID"
                : (identityDetail.empty() ? "process identity is unavailable" : identityDetail);
        }
        return false;
    }

    const std::string kLiveImagePathUtf8 = queryProcessPathByPid(processId);
    std::wstring liveImagePath;
    if (!utf8ToWide(kLiveImagePathUtf8, liveImagePath) || liveImagePath.empty())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "live process image path is unavailable or is not valid UTF-8";
        }
        return false;
    }

    const HANDLE kLiveFileHandle = ::CreateFileW(
        liveImagePath.c_str(),
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (kLiveFileHandle == INVALID_HANDLE_VALUE)
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "open live process image with DELETE access failed: " +
                formatWin32Error(::GetLastError());
        }
        return false;
    }

    const HANDLE kExpectedFileHandle = ::CreateFileW(
        expectedImagePath.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (kExpectedFileHandle == INVALID_HANDLE_VALUE)
    {
        const DWORD kOpenError = ::GetLastError();
        (void)::CloseHandle(kLiveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "open selected snapshot image failed: " + formatWin32Error(kOpenError);
        }
        return false;
    }

    DWORD compareError = ERROR_SUCCESS;
    const bool kIdentitiesMatch = sameFileObject(kLiveFileHandle, kExpectedFileHandle, compareError);
    (void)::CloseHandle(kExpectedFileHandle);
    if (!kIdentitiesMatch)
    {
        (void)::CloseHandle(kLiveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = compareError == ERROR_SUCCESS
                ? "selected image path no longer identifies the live process image"
                : "file identity comparison failed: " + formatWin32Error(compareError);
        }
        return false;
    }

    std::uint32_t volumeSerialNumber = 0U;
    std::uint64_t fileIdentity = 0U;
    bool isDirectory = false;
    DWORD identityError = ERROR_SUCCESS;
    if (!queryFileIdentity(
            kLiveFileHandle,
            volumeSerialNumber,
            fileIdentity,
            isDirectory,
            identityError) ||
        isDirectory)
    {
        (void)::CloseHandle(kLiveFileHandle);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = isDirectory
                ? "process image target unexpectedly resolves to a directory"
                : "query process image file identity failed: " + formatWin32Error(identityError);
        }
        return false;
    }

    targetOut->fileHandle_ = kLiveFileHandle;
    targetOut->finalPath_ = queryFinalPath(kLiveFileHandle);
    if (targetOut->finalPath_.empty())
    {
        targetOut->finalPath_ = liveImagePath;
    }
    targetOut->fileIdentity_ = fileIdentity;
    targetOut->volumeSerialNumber_ = volumeSerialNumber;

    if (detailTextOut != nullptr)
    {
        std::ostringstream stream;
        stream << "captured image handle; volume=0x" << std::hex << volumeSerialNumber
            << ", fileId=0x" << fileIdentity;
        *detailTextOut = stream.str();
    }
    return true;
}

bool ks::process::deleteCapturedProcessImage(
    CapturedProcessImageDeleteTarget* const target,
    std::string* const detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }
    if (target == nullptr || !target->valid())
    {
        if (detailTextOut != nullptr)
        {
            *detailTextOut = "captured image handle is invalid";
        }
        return false;
    }

    DWORD extendedError = ERROR_SUCCESS;
    DWORD legacyError = ERROR_SUCCESS;
    bool deletionMarked = false;
    constexpr int kDeleteRetryCount = 20;
    constexpr DWORD kDeleteRetryDelayMilliseconds = 50U;
    for (int attemptIndex = 0; attemptIndex < kDeleteRetryCount; ++attemptIndex)
    {
        deletionMarked = setDeleteDispositionOnce(
            static_cast<HANDLE>(target->fileHandle_),
            extendedError,
            legacyError);
        if (deletionMarked)
        {
            break;
        }
        if (attemptIndex + 1 < kDeleteRetryCount)
        {
            ::Sleep(kDeleteRetryDelayMilliseconds);
        }
    }

    std::ostringstream stream;
    stream << "volume=0x" << std::hex << target->volumeSerialNumber_
        << ", fileId=0x" << target->fileIdentity_;
    if (deletionMarked)
    {
        FILE_STANDARD_INFO standardInformation{};
        const bool kDeletePending = ::GetFileInformationByHandleEx(
            static_cast<HANDLE>(target->fileHandle_),
            FileStandardInfo,
            &standardInformation,
            sizeof(standardInformation)) != FALSE &&
            standardInformation.DeletePending != FALSE;
        stream << ", deleteDisposition=set, deletePending=" << (kDeletePending ? "true" : "unknown");
        if (detailTextOut != nullptr)
        {
            *detailTextOut = stream.str();
        }
        return true;
    }

    stream << ", FileDispositionInfoEx=" << formatWin32Error(extendedError)
        << ", FileDispositionInfo=" << formatWin32Error(legacyError);
    if (detailTextOut != nullptr)
    {
        *detailTextOut = stream.str();
    }
    return false;
}
