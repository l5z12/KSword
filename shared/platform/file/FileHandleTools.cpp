#include "FileHandleTools.h"

#include "../process/Process.h"
#include "../string/String.h"
#include "../../ark_client/ArkDriverClient.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <TlHelp32.h>
#include <sddl.h>
#include <winioctl.h>

namespace ks::file
{
    namespace
    {
        // NtQuerySystemInformation/NtQueryObject class values are kept local so this file
        // remains stable across SDK revisions that expose different enum names.
        constexpr ULONG kSystemExtendedHandleInformationClass = 64;
        constexpr ULONG kObjectBasicInformationClass = 0;
        constexpr ULONG kObjectNameInformationClass = 1;
        constexpr ULONG kObjectTypeInformationClass = 2;
        constexpr ULONG kMaxReparseBufferBytes = 16U * 1024U;
        constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004);
        constexpr NTSTATUS kStatusInvalidCid = static_cast<NTSTATUS>(0xC000000B);
        constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005);
        constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023);
        constexpr std::uint32_t kReparseTagMicrosoftFlag = 0x80000000U;
        constexpr std::uint32_t kReparseTagNameSurrogateFlag = 0x20000000U;
        constexpr std::uint32_t kReparseTagAppExecLink =
#ifdef IO_REPARSE_TAG_APPEXECLINK
            IO_REPARSE_TAG_APPEXECLINK;
#else
            0x8000001BU;
#endif
        constexpr USHORT kSymbolicLinkRelativeFlag = 1U;

        bool isProcessGone(const std::uint32_t processId)
        {
            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE,
                processId);
            if (kProcessHandle == nullptr)
            {
                return ::GetLastError() == ERROR_INVALID_PARAMETER;
            }

            DWORD exitCode = STILL_ACTIVE;
            const bool kGone = ::GetExitCodeProcess(kProcessHandle, &exitCode) != FALSE &&
                exitCode != STILL_ACTIVE;
            ::CloseHandle(kProcessHandle);
            return kGone;
        }

        // isCancellationRequested: Centralizes optional cancellation callback handling to avoid missing close requests in scan loops.
        bool isCancellationRequested(const CancellationCallback& cancellationCallback)
        {
            return cancellationCallback && cancellationCallback();
        }

        // readableArkIoMessage:
        // - Input: UTF-8 diagnostic text returned by ArkDriverClient and the current capability name.
        // - Processing: Convert low-level English logs such as DeviceIoControl, unsupported, DynData, and buffer into Chinese descriptions.
        // - Returns: text suitable for FileDock/file contention diagnosis display, avoiding direct injection of raw IOCTL logs into the UI.
        std::wstring readableArkIoMessage(
            const std::string& rawMessage,
            const std::wstring& subjectText)
        {
            if (rawMessage.empty())
            {
                return subjectText + L"无额外驱动诊断";
            }

            std::string lowerMessage = rawMessage;
            for (char& ch : lowerMessage)
            {
                if (ch >= 'A' && ch <= 'Z')
                {
                    ch = static_cast<char>(ch - 'A' + 'a');
                }
            }

            if (lowerMessage.find("deviceiocontrol") != std::string::npos)
            {
                return subjectText + L"驱动调用失败或 R3/R0 协议版本不匹配";
            }
            if (lowerMessage.find("unsupported") != std::string::npos ||
                lowerMessage.find("not supported") != std::string::npos)
            {
                return subjectText + L"当前驱动暂不支持该只读枚举入口";
            }
            if (lowerMessage.find("dyndata") != std::string::npos ||
                lowerMessage.find("capability") != std::string::npos)
            {
                return subjectText + L"DynData capability 未满足，请查看内核动态偏移状态";
            }
            if (lowerMessage.find("too small") != std::string::npos ||
                lowerMessage.find("entrysize") != std::string::npos ||
                lowerMessage.find("invalid") != std::string::npos)
            {
                return subjectText + L"驱动返回结构与当前 R3 协议不匹配或缓冲区不足";
            }

            return subjectText + ks::str::utf8ToUtf16(rawMessage);
        }

        // Native mirror for SystemExtendedHandleInformation rows. Only fields used by
        // FileDock and HandleDock are modeled, and every access is bounded by buffer size.
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_NATIVE
        {
            PVOID objectAddress = nullptr;
            ULONG_PTR uniqueProcessId = 0;
            ULONG_PTR handleValue = 0;
            ULONG grantedAccess = 0;
            USHORT creatorBackTraceIndex = 0;
            USHORT objectTypeIndex = 0;
            ULONG handleAttributes = 0;
            ULONG reserved = 0;
        };

        // Variable-size header returned by SystemExtendedHandleInformation. The handles
        // member is a flexible tail and must never be trusted without external size checks.
        struct SYSTEM_HANDLE_INFORMATION_EX_NATIVE
        {
            ULONG_PTR numberOfHandles = 0;
            ULONG_PTR reserved = 0;
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_NATIVE handles[1] = {};
        };

        // Local layout for ObjectBasicInformation. The public UI only needs handle and
        // pointer counts, but the full prefix is required for NtQueryObject to fill it.
        struct OBJECT_BASIC_INFORMATION_NATIVE
        {
            ULONG attributes = 0;
            ACCESS_MASK grantedAccess = 0;
            ULONG handleCount = 0;
            ULONG pointerCount = 0;
            ULONG pagedPoolUsage = 0;
            ULONG nonPagedPoolUsage = 0;
            ULONG reserved[3] = {};
            ULONG nameInfoSize = 0;
            ULONG typeInfoSize = 0;
            ULONG securityDescriptorSize = 0;
            LARGE_INTEGER creationTime{};
        };

        // UniqueHandle gives backend code exception-safe HANDLE ownership. It accepts both
        // nullptr and INVALID_HANDLE_VALUE as invalid values and closes only valid handles.
        class UniqueHandle final
        {
        public:
            explicit UniqueHandle(HANDLE handleValue = nullptr) : handle_(handleValue) {}
            ~UniqueHandle() { reset(nullptr); }
            UniqueHandle(const UniqueHandle&) = delete;
            UniqueHandle& operator=(const UniqueHandle&) = delete;
            UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
            UniqueHandle& operator=(UniqueHandle&& other) noexcept
            {
                if (this != &other)
                {
                    reset(nullptr);
                    handle_ = other.handle_;
                    other.handle_ = nullptr;
                }
                return *this;
            }
            HANDLE get() const { return handle_; }
            bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
            HANDLE release()
            {
                HANDLE releasedHandle = handle_;
                handle_ = nullptr;
                return releasedHandle;
            }
            void reset(HANDLE newHandle)
            {
                if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
                {
                    ::CloseHandle(handle_);
                }
                handle_ = newHandle;
            }
        private:
            HANDLE handle_ = nullptr;
        };

        using NtSuspendProcessFn = NTSTATUS(NTAPI*)(HANDLE);
        using NtResumeProcessFn = NTSTATUS(NTAPI*)(HANDLE);
        constexpr DWORD kProcessSuspendResumeAccess = 0x0800U;

        // ScopedProcessResume ensures that any failure branch in handle closure verification restores the target process.
        class ScopedProcessResume final
        {
        public:
            ScopedProcessResume(HANDLE processHandle, NtResumeProcessFn resumeFunction)
                : processHandle_(processHandle), resumeFunction_(resumeFunction) {}
            ~ScopedProcessResume()
            {
                if (processHandle_ != nullptr && resumeFunction_ != nullptr)
                {
                    (void)resumeFunction_(processHandle_);
                }
            }
            ScopedProcessResume(const ScopedProcessResume&) = delete;
            ScopedProcessResume& operator=(const ScopedProcessResume&) = delete;

        private:
            HANDLE processHandle_ = nullptr;
            NtResumeProcessFn resumeFunction_ = nullptr;
        };

        // CachedObjectSnapshot stores object-level query results so multiple handles to the
        // same kernel object do not repeatedly duplicate/query the same object.
        struct CachedObjectSnapshot
        {
            bool basicInfoAvailable = false;
            std::uint32_t handleCount = 0;
            std::uint32_t pointerCount = 0;
            bool objectNameAvailable = false;
            bool objectNameFromFallback = false;
            std::wstring objectName;
        };

        // HandleIdentityKey is the stable identity used for R3/R0 diff merging.
        struct HandleIdentityKey
        {
            std::uint32_t processId = 0;
            std::uint64_t handleValue = 0;
            bool operator==(const HandleIdentityKey& other) const noexcept
            {
                return processId == other.processId && handleValue == other.handleValue;
            }
        };

        struct HandleIdentityKeyHash
        {
            std::size_t operator()(const HandleIdentityKey& key) const noexcept
            {
                const std::size_t kPidHash = std::hash<std::uint32_t>{}(key.processId);
                const std::size_t kHandleHash = std::hash<std::uint64_t>{}(key.handleValue);
                return kPidHash ^ (kHandleHash + 0x9e3779b97f4a7c15ULL + (kPidHash << 6) + (kPidHash >> 2));
            }
        };

        // trimWideCopy removes leading/trailing whitespace while preserving path body bytes.
        std::wstring trimWideCopy(const std::wstring& text)
        {
            std::size_t beginIndex = 0;
            while (beginIndex < text.size() && std::iswspace(text[beginIndex]) != 0) { ++beginIndex; }
            std::size_t endIndex = text.size();
            while (endIndex > beginIndex && std::iswspace(text[endIndex - 1]) != 0) { --endIndex; }
            return text.substr(beginIndex, endIndex - beginIndex);
        }

        // toLowerWideCopy implements case-insensitive comparison keys for Windows paths
        // and object type names without bringing in Qt string helpers.
        std::wstring toLowerWideCopy(std::wstring text)
        {
            std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return text;
        }

        bool equalsInsensitive(const std::wstring& left, const std::wstring& right)
        {
            return toLowerWideCopy(left) == toLowerWideCopy(right);
        }

        bool containsInsensitive(const std::wstring& haystack, const std::wstring& needle)
        {
            return needle.empty() || toLowerWideCopy(haystack).find(toLowerWideCopy(needle)) != std::wstring::npos;
        }

        bool startsWithInsensitive(const std::wstring& text, const std::wstring& prefix)
        {
            return prefix.size() <= text.size() && equalsInsensitive(text.substr(0, prefix.size()), prefix);
        }

        bool endsWithSlash(const std::wstring& text)
        {
            return !text.empty() && (text.back() == L'\\' || text.back() == L'/');
        }

        // makeAbsolutePath normalizes relative DOS paths while preserving NT device paths.
        std::wstring makeAbsolutePath(const std::wstring& rawPath)
        {
            const std::wstring kNormalizedInput = normalizeNativePath(rawPath);
            if (kNormalizedInput.empty() || startsWithInsensitive(kNormalizedInput, L"\\Device\\"))
            {
                return kNormalizedInput;
            }
            const DWORD kRequiredChars = ::GetFullPathNameW(kNormalizedInput.c_str(), 0, nullptr, nullptr);
            if (kRequiredChars == 0)
            {
                return kNormalizedInput;
            }
            std::vector<wchar_t> buffer(static_cast<std::size_t>(kRequiredChars) + 1U, L'\0');
            const DWORD kWrittenChars = ::GetFullPathNameW(kNormalizedInput.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
            return (kWrittenChars > 0 && kWrittenChars < buffer.size())
                ? normalizeNativePath(std::wstring(buffer.data(), kWrittenChars))
                : kNormalizedInput;
        }

        bool isDirectoryPath(const std::wstring& pathText)
        {
            const DWORD kAttributes = ::GetFileAttributesW(pathText.c_str());
            if (kAttributes != INVALID_FILE_ATTRIBUTES)
            {
                return (kAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            }
            return endsWithSlash(pathText);
        }

        std::wstring joinDiagnostic(const std::vector<std::wstring>& itemList)
        {
            std::wstring output;
            for (const std::wstring& item : itemList)
            {
                if (trimWideCopy(item).empty()) { continue; }
                if (!output.empty()) { output += L" | "; }
                output += item;
            }
            return output;
        }

        std::wstring formatNtStatusHex(const NTSTATUS statusValue)
        {
            std::wostringstream stream;
            stream << L"0x" << std::uppercase << std::hex << static_cast<std::uint32_t>(statusValue);
            return stream.str();
        }

        std::wstring buildHexPreview(const std::uint8_t* data, const std::size_t dataSize, const std::size_t maxBytes)
        {
            if (data == nullptr || dataSize == 0)
            {
                return L"<empty>";
            }

            const std::size_t kPreviewBytes = std::min(dataSize, maxBytes);
            std::wostringstream stream;
            stream << std::uppercase << std::hex;
            for (std::size_t index = 0; index < kPreviewBytes; ++index)
            {
                if (index != 0)
                {
                    stream << L' ';
                }
                stream << std::setw(2) << std::setfill(L'0') << static_cast<unsigned int>(data[index]);
            }
            if (kPreviewBytes < dataSize)
            {
                stream << L" ...";
            }
            return stream.str();
        }

        std::wstring extractWideStringFromBuffer(
            const std::vector<std::uint8_t>& buffer,
            const std::size_t byteOffset,
            const std::size_t byteLength)
        {
            if (byteOffset > buffer.size() || byteLength == 0 || (byteOffset + byteLength) > buffer.size())
            {
                return {};
            }

            const std::size_t kWcharCount = byteLength / sizeof(wchar_t);
            if (kWcharCount == 0)
            {
                return {};
            }

            std::wstring text;
            text.resize(kWcharCount);
            std::memcpy(text.data(), buffer.data() + byteOffset, kWcharCount * sizeof(wchar_t));
            return trimWideCopy(text);
        }

        std::wstring normalizeReparseNativePath(std::wstring text)
        {
            text = normalizeNativePath(text);
            if (startsWithInsensitive(text, L"\\??\\UNC\\"))
            {
                return L"\\\\" + text.substr(8);
            }
            if (startsWithInsensitive(text, L"\\??\\Volume{"))
            {
                return L"\\\\?\\" + text.substr(4);
            }
            if (startsWithInsensitive(text, L"\\??\\"))
            {
                return text.substr(4);
            }
            if (startsWithInsensitive(text, L"\\Device\\Mup\\"))
            {
                return L"\\\\" + text.substr(12);
            }
            return text;
        }

        bool isMicrosoftReparseTagValue(const std::uint32_t tag)
        {
            return (tag & kReparseTagMicrosoftFlag) != 0U;
        }

        bool isNameSurrogateReparseTagValue(const std::uint32_t tag)
        {
            return (tag & kReparseTagNameSurrogateFlag) != 0U;
        }

        bool looksLikeAbsoluteWin32Path(const std::wstring& pathText)
        {
            const std::wstring kNormalizedText = normalizeNativePath(pathText);
            return kNormalizedText.rfind(L"\\\\", 0) == 0
                || kNormalizedText.rfind(L"\\", 0) == 0
                || (kNormalizedText.size() >= 3 && kNormalizedText[1] == L':' && kNormalizedText[2] == L'\\');
        }

        std::wstring resolveRelativeTargetPath(
            const std::wstring& linkPath,
            const std::wstring& targetPath)
        {
            const std::wstring kNormalizedTarget = normalizeNativePath(targetPath);
            if (kNormalizedTarget.empty() || looksLikeAbsoluteWin32Path(kNormalizedTarget))
            {
                return kNormalizedTarget;
            }

            const std::wstring kNormalizedLink = normalizeNativePath(linkPath);
            const std::size_t kSlashPos = kNormalizedLink.find_last_of(L'\\');
            if (kSlashPos == std::wstring::npos)
            {
                return kNormalizedTarget;
            }

            const std::wstring kParentPath = kNormalizedLink.substr(0, kSlashPos);
            const std::wstring kCombinedPath = kParentPath + L"\\" + kNormalizedTarget;
            const DWORD kRequiredChars = ::GetFullPathNameW(kCombinedPath.c_str(), 0, nullptr, nullptr);
            if (kRequiredChars == 0)
            {
                return normalizeNativePath(kCombinedPath);
            }

            std::vector<wchar_t> buffer(static_cast<std::size_t>(kRequiredChars) + 1U, L'\0');
            const DWORD kWrittenChars = ::GetFullPathNameW(
                kCombinedPath.c_str(),
                static_cast<DWORD>(buffer.size()),
                buffer.data(),
                nullptr);
            return (kWrittenChars > 0 && kWrittenChars < buffer.size())
                ? normalizeNativePath(std::wstring(buffer.data(), kWrittenChars))
                : normalizeNativePath(kCombinedPath);
        }

        std::wstring tagNameFromReparseTag(const std::uint32_t tag)
        {
            switch (tag)
            {
            case IO_REPARSE_TAG_SYMLINK:
                return L"IO_REPARSE_TAG_SYMLINK";
            case IO_REPARSE_TAG_MOUNT_POINT:
                return L"IO_REPARSE_TAG_MOUNT_POINT";
            case kReparseTagAppExecLink:
                return L"IO_REPARSE_TAG_APPEXECLINK";
            default:
                return L"IO_REPARSE_TAG_" + std::to_wstring(tag);
            }
        }

        std::wstring kindNameFromReparseTag(
            const std::uint32_t tag,
            const std::wstring& substituteName,
            const std::wstring& printName)
        {
            if (tag == IO_REPARSE_TAG_SYMLINK)
            {
                return L"SYMLINK";
            }
            if (tag == IO_REPARSE_TAG_MOUNT_POINT)
            {
                const std::wstring kNormalizedTarget = normalizeReparseNativePath(
                    !substituteName.empty() ? substituteName : printName);
                if (startsWithInsensitive(kNormalizedTarget, L"\\\\?\\Volume{")
                    || startsWithInsensitive(kNormalizedTarget, L"\\\\.\\Volume{")
                    || startsWithInsensitive(kNormalizedTarget, L"\\Device\\HarddiskVolume")
                    || startsWithInsensitive(kNormalizedTarget, L"\\Device\\Mup\\"))
                {
                    return L"MOUNT_POINT";
                }
                return L"JUNCTION";
            }
            if (tag == kReparseTagAppExecLink)
            {
                return L"APPEXECLINK";
            }
            return L"UNKNOWN_REPARSE";
        }

        void populateReparseTargetFields(ks::file::ReparsePointQueryResult& result)
        {
            const std::wstring kNormalizedSubstitute = normalizeReparseNativePath(result.substituteName);
            const std::wstring kNormalizedPrint = normalizeReparseNativePath(result.printName);
            if (!kNormalizedPrint.empty())
            {
                result.resolvedTargetPath = kNormalizedPrint;
            }
            else if (!kNormalizedSubstitute.empty())
            {
                result.resolvedTargetPath = kNormalizedSubstitute;
            }

            if (result.tag == IO_REPARSE_TAG_SYMLINK)
            {
                if (result.substituteName.empty() && !result.printName.empty())
                {
                    result.substituteName = result.printName;
                }
            }
        }

        std::wstring buildPathRuleText(const std::wstring& sourceText, const bool directoryRule)
        {
            return directoryRule ? sourceText + L"-目录前缀" : sourceText + L"-精确路径";
        }

        std::uint64_t buildHandleKey(const std::uint32_t processId, const std::uint64_t handleValue)
        {
            return (static_cast<std::uint64_t>(processId) << 32) ^ handleValue;
        }
        std::wstring processNameFallback(const std::uint32_t processId)
        {
            return L"PID_" + std::to_wstring(processId);
        }

        // collectProcessNameMap builds a reusable PID -> process name cache through Toolhelp.
        std::unordered_map<std::uint32_t, std::wstring> collectProcessNameMap(
            const CancellationCallback& cancellationCallback = {})
        {
            std::unordered_map<std::uint32_t, std::wstring> processNameMap;
            UniqueHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!snapshotHandle.valid())
            {
                return processNameMap;
            }

            PROCESSENTRY32W processEntry{};
            processEntry.dwSize = sizeof(processEntry);
            BOOL hasItem = ::Process32FirstW(snapshotHandle.get(), &processEntry);
            while (hasItem != FALSE)
            {
                if (isCancellationRequested(cancellationCallback))
                {
                    break;
                }
                processNameMap[processEntry.th32ProcessID] = processEntry.szExeFile;
                hasItem = ::Process32NextW(snapshotHandle.get(), &processEntry);
            }
            return processNameMap;
        }

        std::wstring processNameOf(
            const std::unordered_map<std::uint32_t, std::wstring>& processNameMap,
            const std::uint32_t processId)
        {
            const auto kFoundIt = processNameMap.find(processId);
            return (kFoundIt != processNameMap.end() && !kFoundIt->second.empty())
                ? kFoundIt->second
                : processNameFallback(processId);
        }

        // queryProcessImagePathCached reuses ks::process for process paths while keeping this
        // module free of any UI-framework string or widget dependencies.
        std::wstring queryProcessImagePathCached(
            const std::uint32_t processId,
            std::unordered_map<std::uint32_t, std::wstring>& cacheMap)
        {
            const auto kFoundIt = cacheMap.find(processId);
            if (kFoundIt != cacheMap.end())
            {
                return kFoundIt->second;
            }
            const std::wstring kImagePath = ks::str::utf8ToUtf16(ks::process::queryProcessPathByPid(processId));
            cacheMap.insert_or_assign(processId, kImagePath);
            return kImagePath;
        }

        // queryProcessCreationTimeFromHandle converts FILETIME to a stable 64-bit process identity for comparison.
        bool queryProcessCreationTimeFromHandle(HANDLE processHandle, std::uint64_t& creationTimeOut)
        {
            creationTimeOut = 0U;
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) == FALSE)
            {
                return false;
            }

            ULARGE_INTEGER combinedTime{};
            combinedTime.LowPart = creationTime.dwLowDateTime;
            combinedTime.HighPart = creationTime.dwHighDateTime;
            creationTimeOut = combinedTime.QuadPart;
            return creationTimeOut != 0U;
        }

        // queryProcessCreationTimeCached avoids repeatedly opening the process for multiple handle/module records of the same PID.
        std::uint64_t queryProcessCreationTimeCached(
            const std::uint32_t processId,
            std::unordered_map<std::uint32_t, std::uint64_t>& cacheMap)
        {
            const auto kFoundIt = cacheMap.find(processId);
            if (kFoundIt != cacheMap.end())
            {
                return kFoundIt->second;
            }

            std::uint64_t creationTime = 0U;
            UniqueHandle processHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
            if (processHandle.valid())
            {
                (void)queryProcessCreationTimeFromHandle(processHandle.get(), creationTime);
            }
            cacheMap.insert_or_assign(processId, creationTime);
            return creationTime;
        }

        // openProcessHandleForDuplicate caches remote process handles for one snapshot pass.
        HANDLE openProcessHandleForDuplicate(
            const std::uint32_t processId,
            std::unordered_map<std::uint32_t, UniqueHandle>& processHandleCache,
            std::unordered_set<std::uint32_t>& failedProcessOpenSet)
        {
            const auto kCacheIt = processHandleCache.find(processId);
            if (kCacheIt != processHandleCache.end())
            {
                return kCacheIt->second.get();
            }
            if (failedProcessOpenSet.find(processId) != failedProcessOpenSet.end())
            {
                return nullptr;
            }

            UniqueHandle processHandle(::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
            if (!processHandle.valid())
            {
                processHandle.reset(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId));
            }
            if (!processHandle.valid())
            {
                failedProcessOpenSet.insert(processId);
                return nullptr;
            }

            HANDLE rawHandle = processHandle.get();
            processHandleCache.emplace(processId, std::move(processHandle));
            return rawHandle;
        }

        // openTargetPathHandle opens the first scan target only to discover the runtime File TypeIndex.
        bool openTargetPathHandle(const TargetPathPattern& pattern, UniqueHandle& handleOut)
        {
            handleOut.reset(nullptr);
            const DWORD kFlags = pattern.directoryMode ? FILE_FLAG_BACKUP_SEMANTICS : 0;
            HANDLE rawHandle = ::CreateFileW(
                pattern.displayPath.c_str(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                kFlags,
                nullptr);
            if (rawHandle == INVALID_HANDLE_VALUE || rawHandle == nullptr)
            {
                return false;
            }
            handleOut.reset(rawHandle);
            return true;
        }

        bool resolveFileTypeIndex(
            const HANDLE localTargetHandle,
            const std::vector<RawSystemHandle>& rawRecords,
            std::uint16_t& fileTypeIndexOut)
        {
            fileTypeIndexOut = 0;
            if (localTargetHandle == nullptr || localTargetHandle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            const DWORD kCurrentProcessId = ::GetCurrentProcessId();
            const ULONG_PTR kLocalHandleValue = reinterpret_cast<ULONG_PTR>(localTargetHandle);
            for (const RawSystemHandle& row : rawRecords)
            {
                if (row.processId == kCurrentProcessId && row.handleValue == static_cast<std::uint64_t>(kLocalHandleValue))
                {
                    fileTypeIndexOut = row.typeIndex;
                    return fileTypeIndexOut != 0;
                }
            }
            return false;
        }

        // shouldAttemptNameQuery mirrors the existing HandleDock object-name budget policy.
        bool shouldAttemptNameQuery(const std::wstring& typeNameText)
        {
            const std::wstring kNormalizedType = toLowerWideCopy(trimWideCopy(typeNameText));
            if (kNormalizedType.empty())
            {
                return false;
            }

            static const std::array<const wchar_t*, 28> kAllowTypeKeyword{
                L"file", L"directory", L"symboliclink", L"key", L"event", L"semaphore", L"mutant",
                L"timer", L"section", L"desktop", L"windowstation", L"port", L"alpc", L"job",
                L"token", L"process", L"thread", L"device", L"driver", L"wmi", L"iocompletion",
                L"filterconnectionport", L"waitcompletionpacket", L"session", L"keyedevent", L"eventpair",
                L"iocompletionreserve", L"partition"
            };
            for (const wchar_t* keywordText : kAllowTypeKeyword)
            {
                if (kNormalizedType.find(keywordText) != std::wstring::npos)
                {
                    return true;
                }
            }
            return false;
        }

        std::wstring resolveTypeNameFromCache(
            const std::uint16_t typeIndex,
            const std::unordered_map<std::uint16_t, std::string>& typeNameCache)
        {
            const auto kTypeIt = typeNameCache.find(typeIndex);
            if (kTypeIt != typeNameCache.end() && !kTypeIt->second.empty())
            {
                return ks::str::utf8ToUtf16(kTypeIt->second);
            }
            return L"Type#" + std::to_wstring(typeIndex);
        }

        bool queryFileObjectDisplayName(HANDLE objectHandle, std::wstring& textOut)
        {
            return queryFinalDosPathByHandle(objectHandle, textOut);
        }

        bool queryProcessObjectDisplayName(HANDLE objectHandle, std::wstring& textOut)
        {
            textOut.clear();
            const DWORD kTargetProcessId = ::GetProcessId(objectHandle);
            if (kTargetProcessId == 0)
            {
                return false;
            }

            DWORD bufferChars = 2048;
            std::vector<wchar_t> pathBuffer(static_cast<std::size_t>(bufferChars), L'\0');
            if (::QueryFullProcessImageNameW(objectHandle, 0, pathBuffer.data(), &bufferChars) != FALSE && bufferChars > 0)
            {
                textOut = L"PID " + std::to_wstring(kTargetProcessId) + L" | " +
                    trimWideCopy(std::wstring(pathBuffer.data(), bufferChars));
                return true;
            }
            textOut = L"PID " + std::to_wstring(kTargetProcessId);
            return true;
        }

        bool queryThreadObjectDisplayName(HANDLE objectHandle, std::wstring& textOut)
        {
            textOut.clear();
            const DWORD kTargetThreadId = ::GetThreadId(objectHandle);
            if (kTargetThreadId == 0)
            {
                return false;
            }
            const DWORD kOwnerProcessId = ::GetProcessIdOfThread(objectHandle);
            textOut = (kOwnerProcessId != 0)
                ? L"PID " + std::to_wstring(kOwnerProcessId) + L" / TID " + std::to_wstring(kTargetThreadId)
                : L"TID " + std::to_wstring(kTargetThreadId);
            return true;
        }

        bool queryTokenObjectDisplayName(HANDLE objectHandle, std::wstring& textOut)
        {
            textOut.clear();
            DWORD requiredLength = 0;
            ::GetTokenInformation(objectHandle, TokenUser, nullptr, 0, &requiredLength);
            if (requiredLength == 0)
            {
                return false;
            }

            std::vector<std::uint8_t> tokenBuffer(static_cast<std::size_t>(requiredLength), 0);
            if (::GetTokenInformation(objectHandle, TokenUser, tokenBuffer.data(), requiredLength, &requiredLength) == FALSE)
            {
                return false;
            }

            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
            if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
            {
                return false;
            }

            wchar_t accountName[256] = {};
            wchar_t domainName[256] = {};
            DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
            DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
            SID_NAME_USE sidType = SidTypeUnknown;
            if (::LookupAccountSidW(nullptr, tokenUser->User.Sid, accountName, &accountNameLength, domainName, &domainNameLength, &sidType) != FALSE)
            {
                textOut = std::wstring(domainName) + L"\\" + accountName;
                return true;
            }

            LPWSTR sidText = nullptr;
            if (::ConvertSidToStringSidW(tokenUser->User.Sid, &sidText) != FALSE && sidText != nullptr)
            {
                textOut = sidText;
                ::LocalFree(sidText);
                return true;
            }
            return false;
        }

        bool queryTypeSpecificObjectName(const std::wstring& typeNameText, HANDLE objectHandle, std::wstring& textOut)
        {
            const std::wstring kNormalizedType = toLowerWideCopy(trimWideCopy(typeNameText));
            if (kNormalizedType == L"file" || kNormalizedType == L"directory")
            {
                return queryFileObjectDisplayName(objectHandle, textOut);
            }
            if (kNormalizedType == L"process")
            {
                return queryProcessObjectDisplayName(objectHandle, textOut);
            }
            if (kNormalizedType == L"thread")
            {
                return queryThreadObjectDisplayName(objectHandle, textOut);
            }
            if (kNormalizedType == L"token")
            {
                return queryTokenObjectDisplayName(objectHandle, textOut);
            }
            textOut.clear();
            return false;
        }
    }

    bool NtApiSet::ready() const
    {
        return ntdllModule != nullptr && querySystemInformation != nullptr && queryObject != nullptr;
    }

    std::wstring normalizeNativePath(const std::wstring& pathText)
    {
        std::wstring pathValue = trimWideCopy(pathText);
        std::replace(pathValue.begin(), pathValue.end(), L'/', L'\\');
        if (startsWithInsensitive(pathValue, L"\\\\?\\UNC\\"))
        {
            pathValue = L"\\\\" + pathValue.substr(8);
        }
        else if (startsWithInsensitive(pathValue, L"\\\\?\\"))
        {
            pathValue = pathValue.substr(4);
        }
        return trimWideCopy(pathValue);
    }

    std::wstring normalizePathForCompare(const std::wstring& pathText)
    {
        std::wstring pathValue = normalizeNativePath(pathText);
        while (pathValue.size() > 3 && pathValue.back() == L'\\')
        {
            pathValue.pop_back();
        }
        return toLowerWideCopy(pathValue);
    }

    bool buildNtPathEquivalent(const std::wstring& absolutePath, std::wstring& ntPathOut)
    {
        ntPathOut.clear();
        const std::wstring kPathValue = normalizeNativePath(absolutePath);
        if (kPathValue.size() >= 2 && kPathValue[1] == L':')
        {
            const std::wstring kDriveText = kPathValue.substr(0, 2);
            wchar_t deviceBuffer[4096] = {};
            const DWORD kQueryChars = ::QueryDosDeviceW(kDriveText.c_str(), deviceBuffer, static_cast<DWORD>(std::size(deviceBuffer)));
            if (kQueryChars == 0 || deviceBuffer[0] == L'\0')
            {
                return false;
            }
            ntPathOut = trimWideCopy(std::wstring(deviceBuffer)) + kPathValue.substr(2);
            return !trimWideCopy(ntPathOut).empty();
        }
        if (kPathValue.rfind(L"\\\\", 0) == 0)
        {
            ntPathOut = L"\\Device\\Mup" + kPathValue.substr(1);
            return !trimWideCopy(ntPathOut).empty();
        }
        return false;
    }

    std::vector<TargetPathPattern> buildTargetPathPatterns(const std::vector<std::wstring>& absolutePaths)
    {
        std::vector<TargetPathPattern> patternList;
        patternList.reserve(absolutePaths.size() * 2U);
        std::set<std::wstring> normalizedSet;
        for (const std::wstring& rawPath : absolutePaths)
        {
            if (trimWideCopy(rawPath).empty())
            {
                continue;
            }

            const std::wstring kAbsolutePath = makeAbsolutePath(rawPath);
            const std::wstring kNormalizedPath = normalizePathForCompare(kAbsolutePath);
            if (kNormalizedPath.empty() || normalizedSet.find(kNormalizedPath) != normalizedSet.end())
            {
                continue;
            }
            normalizedSet.insert(kNormalizedPath);

            const bool kDirectoryMode = isDirectoryPath(kAbsolutePath);
            TargetPathPattern pattern{};
            pattern.displayPath = kAbsolutePath;
            pattern.normalizedPath = kNormalizedPath;
            pattern.directoryMode = kDirectoryMode;
            patternList.push_back(std::move(pattern));

            std::wstring ntPathText;
            if (buildNtPathEquivalent(kAbsolutePath, ntPathText))
            {
                const std::wstring kNormalizedNtPath = normalizePathForCompare(ntPathText);
                if (!kNormalizedNtPath.empty() && normalizedSet.find(kNormalizedNtPath) == normalizedSet.end())
                {
                    normalizedSet.insert(kNormalizedNtPath);
                    TargetPathPattern ntPattern{};
                    ntPattern.displayPath = kAbsolutePath;
                    ntPattern.normalizedPath = kNormalizedNtPath;
                    ntPattern.directoryMode = kDirectoryMode;
                    patternList.push_back(std::move(ntPattern));
                }
            }
        }
        return patternList;
    }

    bool matchTargetPath(
        const std::wstring& normalizedCandidatePath,
        const std::vector<TargetPathPattern>& patternList,
        std::wstring& matchedTargetPathOut,
        bool& matchedByDirectoryRuleOut)
    {
        matchedTargetPathOut.clear();
        matchedByDirectoryRuleOut = false;
        if (trimWideCopy(normalizedCandidatePath).empty())
        {
            return false;
        }

        for (const TargetPathPattern& pattern : patternList)
        {
            if (!pattern.directoryMode)
            {
                if (normalizedCandidatePath == pattern.normalizedPath)
                {
                    matchedTargetPathOut = pattern.displayPath;
                    matchedByDirectoryRuleOut = false;
                    return true;
                }
                continue;
            }
            if (normalizedCandidatePath == pattern.normalizedPath || normalizedCandidatePath.rfind(pattern.normalizedPath + L"\\", 0) == 0)
            {
                matchedTargetPathOut = pattern.displayPath;
                matchedByDirectoryRuleOut = true;
                return true;
            }
        }
        return false;
    }

    NtApiSet queryNtApis()
    {
        NtApiSet apiSet{};
        apiSet.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiSet.ntdllModule == nullptr)
        {
            apiSet.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiSet.ntdllModule == nullptr)
        {
            return apiSet;
        }
        apiSet.querySystemInformation = reinterpret_cast<NtApiSet::NtQuerySystemInformationFn>(
            ::GetProcAddress(apiSet.ntdllModule, "NtQuerySystemInformation"));
        apiSet.queryObject = reinterpret_cast<NtApiSet::NtQueryObjectFn>(
            ::GetProcAddress(apiSet.ntdllModule, "NtQueryObject"));
        return apiSet;
    }

    bool querySystemHandles(
        const NtApiSet& apiSet,
        std::vector<RawSystemHandle>& recordsOut,
        std::wstring& diagnosticTextOut,
        const CancellationCallback& cancellationCallback)
    {
        recordsOut.clear();
        diagnosticTextOut.clear();
        if (!apiSet.ready())
        {
            diagnosticTextOut = L"Nt API 不可用，无法枚举系统句柄。";
            return false;
        }

        ULONG bufferSize = 1024U * 1024U;
        for (int attemptIndex = 0; attemptIndex < 10; ++attemptIndex)
        {
            if (isCancellationRequested(cancellationCallback))
            {
                diagnosticTextOut = L"扫描已取消。";
                return false;
            }
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(bufferSize), 0);
            ULONG returnLength = 0;
            const NTSTATUS kStatus = apiSet.querySystemInformation(kSystemExtendedHandleInformationClass, buffer.data(), bufferSize, &returnLength);
            const bool kNeedGrow = kStatus == kStatusInfoLengthMismatch || kStatus == kStatusBufferOverflow || kStatus == kStatusBufferTooSmall;
            if (kNeedGrow)
            {
                const ULONG kRecommendedSize = (returnLength > bufferSize) ? returnLength + (256U * 1024U) : bufferSize * 2U;
                bufferSize = std::max<ULONG>(kRecommendedSize, bufferSize + (256U * 1024U));
                continue;
            }
            if (kStatus < 0)
            {
                diagnosticTextOut = L"NtQuerySystemInformation 失败，status=" + formatNtStatusHex(kStatus);
                return false;
            }
            if (buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_EX_NATIVE))
            {
                diagnosticTextOut = L"句柄快照缓冲区尺寸异常（过小）。";
                return false;
            }

            const auto* handleHeader = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX_NATIVE*>(buffer.data());
            const std::size_t kDeclaredCount = static_cast<std::size_t>(handleHeader->numberOfHandles);
            const std::size_t kHeaderBytes = offsetof(SYSTEM_HANDLE_INFORMATION_EX_NATIVE, handles);
            const std::size_t kAvailableBytes = buffer.size() > kHeaderBytes ? buffer.size() - kHeaderBytes : 0U;
            const std::size_t kSafeRecordCount = std::min(kDeclaredCount, kAvailableBytes / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_NATIVE));
            recordsOut.reserve(kSafeRecordCount);
            for (std::size_t index = 0; index < kSafeRecordCount; ++index)
            {
                if ((index % 1024U) == 0U && isCancellationRequested(cancellationCallback))
                {
                    diagnosticTextOut = L"扫描已取消。";
                    recordsOut.clear();
                    return false;
                }
                const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_NATIVE& source = handleHeader->handles[index];
                RawSystemHandle row{};
                row.processId = static_cast<std::uint32_t>(source.uniqueProcessId);
                row.handleValue = static_cast<std::uint64_t>(source.handleValue);
                row.typeIndex = static_cast<std::uint16_t>(source.objectTypeIndex);
                row.objectAddress = reinterpret_cast<std::uint64_t>(source.objectAddress);
                row.grantedAccess = static_cast<std::uint32_t>(source.grantedAccess);
                row.attributes = static_cast<std::uint32_t>(source.handleAttributes);
                recordsOut.push_back(row);
            }
            if (kSafeRecordCount < kDeclaredCount)
            {
                diagnosticTextOut = L"句柄记录超出缓冲区，结果已截断。";
            }
            return true;
        }
        diagnosticTextOut = L"句柄快照缓冲区扩容次数已达上限。";
        return false;
    }

    bool queryNtObjectText(const NtApiSet& apiSet, HANDLE objectHandle, const ULONG informationClass, std::wstring& textOut)
    {
        textOut.clear();
        if (!apiSet.ready() || objectHandle == nullptr || objectHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        ULONG bufferSize = 1024;
        for (int attemptIndex = 0; attemptIndex < 8; ++attemptIndex)
        {
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(bufferSize), 0);
            ULONG returnLength = 0;
            const NTSTATUS kStatus = apiSet.queryObject(objectHandle, informationClass, buffer.data(), bufferSize, &returnLength);
            const bool kNeedGrow = kStatus == kStatusInfoLengthMismatch || kStatus == kStatusBufferOverflow || kStatus == kStatusBufferTooSmall;
            if (kNeedGrow)
            {
                const ULONG kRecommendedSize = (returnLength > bufferSize) ? returnLength + 256U : bufferSize * 2U;
                bufferSize = std::max<ULONG>(kRecommendedSize, bufferSize + 256U);
                continue;
            }
            if (kStatus < 0)
            {
                return false;
            }

            const auto* unicodeValue = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
            if (unicodeValue == nullptr || unicodeValue->Buffer == nullptr || unicodeValue->Length == 0)
            {
                textOut.clear();
                return true;
            }
            const std::uintptr_t kBufferBegin = reinterpret_cast<std::uintptr_t>(buffer.data());
            const std::uintptr_t kBufferEnd = kBufferBegin + buffer.size();
            const std::uintptr_t kTextBegin = reinterpret_cast<std::uintptr_t>(unicodeValue->Buffer);
            const std::size_t kTextLength = unicodeValue->Length;
            if ((unicodeValue->Length % sizeof(wchar_t)) != 0 ||
                kTextBegin < kBufferBegin || kTextBegin > kBufferEnd || kTextLength > kBufferEnd - kTextBegin)
            {
                return false;
            }
            textOut.assign(unicodeValue->Buffer, unicodeValue->Length / sizeof(wchar_t));
            return true;
        }
        return false;
    }

    ReparsePointQueryResult queryReparsePointInfo(
        const std::wstring& absolutePath,
        const bool directoryHint)
    {
        ReparsePointQueryResult result{};
        const std::wstring kNormalizedPath = makeAbsolutePath(absolutePath);
        if (trimWideCopy(kNormalizedPath).empty())
        {
            result.errorText = L"路径为空。";
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        DWORD openFlags = FILE_FLAG_OPEN_REPARSE_POINT;
        if (directoryHint)
        {
            openFlags |= FILE_FLAG_BACKUP_SEMANTICS;
        }

        HANDLE fileHandle = ::CreateFileW(
            kNormalizedPath.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            openFlags,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE || fileHandle == nullptr)
        {
            result.errorText = L"CreateFileW 失败。";
            result.win32Error = ::GetLastError();
            return result;
        }

        result.pathOpened = true;
        std::vector<std::uint8_t> buffer(kMaxReparseBufferBytes, 0);
        DWORD returnedBytes = 0;
        const BOOL kIoOk = ::DeviceIoControl(
            fileHandle,
            FSCTL_GET_REPARSE_POINT,
            nullptr,
            0,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returnedBytes,
            nullptr);
        if (kIoOk == FALSE)
        {
            result.win32Error = ::GetLastError();
            result.errorText = L"FSCTL_GET_REPARSE_POINT 失败。";
            if (result.win32Error == ERROR_NOT_A_REPARSE_POINT)
            {
                result.isReparsePoint = false;
            }
            ::CloseHandle(fileHandle);
            return result;
        }

        result.querySucceeded = true;
        result.isReparsePoint = true;
        if (returnedBytes < 8U)
        {
            result.errorText = L"重解析缓冲区尺寸异常。";
            ::CloseHandle(fileHandle);
            return result;
        }

        std::uint32_t tagValue = 0;
        std::memcpy(&tagValue, buffer.data(), sizeof(tagValue));
        result.tag = tagValue;
        result.isMicrosoftTag = isMicrosoftReparseTagValue(tagValue);
        result.isNameSurrogate = isNameSurrogateReparseTagValue(tagValue);
        result.tagName = tagNameFromReparseTag(tagValue);
        result.rawHexPreview = buildHexPreview(buffer.data(), returnedBytes, 64U);

        if (tagValue == IO_REPARSE_TAG_SYMLINK)
        {
            if (returnedBytes < 20U)
            {
                result.errorText = L"符号链接重解析缓冲区尺寸异常。";
            }
            else
            {
                const auto kReadU16 = [&buffer](const std::size_t offset) -> USHORT
                {
                    USHORT value = 0;
                    std::memcpy(&value, buffer.data() + offset, sizeof(value));
                    return value;
                };
                const auto kReadU32 = [&buffer](const std::size_t offset) -> std::uint32_t
                {
                    std::uint32_t value = 0;
                    std::memcpy(&value, buffer.data() + offset, sizeof(value));
                    return value;
                };

                const USHORT kSubstituteOffset = kReadU16(8U);
                const USHORT kSubstituteLength = kReadU16(10U);
                const USHORT kPrintOffset = kReadU16(12U);
                const USHORT kPrintLength = kReadU16(14U);
                const std::uint32_t kFlags = kReadU32(16U);
                result.isRelative = (kFlags & kSymbolicLinkRelativeFlag) != 0U;
                result.substituteName = extractWideStringFromBuffer(buffer, 20U + kSubstituteOffset, kSubstituteLength);
                result.printName = extractWideStringFromBuffer(buffer, 20U + kPrintOffset, kPrintLength);
                result.kindName = kindNameFromReparseTag(tagValue, result.substituteName, result.printName);
                populateReparseTargetFields(result);
            }
        }
        else if (tagValue == IO_REPARSE_TAG_MOUNT_POINT)
        {
            if (returnedBytes < 16U)
            {
                result.errorText = L"挂载点重解析缓冲区尺寸异常。";
            }
            else
            {
                const auto kReadU16 = [&buffer](const std::size_t offset) -> USHORT
                {
                    USHORT value = 0;
                    std::memcpy(&value, buffer.data() + offset, sizeof(value));
                    return value;
                };

                const USHORT kSubstituteOffset = kReadU16(8U);
                const USHORT kSubstituteLength = kReadU16(10U);
                const USHORT kPrintOffset = kReadU16(12U);
                const USHORT kPrintLength = kReadU16(14U);
                result.substituteName = extractWideStringFromBuffer(buffer, 16U + kSubstituteOffset, kSubstituteLength);
                result.printName = extractWideStringFromBuffer(buffer, 16U + kPrintOffset, kPrintLength);
                result.kindName = kindNameFromReparseTag(tagValue, result.substituteName, result.printName);
                populateReparseTargetFields(result);
            }
        }
        else if (tagValue == kReparseTagAppExecLink)
        {
            const std::size_t kPayloadSize = returnedBytes > 8U ? returnedBytes - 8U : 0U;
            result.kindName = kindNameFromReparseTag(tagValue, {}, {});
            result.rawPayloadText = L"APPEXECLINK 原始数据（未结构化解析），长度=" + std::to_wstring(kPayloadSize);
            populateReparseTargetFields(result);
        }
        else
        {
            result.kindName = kindNameFromReparseTag(tagValue, {}, {});
            result.rawPayloadText = L"未知重解析点，原始数据长度=" + std::to_wstring(returnedBytes > 8U ? returnedBytes - 8U : 0U);
            populateReparseTargetFields(result);
        }

        if (result.kindName.empty())
        {
            result.kindName = L"UNKNOWN_REPARSE";
        }
        if (result.isRelative && !trimWideCopy(result.resolvedTargetPath).empty())
        {
            result.resolvedTargetPath = resolveRelativeTargetPath(kNormalizedPath, result.resolvedTargetPath);
        }
        if (result.rawPayloadText.empty())
        {
            result.rawPayloadText = L"RawHex=" + result.rawHexPreview;
        }

        ::CloseHandle(fileHandle);
        return result;
    }
    bool queryObjectBasicInfo(const NtApiSet& apiSet, HANDLE objectHandle, ObjectBasicInfo& basicInfoOut)
    {
        basicInfoOut = ObjectBasicInfo{};
        if (!apiSet.ready() || objectHandle == nullptr || objectHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        OBJECT_BASIC_INFORMATION_NATIVE nativeInfo{};
        const NTSTATUS kStatus = apiSet.queryObject(
            objectHandle,
            kObjectBasicInformationClass,
            &nativeInfo,
            static_cast<ULONG>(sizeof(nativeInfo)),
            nullptr);
        if (kStatus < 0)
        {
            return false;
        }
        basicInfoOut.handleCount = nativeInfo.handleCount;
        basicInfoOut.pointerCount = nativeInfo.pointerCount;
        return true;
    }

    ObjectNameQueryResult resolveObjectNameText(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        const std::wstring& typeNameText)
    {
        ObjectNameQueryResult result{};
        std::wstring ntObjectNameText;
        const bool kNtQueryOk = queryNtObjectText(apiSet, objectHandle, kObjectNameInformationClass, ntObjectNameText);
        if (kNtQueryOk)
        {
            result.available = true;
            result.objectName = trimWideCopy(ntObjectNameText);
            if (!result.objectName.empty())
            {
                return result;
            }
        }

        std::wstring fallbackText;
        if (queryTypeSpecificObjectName(typeNameText, objectHandle, fallbackText))
        {
            result.available = true;
            result.usedFallback = !trimWideCopy(fallbackText).empty();
            result.objectName = trimWideCopy(fallbackText);
            return result;
        }
        if (kNtQueryOk)
        {
            result.objectName.clear();
            return result;
        }
        result.failed = true;
        return result;
    }

    bool duplicateRemoteHandleToLocal(HANDLE sourceProcessHandle, const std::uint64_t handleValue, HANDLE& localHandleOut)
    {
        localHandleOut = nullptr;
        if (sourceProcessHandle == nullptr || sourceProcessHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        HANDLE duplicatedHandle = nullptr;
        const BOOL kDuplicateOk = ::DuplicateHandle(
            sourceProcessHandle,
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleValue)),
            ::GetCurrentProcess(),
            &duplicatedHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);
        if (kDuplicateOk == FALSE || duplicatedHandle == nullptr)
        {
            return false;
        }
        localHandleOut = duplicatedHandle;
        return true;
    }

    bool queryFinalDosPathByHandle(HANDLE objectHandle, std::wstring& pathOut)
    {
        pathOut.clear();
        if (objectHandle == nullptr || objectHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        DWORD bufferChars = 512;
        for (int attemptIndex = 0; attemptIndex < 6; ++attemptIndex)
        {
            std::vector<wchar_t> pathBuffer(static_cast<std::size_t>(bufferChars), L'\0');
            const DWORD kPathLength = ::GetFinalPathNameByHandleW(
                objectHandle,
                pathBuffer.data(),
                bufferChars,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (kPathLength == 0)
            {
                return false;
            }
            if (kPathLength >= bufferChars)
            {
                bufferChars = kPathLength + 1;
                continue;
            }
            pathOut = normalizeNativePath(std::wstring(pathBuffer.data(), kPathLength));
            return !pathOut.empty();
        }
        return false;
    }

    bool openProcessForVerifiedAction(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime,
        const DWORD desiredAccess,
        HANDLE& processHandleOut,
        std::string& detailTextOut)
    {
        processHandleOut = nullptr;
        detailTextOut.clear();
        if (processId == 0U || expectedCreationTime == 0U)
        {
            detailTextOut = "process identity is unavailable; rescan before retrying";
            return false;
        }

        UniqueHandle processHandle(::OpenProcess(
            desiredAccess | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            processId));
        if (!processHandle.valid())
        {
            detailTextOut = "OpenProcess for verified action failed, error=" + std::to_string(::GetLastError());
            return false;
        }

        std::uint64_t actualCreationTime = 0U;
        if (!queryProcessCreationTimeFromHandle(processHandle.get(), actualCreationTime))
        {
            detailTextOut = "GetProcessTimes failed, error=" + std::to_string(::GetLastError());
            return false;
        }
        if (actualCreationTime != expectedCreationTime)
        {
            detailTextOut = "process identity changed (PID was reused); rescan before retrying";
            return false;
        }

        processHandleOut = processHandle.release();
        detailTextOut = "process identity verified";
        return true;
    }

    bool closeRemoteHandle(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const std::uint64_t expectedProcessCreationTime,
        const std::wstring& expectedTargetPath,
        const bool expectedDirectoryMatch,
        std::string& detailTextOut)
    {
        detailTextOut.clear();
        if (processId <= 4U || processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) || handleValue == 0U)
        {
            detailTextOut = "invalid or protected remote handle target";
            return false;
        }
        if (normalizePathForCompare(expectedTargetPath).empty())
        {
            detailTextOut = "expected target path is unavailable; rescan before retrying";
            return false;
        }

        HANDLE rawProcessHandle = nullptr;
        if (!openProcessForVerifiedAction(
                processId,
                expectedProcessCreationTime,
                PROCESS_DUP_HANDLE | kProcessSuspendResumeAccess,
                rawProcessHandle,
                detailTextOut))
        {
            return false;
        }
        UniqueHandle processHandle(rawProcessHandle);

        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        const auto kSuspendProcess = ntdllModule == nullptr
            ? nullptr
            : reinterpret_cast<NtSuspendProcessFn>(::GetProcAddress(ntdllModule, "NtSuspendProcess"));
        const auto kResumeProcess = ntdllModule == nullptr
            ? nullptr
            : reinterpret_cast<NtResumeProcessFn>(::GetProcAddress(ntdllModule, "NtResumeProcess"));
        if (kSuspendProcess == nullptr || kResumeProcess == nullptr)
        {
            detailTextOut = "NtSuspendProcess/NtResumeProcess is unavailable";
            return false;
        }

        const NTSTATUS kSuspendStatus = kSuspendProcess(processHandle.get());
        if (kSuspendStatus < 0)
        {
            std::ostringstream stream;
            stream << "NtSuspendProcess failed, status=0x"
                   << std::hex << std::uppercase << static_cast<std::uint32_t>(kSuspendStatus);
            detailTextOut = stream.str();
            return false;
        }
        const ScopedProcessResume kResumeGuard(processHandle.get(), kResumeProcess);

        HANDLE rawProbeHandle = nullptr;
        if (!duplicateRemoteHandleToLocal(processHandle.get(), handleValue, rawProbeHandle))
        {
            detailTextOut = "DuplicateHandle validation failed, error=" + std::to_string(::GetLastError());
            return false;
        }
        UniqueHandle probeHandle(rawProbeHandle);

        std::wstring currentPath;
        if (!queryFinalDosPathByHandle(probeHandle.get(), currentPath))
        {
            detailTextOut = "current handle is no longer a queryable disk file";
            return false;
        }

        TargetPathPattern expectedPattern{};
        expectedPattern.displayPath = expectedTargetPath;
        expectedPattern.normalizedPath = normalizePathForCompare(expectedTargetPath);
        expectedPattern.directoryMode = expectedDirectoryMatch;
        std::wstring matchedPath;
        bool matchedByDirectoryRule = false;
        if (!matchTargetPath(
                normalizePathForCompare(currentPath),
                std::vector<TargetPathPattern>{ expectedPattern },
                matchedPath,
                matchedByDirectoryRule))
        {
            detailTextOut = "remote handle identity changed; current file no longer matches the scanned target";
            return false;
        }

        HANDLE rawClosedHandle = nullptr;
        const BOOL kCloseOk = ::DuplicateHandle(
            processHandle.get(),
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleValue)),
            ::GetCurrentProcess(),
            &rawClosedHandle,
            0,
            FALSE,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
        UniqueHandle closedHandle(rawClosedHandle);
        if (kCloseOk == FALSE)
        {
            detailTextOut = "DuplicateHandle(DUPLICATE_CLOSE_SOURCE) failed, error=" + std::to_string(::GetLastError());
            return false;
        }

        std::wstring closedPath;
        if (!closedHandle.valid()
            || !queryFinalDosPathByHandle(closedHandle.get(), closedPath)
            || normalizePathForCompare(closedPath) != normalizePathForCompare(currentPath))
        {
            detailTextOut = "closed handle identity changed unexpectedly while the process was suspended";
            return false;
        }

        detailTextOut = "process and file handle identities verified; CloseSource success";
        return true;
    }

    bool closeRemoteHandleByObjectIdentity(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const std::uint64_t expectedProcessCreationTime,
        const std::uint64_t expectedObjectAddress,
        std::string& detailTextOut)
    {
        detailTextOut.clear();
        if (processId <= 4U
            || processId == static_cast<std::uint32_t>(::GetCurrentProcessId())
            || handleValue == 0U
            || expectedObjectAddress == 0U)
        {
            detailTextOut = "invalid, protected, or unverifiable handle identity";
            return false;
        }

        HANDLE rawProcessHandle = nullptr;
        if (!openProcessForVerifiedAction(
                processId,
                expectedProcessCreationTime,
                PROCESS_DUP_HANDLE | kProcessSuspendResumeAccess,
                rawProcessHandle,
                detailTextOut))
        {
            return false;
        }
        UniqueHandle processHandle(rawProcessHandle);

        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        const auto kSuspendProcess = ntdllModule == nullptr
            ? nullptr
            : reinterpret_cast<NtSuspendProcessFn>(::GetProcAddress(ntdllModule, "NtSuspendProcess"));
        const auto kResumeProcess = ntdllModule == nullptr
            ? nullptr
            : reinterpret_cast<NtResumeProcessFn>(::GetProcAddress(ntdllModule, "NtResumeProcess"));
        if (kSuspendProcess == nullptr || kResumeProcess == nullptr)
        {
            detailTextOut = "NtSuspendProcess/NtResumeProcess is unavailable";
            return false;
        }

        const NTSTATUS kSuspendStatus = kSuspendProcess(processHandle.get());
        if (kSuspendStatus < 0)
        {
            std::ostringstream stream;
            stream << "NtSuspendProcess failed, status=0x"
                   << std::hex << std::uppercase << static_cast<std::uint32_t>(kSuspendStatus);
            detailTextOut = stream.str();
            return false;
        }
        const ScopedProcessResume kResumeGuard(processHandle.get(), kResumeProcess);

        const NtApiSet kApiSet = queryNtApis();
        std::vector<RawSystemHandle> currentHandles;
        std::wstring queryDiagnostic;
        if (!kApiSet.ready() || !querySystemHandles(kApiSet, currentHandles, queryDiagnostic))
        {
            detailTextOut = "failed to refresh the handle identity before close";
            if (!queryDiagnostic.empty())
            {
                detailTextOut += ": " + ks::str::utf16ToUtf8(queryDiagnostic);
            }
            return false;
        }

        const auto kCurrentRow = std::find_if(
            currentHandles.begin(),
            currentHandles.end(),
            [processId, handleValue](const RawSystemHandle& row) {
                return row.processId == processId && row.handleValue == handleValue;
            });
        if (kCurrentRow == currentHandles.end())
        {
            detailTextOut = "the remote handle no longer exists; refresh before retrying";
            return false;
        }
        if (kCurrentRow->objectAddress != expectedObjectAddress)
        {
            detailTextOut = "remote handle identity changed (handle value was reused); refresh before retrying";
            return false;
        }

        HANDLE rawClosedHandle = nullptr;
        const BOOL kCloseOk = ::DuplicateHandle(
            processHandle.get(),
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleValue)),
            ::GetCurrentProcess(),
            &rawClosedHandle,
            0,
            FALSE,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
        UniqueHandle closedHandle(rawClosedHandle);
        if (kCloseOk == FALSE || !closedHandle.valid())
        {
            detailTextOut = "DuplicateHandle(DUPLICATE_CLOSE_SOURCE) failed, error=" + std::to_string(::GetLastError());
            return false;
        }

        detailTextOut = "process, handle value, and object address verified; CloseSource success";
        return true;
    }

    HandleSnapshotResult buildHandleSnapshot(const HandleSnapshotOptions& options)
    {
        HandleSnapshotResult result{};
        const auto kBeginTime = std::chrono::steady_clock::now();
        if (options.enumMode == HandleEnumMode::kKernelHandleTable &&
            (!options.hasPidFilter || options.pidFilter == 0U))
        {
            // Input: KernelHandleTable mode supports supplementing R0 views only for a single real process PID.
            // Processing: Do not call ArkDriverClient when pidFilter is null or 0, to avoid
            // sending pid=0 to the driver and generating STATUS_INVALID_PARAMETER log noise.
            // Return: Empty snapshot with explicit diagnostics, allowing the caller to continue using the R3 DuplicateHandle path.
            result.diagnosticText = L"Kernel HandleTable 模式需要先输入非 0 目标 PID。";
            result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
            return result;
        }

        const NtApiSet kApiSet = queryNtApis();
        std::vector<RawSystemHandle> rawRecords;
        std::wstring queryDiagnosticText;
        if (!querySystemHandles(kApiSet, rawRecords, queryDiagnosticText))
        {
            result.diagnosticText = queryDiagnosticText;
            result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
            return result;
        }
        result.totalHandleCount = rawRecords.size();

        const std::unordered_map<std::uint32_t, std::wstring> kProcessNameMap = collectProcessNameMap();
        std::unordered_map<std::uint32_t, std::uint64_t> processCreationTimeCache;
        std::unordered_map<std::uint16_t, std::string> typeNameCache = options.typeNameCacheByIndex;
        for (const auto& pairItem : options.typeNameMapFromObjectTab)
        {
            typeNameCache[pairItem.first] = pairItem.second;
        }

        std::unordered_map<std::uint32_t, UniqueHandle> processHandleCache;
        std::unordered_set<std::uint32_t> failedProcessOpenSet;
        std::size_t typeQueryFailedCount = 0;
        std::unordered_map<std::uint16_t, const RawSystemHandle*> typeRepresentativeMap;
        for (const RawSystemHandle& rawRow : rawRecords)
        {
            if (rawRow.processId == 0 || typeNameCache.find(rawRow.typeIndex) != typeNameCache.end())
            {
                continue;
            }
            if (typeRepresentativeMap.find(rawRow.typeIndex) == typeRepresentativeMap.end())
            {
                typeRepresentativeMap[rawRow.typeIndex] = &rawRow;
            }
        }

        for (const auto& pairItem : typeRepresentativeMap)
        {
            const RawSystemHandle* representativeRow = pairItem.second;
            HANDLE sourceProcessHandle = representativeRow == nullptr ? nullptr : openProcessHandleForDuplicate(
                representativeRow->processId,
                processHandleCache,
                failedProcessOpenSet);
            if (sourceProcessHandle == nullptr)
            {
                ++typeQueryFailedCount;
                continue;
            }

            HANDLE localRawHandle = nullptr;
            if (!duplicateRemoteHandleToLocal(sourceProcessHandle, representativeRow->handleValue, localRawHandle))
            {
                ++typeQueryFailedCount;
                continue;
            }
            UniqueHandle localHandle(localRawHandle);
            std::wstring typeNameText;
            if (!queryNtObjectText(kApiSet, localHandle.get(), kObjectTypeInformationClass, typeNameText))
            {
                ++typeQueryFailedCount;
                continue;
            }
            typeNameText = trimWideCopy(typeNameText);
            if (!typeNameText.empty())
            {
                typeNameCache[pairItem.first] = ks::str::utf16ToUtf8(typeNameText);
            }
        }

        int nameBudgetRemain = std::max(options.nameResolveBudget, 0);
        int basicInfoBudgetRemain = options.basicInfoQueryBudget;
        std::size_t duplicateFailedCount = 0;
        std::size_t basicInfoFailedCount = 0;
        std::size_t basicInfoBudgetSkippedCount = 0;
        std::size_t nameQueryFailedCount = 0;
        std::size_t nameBudgetSkippedCount = 0;
        std::unordered_map<std::uint64_t, CachedObjectSnapshot> objectSnapshotCacheByAddress;
        std::set<std::wstring> typeNameSet;
        result.rows.reserve(rawRecords.size());
        const std::wstring kTypeFilterText = trimWideCopy(options.typeFilterText);
        const bool kHasTypeFilter = !kTypeFilterText.empty() && kTypeFilterText != L"全部类型";

        for (const RawSystemHandle& rawRow : rawRecords)
        {
            if (rawRow.processId == 0)
            {
                continue;
            }

            HandleSnapshotRow row{};
            row.processId = rawRow.processId;
            row.processCreationTime = queryProcessCreationTimeCached(
                rawRow.processId,
                processCreationTimeCache);
            row.processName = processNameOf(kProcessNameMap, rawRow.processId);
            row.handleValue = rawRow.handleValue;
            row.typeIndex = rawRow.typeIndex;
            row.objectAddress = rawRow.objectAddress;
            row.grantedAccess = rawRow.grantedAccess;
            row.attributes = rawRow.attributes;
            row.sourceMode = options.enumMode == HandleEnumMode::kUserSnapshot ? HandleEnumMode::kUserSnapshot : HandleEnumMode::kDuplicateHandle;
            row.decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
            if (options.enumMode == HandleEnumMode::kKernelHandleTable)
            {
                row.diffStatus = HandleDiffStatus::kUserOnly;
            }
            row.typeName = resolveTypeNameFromCache(rawRow.typeIndex, typeNameCache);
            if (options.typeNameMapFromObjectTab.find(rawRow.typeIndex) != options.typeNameMapFromObjectTab.end())
            {
                ++result.objectTypeMappedCount;
            }
            typeNameSet.insert(row.typeName);

            if (rawRow.objectAddress != 0)
            {
                const auto kCachedObjectIt = objectSnapshotCacheByAddress.find(rawRow.objectAddress);
                if (kCachedObjectIt != objectSnapshotCacheByAddress.end())
                {
                    const CachedObjectSnapshot& cachedSnapshot = kCachedObjectIt->second;
                    if (cachedSnapshot.basicInfoAvailable)
                    {
                        row.basicInfoAvailable = true;
                        row.handleCount = cachedSnapshot.handleCount;
                        row.pointerCount = cachedSnapshot.pointerCount;
                    }
                    if (cachedSnapshot.objectNameAvailable)
                    {
                        row.objectNameAvailable = true;
                        row.objectNameFromFallback = cachedSnapshot.objectNameFromFallback;
                        row.objectName = cachedSnapshot.objectName;
                    }
                }
            }

            const bool kPidMatchedForBudget = !options.hasPidFilter || row.processId == options.pidFilter;
            const bool kTypeMatchedForBudget = !kHasTypeFilter || equalsInsensitive(row.typeName, kTypeFilterText);
            const bool kAllowDuplicateQueries = options.enumMode == HandleEnumMode::kDuplicateHandle || options.enumMode == HandleEnumMode::kKernelHandleTable;
            bool shouldQueryBasicInfo = kAllowDuplicateQueries && !row.basicInfoAvailable;
            if (shouldQueryBasicInfo && basicInfoBudgetRemain >= 0)
            {
                if (basicInfoBudgetRemain > 0)
                {
                    --basicInfoBudgetRemain;
                }
                else
                {
                    shouldQueryBasicInfo = false;
                    ++basicInfoBudgetSkippedCount;
                }
            }
            const bool kTypeEligibleForNameResolve = kAllowDuplicateQueries && options.resolveObjectName &&
                kPidMatchedForBudget && kTypeMatchedForBudget && shouldAttemptNameQuery(row.typeName);
            bool shouldQueryObjectName = false;
            if (kTypeEligibleForNameResolve && !row.objectNameAvailable)
            {
                if (nameBudgetRemain > 0)
                {
                    shouldQueryObjectName = true;
                    --nameBudgetRemain;
                }
                else
                {
                    ++nameBudgetSkippedCount;
                }
            }

            if (shouldQueryBasicInfo || shouldQueryObjectName)
            {
                HANDLE sourceProcessHandle = openProcessHandleForDuplicate(rawRow.processId, processHandleCache, failedProcessOpenSet);
                if (sourceProcessHandle != nullptr)
                {
                    HANDLE localRawHandle = nullptr;
                    if (duplicateRemoteHandleToLocal(sourceProcessHandle, rawRow.handleValue, localRawHandle))
                    {
                        UniqueHandle localHandle(localRawHandle);
                        CachedObjectSnapshot* cachedSnapshot = rawRow.objectAddress != 0 ? &objectSnapshotCacheByAddress[rawRow.objectAddress] : nullptr;
                        if (shouldQueryBasicInfo)
                        {
                            ObjectBasicInfo basicInfo{};
                            if (queryObjectBasicInfo(kApiSet, localHandle.get(), basicInfo))
                            {
                                row.basicInfoAvailable = true;
                                row.handleCount = basicInfo.handleCount;
                                row.pointerCount = basicInfo.pointerCount;
                                if (cachedSnapshot != nullptr)
                                {
                                    cachedSnapshot->basicInfoAvailable = true;
                                    cachedSnapshot->handleCount = basicInfo.handleCount;
                                    cachedSnapshot->pointerCount = basicInfo.pointerCount;
                                }
                            }
                            else
                            {
                                ++basicInfoFailedCount;
                            }
                        }
                        if (shouldQueryObjectName)
                        {
                            const ObjectNameQueryResult kNameQueryResult = resolveObjectNameText(kApiSet, localHandle.get(), row.typeName);
                            if (kNameQueryResult.available)
                            {
                                row.objectNameAvailable = true;
                                row.objectNameFailed = false;
                                row.objectNameFromFallback = kNameQueryResult.usedFallback;
                                row.objectName = kNameQueryResult.objectName;
                                if (cachedSnapshot != nullptr)
                                {
                                    cachedSnapshot->objectNameAvailable = true;
                                    cachedSnapshot->objectNameFromFallback = kNameQueryResult.usedFallback;
                                    cachedSnapshot->objectName = kNameQueryResult.objectName;
                                }
                            }
                            else
                            {
                                row.objectNameFailed = kNameQueryResult.failed;
                                if (kNameQueryResult.failed) { ++nameQueryFailedCount; }
                            }
                        }
                    }
                    else
                    {
                        ++duplicateFailedCount;
                        if (shouldQueryBasicInfo) { ++basicInfoFailedCount; }
                        if (shouldQueryObjectName) { row.objectNameFailed = true; ++nameQueryFailedCount; }
                    }
                }
                else
                {
                    ++duplicateFailedCount;
                    if (shouldQueryBasicInfo) { ++basicInfoFailedCount; }
                    if (shouldQueryObjectName) { row.objectNameFailed = true; ++nameQueryFailedCount; }
                }
            }

            if (row.basicInfoAvailable) { ++result.basicInfoResolvedCount; }
            if (row.objectNameAvailable && !trimWideCopy(row.objectName).empty())
            {
                ++result.resolvedNameCount;
                if (row.objectNameFromFallback) { ++result.fallbackNameCount; }
            }
            result.rows.push_back(std::move(row));
        }
        if (options.enumMode == HandleEnumMode::kKernelHandleTable)
        {
            ksword::ark::DriverClient driverClient;
            std::size_t kernelDecodeProblemCount = 0;
            std::size_t kernelMappedTypeCount = 0;
            std::unordered_map<HandleIdentityKey, std::size_t, HandleIdentityKeyHash> rowIndexByKey;
            rowIndexByKey.reserve(result.rows.size());
            for (std::size_t rowIndex = 0; rowIndex < result.rows.size(); ++rowIndex)
            {
                const HandleSnapshotRow& row = result.rows[rowIndex];
                rowIndexByKey[HandleIdentityKey{ row.processId, row.handleValue }] = rowIndex;
            }

            const ksword::ark::HandleEnumResult kKernelResult = driverClient.enumerateProcessHandles(
                options.pidFilter,
                KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL);
            if (!kKernelResult.io.ok)
            {
                queryDiagnosticText = readableArkIoMessage(
                    kKernelResult.io.message,
                    L"R0 HandleTable 枚举失败: ");
            }
            else
            {
                result.kernelHandleCount = kKernelResult.entries.size();
                for (const ksword::ark::HandleEntry& kernelEntry : kKernelResult.entries)
                {
                    const HandleIdentityKey kKey{ kernelEntry.processId, static_cast<std::uint64_t>(kernelEntry.handleValue) };
                    const auto kExistingIt = rowIndexByKey.find(kKey);
                    HandleSnapshotRow* row = nullptr;
                    if (kExistingIt != rowIndexByKey.end())
                    {
                        row = &result.rows[kExistingIt->second];
                        row->diffStatus = HandleDiffStatus::kBoth;
                    }
                    else
                    {
                        HandleSnapshotRow kernelRow{};
                        kernelRow.processId = kernelEntry.processId;
                        kernelRow.processCreationTime = queryProcessCreationTimeCached(
                            kernelEntry.processId,
                            processCreationTimeCache);
                        kernelRow.processName = processNameOf(kProcessNameMap, kernelEntry.processId);
                        kernelRow.handleValue = static_cast<std::uint64_t>(kernelEntry.handleValue);
                        kernelRow.diffStatus = HandleDiffStatus::kKernelOnly;
                        result.rows.push_back(std::move(kernelRow));
                        row = &result.rows.back();
                        rowIndexByKey[kKey] = result.rows.size() - 1U;
                    }

                    row->sourceMode = HandleEnumMode::kKernelHandleTable;
                    row->typeIndex = static_cast<std::uint16_t>(kernelEntry.objectTypeIndex);
                    row->objectAddress = kernelEntry.objectAddress;
                    row->grantedAccess = kernelEntry.grantedAccess;
                    row->attributes = kernelEntry.attributes;
                    row->decodeStatus = kernelEntry.decodeStatus;
                    row->r0FieldFlags = kernelEntry.fieldFlags;
                    row->r0DynDataCapabilityMask = kernelEntry.dynDataCapabilityMask;
                    row->epObjectTableOffset = kernelEntry.epObjectTableOffset;
                    row->htHandleContentionEventOffset = kernelEntry.htHandleContentionEventOffset;
                    row->obDecodeShift = kernelEntry.obDecodeShift;
                    row->obAttributesShift = kernelEntry.obAttributesShift;
                    row->otNameOffset = kernelEntry.otNameOffset;
                    row->otIndexOffset = kernelEntry.otIndexOffset;
                    row->typeName = resolveTypeNameFromCache(row->typeIndex, typeNameCache);
                    typeNameSet.insert(row->typeName);

                    if ((kernelEntry.fieldFlags & KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT) != 0U)
                    {
                        ++kernelMappedTypeCount;
                    }
                    if (kernelEntry.decodeStatus != KSWORD_ARK_HANDLE_DECODE_STATUS_OK)
                    {
                        ++kernelDecodeProblemCount;
                    }
                }

                for (const HandleSnapshotRow& row : result.rows)
                {
                    if (row.diffStatus == HandleDiffStatus::kUserOnly) { ++result.userOnlyCount; }
                    else if (row.diffStatus == HandleDiffStatus::kKernelOnly) { ++result.kernelOnlyCount; }
                    else if (row.diffStatus == HandleDiffStatus::kBoth) { ++result.bothCount; }
                }
                if (kKernelResult.totalCount > kKernelResult.returnedCount)
                {
                    queryDiagnosticText = joinDiagnostic({
                        queryDiagnosticText,
                        L"R0 HandleTable 输出截断 total=" + std::to_wstring(kKernelResult.totalCount) +
                            L" returned=" + std::to_wstring(kKernelResult.returnedCount)
                    });
                }
                if (kernelDecodeProblemCount > 0)
                {
                    queryDiagnosticText = joinDiagnostic({ queryDiagnosticText, L"R0 解码异常:" + std::to_wstring(kernelDecodeProblemCount) });
                }
                if (kernelMappedTypeCount > 0)
                {
                    queryDiagnosticText = joinDiagnostic({ queryDiagnosticText, L"R0 类型索引:" + std::to_wstring(kernelMappedTypeCount) });
                }
            }
        }
        else
        {
            result.userOnlyCount = result.rows.size();
        }

        std::sort(result.rows.begin(), result.rows.end(), [](const HandleSnapshotRow& leftRow, const HandleSnapshotRow& rightRow) {
            if (leftRow.processId != rightRow.processId) { return leftRow.processId < rightRow.processId; }
            if (leftRow.typeIndex != rightRow.typeIndex) { return leftRow.typeIndex < rightRow.typeIndex; }
            return leftRow.handleValue < rightRow.handleValue;
        });

        result.visibleHandleCount = result.rows.size();
        result.availableTypeList.assign(typeNameSet.begin(), typeNameSet.end());
        result.updatedTypeNameCacheByIndex = std::move(typeNameCache);

        std::vector<std::wstring> diagnosticList;
        diagnosticList.push_back(queryDiagnosticText);
        if (typeQueryFailedCount > 0) { diagnosticList.push_back(L"类型解析失败:" + std::to_wstring(typeQueryFailedCount)); }
        if (duplicateFailedCount > 0) { diagnosticList.push_back(L"句柄复制失败:" + std::to_wstring(duplicateFailedCount)); }
        if (basicInfoFailedCount > 0) { diagnosticList.push_back(L"对象计数查询失败:" + std::to_wstring(basicInfoFailedCount)); }
        if (basicInfoBudgetSkippedCount > 0) { diagnosticList.push_back(L"对象计数预算跳过:" + std::to_wstring(basicInfoBudgetSkippedCount)); }
        if (nameQueryFailedCount > 0) { diagnosticList.push_back(L"对象名查询失败:" + std::to_wstring(nameQueryFailedCount)); }
        if (result.fallbackNameCount > 0) { diagnosticList.push_back(L"对象名回退命中:" + std::to_wstring(result.fallbackNameCount)); }
        if (nameBudgetSkippedCount > 0) { diagnosticList.push_back(L"对象名预算跳过:" + std::to_wstring(nameBudgetSkippedCount)); }
        if (options.resolveObjectName && nameBudgetSkippedCount > 0 && options.nameResolveBudget > 0)
        {
            diagnosticList.push_back(L"对象名解析已达到预算上限");
        }
        result.diagnosticText = joinDiagnostic(diagnosticList);
        result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count());
        return result;
    }

    namespace
    {
        // scanKernelHandleTableOccupancy uses the existing R0 ArkDriverClient path and
        // returns only entries that match target file/directory patterns.
        HandleUsageScanResult scanKernelHandleTableOccupancy(
            const std::vector<TargetPathPattern>& targetPatterns,
            const std::unordered_map<std::uint32_t, std::wstring>& processNameMap,
            const ProgressCallback& progressCallback,
            const CancellationCallback& cancellationCallback,
            bool& kernelUsableOut)
        {
            kernelUsableOut = false;
            HandleUsageScanResult result{};
            if (targetPatterns.empty())
            {
                result.diagnosticText = L"KernelHandleTable:目标为空";
                return result;
            }
            if (isCancellationRequested(cancellationCallback))
            {
                result.diagnosticText = L"扫描已取消。";
                return result;
            }

            ksword::ark::DriverClient driverClient;
            const ksword::ark::ProcessEnumResult kProcessResult = driverClient.enumerateProcesses(KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE);
            if (!kProcessResult.io.ok || kProcessResult.entries.empty())
            {
                result.diagnosticText = readableArkIoMessage(
                    kProcessResult.io.message,
                    L"KernelHandleTable不可用: ");
                return result;
            }

            std::unordered_set<std::uint64_t> emittedHandleKeySet;
            std::unordered_map<std::uint32_t, bool> fileTypeIndexCache;
            std::size_t enumSucceededCount = 0;
            std::size_t enumFailedCount = 0;
            std::size_t objectQueryFailedCount = 0;
            std::size_t nonFileSkippedCount = 0;
            std::size_t fileLikeHandleCount = 0;
            std::vector<ksword::ark::HandleEntry> pendingFileHandles;

            const auto kConsumeObjectResult =
                [&](const ksword::ark::HandleEntry& handleEntry,
                    const ksword::ark::HandleObjectQueryResult& objectResult,
                    const bool cachedFileType)
            {
                if (!objectResult.io.ok)
                {
                    if (cachedFileType)
                    {
                        ++fileLikeHandleCount;
                    }
                    ++objectQueryFailedCount;
                    return;
                }
                if (objectResult.queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_PROCESS_LOOKUP_FAILED ||
                    objectResult.queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED)
                {
                    if (cachedFileType)
                    {
                        ++fileLikeHandleCount;
                    }
                    return;
                }

                const std::wstring kTypeName = objectResult.typeName;
                const bool kQueryIdentifiedFile =
                    equalsInsensitive(kTypeName, L"File") || containsInsensitive(kTypeName, L"File");
                const std::uint32_t kResolvedTypeIndex = objectResult.objectTypeIndex != 0
                    ? objectResult.objectTypeIndex
                    : handleEntry.objectTypeIndex;
                if (kResolvedTypeIndex != 0 && !trimWideCopy(kTypeName).empty())
                {
                    fileTypeIndexCache[kResolvedTypeIndex] = kQueryIdentifiedFile;
                }
                const bool kIsFileType = kQueryIdentifiedFile ||
                    (cachedFileType && trimWideCopy(kTypeName).empty());
                if (!kIsFileType)
                {
                    ++nonFileSkippedCount;
                    return;
                }
                ++fileLikeHandleCount;
                const std::wstring kObjectName = objectResult.objectName;
                if (trimWideCopy(kObjectName).empty())
                {
                    // A successful object query may legitimately have no
                    // comparable name (anonymous File objects, endpoints, or
                    // a per-object name lookup that returned partial data).
                    // It cannot match a target path, but it is not an R0
                    // transport failure and must not inflate the error count.
                    return;
                }

                std::wstring matchedTargetPath;
                bool matchedByDirectoryRule = false;
                if (!matchTargetPath(
                        normalizePathForCompare(kObjectName),
                        targetPatterns,
                        matchedTargetPath,
                        matchedByDirectoryRule))
                {
                    return;
                }

                const std::uint64_t kHandleKey =
                    buildHandleKey(handleEntry.processId, handleEntry.handleValue);
                if (emittedHandleKeySet.find(kHandleKey) != emittedHandleKeySet.end())
                {
                    return;
                }

                HandleUsageEntry entry{};
                entry.processId = handleEntry.processId;
                entry.processName = processNameOf(processNameMap, entry.processId);
                entry.handleValue = handleEntry.handleValue;
                entry.typeIndex = static_cast<std::uint16_t>(objectResult.objectTypeIndex);
                entry.typeName = kTypeName.empty() ? L"File" : kTypeName;
                entry.objectName = kObjectName;
                entry.grantedAccess = objectResult.actualGrantedAccess != 0
                    ? objectResult.actualGrantedAccess
                    : handleEntry.grantedAccess;
                entry.attributes = handleEntry.attributes;
                entry.matchedTargetPath = matchedTargetPath;
                entry.matchedByDirectoryRule = matchedByDirectoryRule;
                entry.matchRuleText = buildPathRuleText(L"文件句柄", matchedByDirectoryRule);
                entry.enumerationSource = L"Kernel HandleTable";
                emittedHandleKeySet.insert(kHandleKey);
                result.entries.push_back(std::move(entry));
            };

            for (std::size_t processIndex = 0; processIndex < kProcessResult.entries.size(); ++processIndex)
            {
                const ksword::ark::ProcessEntry& processEntry = kProcessResult.entries[processIndex];
                if (isCancellationRequested(cancellationCallback))
                {
                    result.diagnosticText = L"扫描已取消。";
                    return result;
                }
                if (progressCallback &&
                    (processIndex == 0U ||
                        ((processIndex + 1U) % 16U) == 0U ||
                        processIndex + 1U == kProcessResult.entries.size()))
                {
                    const float kProgressValue = 10.0f +
                        (60.0f * static_cast<float>(processIndex + 1U) /
                            static_cast<float>(kProcessResult.entries.size()));
                    progressCallback("开始扫描占用来源", kProgressValue);
                }
                if (processEntry.processId == 0) { continue; }
                const ksword::ark::HandleEnumResult kHandleResult = driverClient.enumerateProcessHandles(
                    processEntry.processId,
                    KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL |
                        KSWORD_ARK_ENUM_HANDLE_FLAG_QUIET_LOG);
                if (!kHandleResult.io.ok)
                {
                    const bool kInvalidCid =
                        kHandleResult.io.ntStatus == kStatusInvalidCid ||
                        kHandleResult.lastStatus == kStatusInvalidCid;
                    const bool kInvalidParameterForGoneProcess =
                        kHandleResult.io.win32Error == ERROR_INVALID_PARAMETER &&
                        isProcessGone(processEntry.processId);
                    if (kInvalidCid || kInvalidParameterForGoneProcess)
                    {
                        continue;
                    }
                    ++enumFailedCount;
                    continue;
                }
                ++enumSucceededCount;
                if (kHandleResult.entries.empty())
                {
                    continue;
                }
                result.totalHandleCount += kHandleResult.entries.size();
                for (const ksword::ark::HandleEntry& handleEntry : kHandleResult.entries)
                {
                    if (isCancellationRequested(cancellationCallback))
                    {
                        result.diagnosticText = L"扫描已取消。";
                        return result;
                    }
                    const std::uint64_t kHandleKey = buildHandleKey(handleEntry.processId, handleEntry.handleValue);
                    if (emittedHandleKeySet.find(kHandleKey) != emittedHandleKeySet.end()) { continue; }

                    // Object type indexes are system-wide for the current boot. Query one
                    // representative handle to classify an index, then avoid an expensive
                    // object-name IOCTL for every later handle of a known non-File type.
                    bool cachedFileType = false;
                    if (handleEntry.objectTypeIndex != 0)
                    {
                        const auto kCachedType = fileTypeIndexCache.find(handleEntry.objectTypeIndex);
                        if (kCachedType != fileTypeIndexCache.end())
                        {
                            if (!kCachedType->second)
                            {
                                ++nonFileSkippedCount;
                                continue;
                            }
                            cachedFileType = true;
                        }
                    }

                    if (cachedFileType)
                    {
                        pendingFileHandles.push_back(handleEntry);
                        continue;
                    }

                    const ksword::ark::HandleObjectQueryResult kObjectResult = driverClient.queryHandleObject(
                        handleEntry.processId,
                        handleEntry.handleValue,
                        KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL |
                            KSWORD_ARK_QUERY_OBJECT_FLAG_QUIET_LOG);
                    kConsumeObjectResult(handleEntry, kObjectResult, false);
                }
            }

            if (!pendingFileHandles.empty())
            {
                if (progressCallback) { progressCallback("开始扫描占用来源", 75.0f); }
                std::vector<ksword::ark::HandleObjectQueryResult> pendingResults(
                    pendingFileHandles.size());
                std::atomic_size_t nextIndex{ 0 };
                std::atomic_bool cancellationObserved{ false };
                std::mutex cancellationMutex;
                constexpr std::size_t kMaxObjectQueryWorkers = 8U;
                const std::size_t kWorkerCount = std::min<std::size_t>(
                    kMaxObjectQueryWorkers,
                    pendingFileHandles.size());

                const auto kQueryWorker = [&]()
                {
                    while (!cancellationObserved.load(std::memory_order_acquire))
                    {
                        const std::size_t kIndex = nextIndex.fetch_add(1, std::memory_order_acq_rel);
                        if (kIndex >= pendingFileHandles.size())
                        {
                            return;
                        }
                        {
                            std::lock_guard<std::mutex> cancellationLock(cancellationMutex);
                            if (isCancellationRequested(cancellationCallback))
                            {
                                cancellationObserved.store(true, std::memory_order_release);
                                return;
                            }
                        }

                        const ksword::ark::HandleEntry& handleEntry = pendingFileHandles[kIndex];
                        pendingResults[kIndex] = driverClient.queryHandleObject(
                            handleEntry.processId,
                            handleEntry.handleValue,
                            KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL |
                                KSWORD_ARK_QUERY_OBJECT_FLAG_QUIET_LOG);
                    }
                };

                std::vector<std::thread> workers;
                workers.reserve(kWorkerCount);
                for (std::size_t workerIndex = 0; workerIndex < kWorkerCount; ++workerIndex)
                {
                    workers.emplace_back(kQueryWorker);
                }
                for (std::thread& worker : workers)
                {
                    worker.join();
                }

                if (cancellationObserved.load(std::memory_order_acquire) ||
                    isCancellationRequested(cancellationCallback))
                {
                    result.diagnosticText = L"扫描已取消。";
                    return result;
                }

                for (std::size_t index = 0; index < pendingFileHandles.size(); ++index)
                {
                    kConsumeObjectResult(pendingFileHandles[index], pendingResults[index], true);
                }
            }
            if (progressCallback) { progressCallback("开始扫描占用来源", 90.0f); }

            result.fileLikeHandleCount = fileLikeHandleCount;
            result.matchedHandleCount = result.entries.size();
            result.kernelHandleMatchCount = result.entries.size();
            // If at least one process's HandleTable IOCTL succeeds, it indicates that the R0 path is available;
            // The process having no handles or the entire system having no target matches are both valid empty results.
            kernelUsableOut = enumSucceededCount > 0;
            std::vector<std::wstring> diagnosticList;
            diagnosticList.push_back(L"KernelHandleTable进程:" + std::to_wstring(kProcessResult.entries.size()));
            if (enumFailedCount > 0) { diagnosticList.push_back(L"R0枚举失败进程:" + std::to_wstring(enumFailedCount)); }
            if (objectQueryFailedCount > 0) { diagnosticList.push_back(L"R0对象查询失败:" + std::to_wstring(objectQueryFailedCount)); }
            if (nonFileSkippedCount > 0) { diagnosticList.push_back(L"R0非File跳过:" + std::to_wstring(nonFileSkippedCount)); }
            result.diagnosticText = joinDiagnostic(diagnosticList);
            return result;
        }
        // scanFileHandleOccupancyByR3 scans duplicated File handles from the R3 system snapshot.
        HandleUsageScanResult scanFileHandleOccupancyByR3(
            const std::vector<TargetPathPattern>& targetPatterns,
            const std::unordered_map<std::uint32_t, std::wstring>& processNameMap,
            const ProgressCallback& progressCallback,
            const CancellationCallback& cancellationCallback)
        {
            HandleUsageScanResult result{};
            if (targetPatterns.empty())
            {
                result.diagnosticText = L"未提供有效目标路径。";
                return result;
            }
            if (isCancellationRequested(cancellationCallback))
            {
                result.diagnosticText = L"扫描已取消。";
                return result;
            }

            UniqueHandle helperHandle;
            if (!openTargetPathHandle(targetPatterns.front(), helperHandle))
            {
                result.diagnosticText = L"打开目标路径失败，无法解析 File TypeIndex。";
                return result;
            }
            if (progressCallback) { progressCallback("准备抓取系统句柄快照", 10.0f); }

            const NtApiSet kApiSet = queryNtApis();
            std::vector<RawSystemHandle> rawRecords;
            std::wstring snapshotDiagnosticText;
            if (!querySystemHandles(kApiSet, rawRecords, snapshotDiagnosticText, cancellationCallback))
            {
                result.diagnosticText = snapshotDiagnosticText;
                return result;
            }
            result.totalHandleCount = rawRecords.size();

            std::uint16_t fileTypeIndex = 0;
            if (!resolveFileTypeIndex(helperHandle.get(), rawRecords, fileTypeIndex))
            {
                result.diagnosticText = L"动态 File TypeIndex 解析失败。";
                return result;
            }

            const std::uint64_t kHelperHandleKey = buildHandleKey(
                ::GetCurrentProcessId(),
                static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(helperHandle.get())));
            std::unordered_set<std::uint64_t> emittedHandleKeySet;
            std::unordered_map<std::uint32_t, UniqueHandle> processHandleCache;
            std::unordered_set<std::uint32_t> failedProcessOpenSet;
            std::unordered_map<std::uint32_t, std::wstring> processImagePathCache;
            std::size_t openProcessFailedCount = 0;
            std::size_t duplicateFailedCount = 0;
            std::size_t pathQueryFailedCount = 0;
            std::size_t nonDiskFileSkippedCount = 0;
            if (progressCallback) { progressCallback("扫描文件句柄", 35.0f); }

            for (const RawSystemHandle& row : rawRecords)
            {
                if (isCancellationRequested(cancellationCallback))
                {
                    result.diagnosticText = L"扫描已取消。";
                    return result;
                }
                if (row.typeIndex != fileTypeIndex)
                {
                    continue;
                }
                const std::uint64_t kHandleKey = buildHandleKey(row.processId, row.handleValue);
                if (kHandleKey == kHelperHandleKey || emittedHandleKeySet.find(kHandleKey) != emittedHandleKeySet.end())
                {
                    continue;
                }

                HANDLE ownerProcessHandle = openProcessHandleForDuplicate(row.processId, processHandleCache, failedProcessOpenSet);
                if (ownerProcessHandle == nullptr)
                {
                    ++openProcessFailedCount;
                    continue;
                }
                HANDLE localRawHandle = nullptr;
                if (!duplicateRemoteHandleToLocal(ownerProcessHandle, row.handleValue, localRawHandle))
                {
                    ++duplicateFailedCount;
                    continue;
                }
                UniqueHandle localHandle(localRawHandle);
                if (::GetFileType(localHandle.get()) != FILE_TYPE_DISK)
                {
                    ++nonDiskFileSkippedCount;
                    continue;
                }

                std::wstring finalPathText;
                if (!queryFinalDosPathByHandle(localHandle.get(), finalPathText))
                {
                    std::wstring ntObjectPathText;
                    if (queryNtObjectText(kApiSet, localHandle.get(), kObjectNameInformationClass, ntObjectPathText))
                    {
                        finalPathText = trimWideCopy(ntObjectPathText);
                    }
                }
                if (trimWideCopy(finalPathText).empty())
                {
                    ++pathQueryFailedCount;
                    continue;
                }

                std::wstring matchedTargetPath;
                bool matchedByDirectoryRule = false;
                if (!matchTargetPath(normalizePathForCompare(finalPathText), targetPatterns, matchedTargetPath, matchedByDirectoryRule))
                {
                    continue;
                }

                HandleUsageEntry entry{};
                entry.processId = row.processId;
                entry.processName = processNameOf(processNameMap, row.processId);
                entry.processImagePath = queryProcessImagePathCached(row.processId, processImagePathCache);
                entry.handleValue = row.handleValue;
                entry.typeIndex = fileTypeIndex;
                entry.typeName = L"FileHandle";
                entry.objectName = normalizeNativePath(finalPathText);
                entry.grantedAccess = row.grantedAccess;
                entry.attributes = row.attributes;
                entry.matchedTargetPath = matchedTargetPath;
                entry.matchedByDirectoryRule = matchedByDirectoryRule;
                entry.matchRuleText = buildPathRuleText(L"文件句柄", matchedByDirectoryRule);
                entry.enumerationSource = L"R3 DuplicateHandle";
                emittedHandleKeySet.insert(kHandleKey);
                result.entries.push_back(std::move(entry));
            }

            result.fileLikeHandleCount = result.entries.size();
            result.matchedHandleCount = result.entries.size();
            std::vector<std::wstring> diagnosticList;
            diagnosticList.push_back(L"文件TypeIndex:" + std::to_wstring(fileTypeIndex));
            diagnosticList.push_back(snapshotDiagnosticText);
            if (openProcessFailedCount > 0) { diagnosticList.push_back(L"OpenProcess失败:" + std::to_wstring(openProcessFailedCount)); }
            if (duplicateFailedCount > 0) { diagnosticList.push_back(L"DuplicateHandle失败:" + std::to_wstring(duplicateFailedCount)); }
            if (pathQueryFailedCount > 0) { diagnosticList.push_back(L"路径查询失败:" + std::to_wstring(pathQueryFailedCount)); }
            if (nonDiskFileSkippedCount > 0) { diagnosticList.push_back(L"非磁盘File跳过:" + std::to_wstring(nonDiskFileSkippedCount)); }
            result.diagnosticText = joinDiagnostic(diagnosticList);
            return result;
        }

        // appendSyntheticOccupancyEntries adds image/module occupancy sources that do not
        // necessarily appear as File handles but still keep files busy on disk.
        void appendSyntheticOccupancyEntries(
            const std::vector<TargetPathPattern>& targetPatterns,
            std::unordered_map<std::uint32_t, std::wstring>& processImagePathCache,
            const std::unordered_map<std::uint32_t, std::wstring>& processNameMap,
            std::vector<HandleUsageEntry>& entryList,
            std::size_t& processImageMatchCountOut,
            std::size_t& loadedModuleMatchCountOut,
            const ProgressCallback& progressCallback,
            const CancellationCallback& cancellationCallback)
        {
            processImageMatchCountOut = 0;
            loadedModuleMatchCountOut = 0;
            if (progressCallback) { progressCallback("扫描进程映像占用", 90.0f); }

            std::set<std::wstring> syntheticDedupeSet;
            for (const auto& processPair : processNameMap)
            {
                if (isCancellationRequested(cancellationCallback))
                {
                    return;
                }
                const std::uint32_t kProcessId = processPair.first;
                const std::wstring kImagePath = queryProcessImagePathCached(kProcessId, processImagePathCache);
                std::wstring matchedTargetPath;
                bool matchedByDirectoryRule = false;
                if (!matchTargetPath(normalizePathForCompare(kImagePath), targetPatterns, matchedTargetPath, matchedByDirectoryRule))
                {
                    continue;
                }
                const std::wstring kDedupeKey = L"PI|" + std::to_wstring(kProcessId) + L"|" + normalizePathForCompare(kImagePath);
                if (syntheticDedupeSet.find(kDedupeKey) != syntheticDedupeSet.end())
                {
                    continue;
                }
                syntheticDedupeSet.insert(kDedupeKey);

                HandleUsageEntry entry{};
                entry.processId = kProcessId;
                entry.processName = processPair.second;
                entry.processImagePath = kImagePath;
                entry.typeName = L"ProcessImage";
                entry.objectName = kImagePath;
                entry.matchedTargetPath = matchedTargetPath;
                entry.matchedByDirectoryRule = matchedByDirectoryRule;
                entry.matchRuleText = buildPathRuleText(L"进程映像", matchedByDirectoryRule);
                entry.enumerationSource = L"R3 ProcessImage";
                entryList.push_back(std::move(entry));
                ++processImageMatchCountOut;
            }

            if (progressCallback) { progressCallback("扫描模块加载占用", 95.0f); }
            for (const auto& processPair : processNameMap)
            {
                if (isCancellationRequested(cancellationCallback))
                {
                    return;
                }
                const std::uint32_t kProcessId = processPair.first;
                UniqueHandle moduleSnapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, kProcessId));
                if (!moduleSnapshot.valid())
                {
                    continue;
                }

                MODULEENTRY32W moduleEntry{};
                moduleEntry.dwSize = sizeof(moduleEntry);
                BOOL hasModule = ::Module32FirstW(moduleSnapshot.get(), &moduleEntry);
                while (hasModule != FALSE)
                {
                    if (isCancellationRequested(cancellationCallback))
                    {
                        return;
                    }
                    const std::wstring kModulePath = moduleEntry.szExePath;
                    std::wstring matchedTargetPath;
                    bool matchedByDirectoryRule = false;
                    if (matchTargetPath(normalizePathForCompare(kModulePath), targetPatterns, matchedTargetPath, matchedByDirectoryRule))
                    {
                        const std::wstring kDedupeKey = L"LM|" + std::to_wstring(kProcessId) + L"|" + normalizePathForCompare(kModulePath);
                        if (syntheticDedupeSet.find(kDedupeKey) == syntheticDedupeSet.end())
                        {
                            syntheticDedupeSet.insert(kDedupeKey);
                            HandleUsageEntry entry{};
                            entry.processId = kProcessId;
                            entry.processName = processPair.second;
                            entry.processImagePath = queryProcessImagePathCached(kProcessId, processImagePathCache);
                            entry.typeName = L"LoadedModule";
                            entry.objectName = kModulePath;
                            entry.matchedTargetPath = matchedTargetPath;
                            entry.matchedByDirectoryRule = matchedByDirectoryRule;
                            entry.matchRuleText = buildPathRuleText(L"模块加载", matchedByDirectoryRule);
                            entry.enumerationSource = L"R3 ModuleSnapshot";
                            entryList.push_back(std::move(entry));
                            ++loadedModuleMatchCountOut;
                        }
                    }
                    hasModule = ::Module32NextW(moduleSnapshot.get(), &moduleEntry);
                }
            }
        }
    }

    HandleUsageScanResult scanHandleUsageByPaths(const std::vector<std::wstring>& absolutePaths, const HandleUsageScanOptions& options)
    {
        HandleUsageScanResult result{};
        const auto kBeginTime = std::chrono::steady_clock::now();
        const auto kFinishCancelledScan = [&result, kBeginTime]()
        {
            result.entries.clear();
            result.matchedHandleCount = 0;
            result.processImageMatchCount = 0;
            result.loadedModuleMatchCount = 0;
            result.kernelHandleMatchCount = 0;
            result.diagnosticText = L"扫描已取消。";
            result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        };
        if (isCancellationRequested(options.cancellationCallback))
        {
            kFinishCancelledScan();
            return result;
        }
        const std::vector<TargetPathPattern> kTargetPatterns = buildTargetPathPatterns(absolutePaths);
        if (kTargetPatterns.empty())
        {
            result.diagnosticText = L"未提供有效目标路径。";
            result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
            return result;
        }

        const std::unordered_map<std::uint32_t, std::wstring> kProcessNameMap = collectProcessNameMap(options.cancellationCallback);
        if (isCancellationRequested(options.cancellationCallback))
        {
            kFinishCancelledScan();
            return result;
        }
        std::unordered_map<std::uint32_t, std::wstring> processImagePathCache;
        if (options.progressCallback) { options.progressCallback("开始扫描占用来源", 5.0f); }

        HandleUsageScanResult kernelHandleResult{};
        bool kernelUsable = false;
        if (options.tryKernelHandleTable)
        {
            kernelHandleResult = scanKernelHandleTableOccupancy(
                kTargetPatterns,
                kProcessNameMap,
                options.progressCallback,
                options.cancellationCallback,
                kernelUsable);
            if (isCancellationRequested(options.cancellationCallback))
            {
                kFinishCancelledScan();
                return result;
            }
        }

        const HandleUsageScanResult kFileHandleResult =
            options.tryKernelHandleTable && kernelUsable
            ? kernelHandleResult
            : scanFileHandleOccupancyByR3(
                kTargetPatterns,
                kProcessNameMap,
                options.progressCallback,
                options.cancellationCallback);
        result = kFileHandleResult;
        result.kernelHandleTableAttempted = options.tryKernelHandleTable;
        result.kernelHandleTableUsed = options.tryKernelHandleTable && kernelUsable;
        result.r3HandleFallbackUsed = options.tryKernelHandleTable && !kernelUsable;
        if (isCancellationRequested(options.cancellationCallback))
        {
            kFinishCancelledScan();
            return result;
        }

        appendSyntheticOccupancyEntries(
            kTargetPatterns,
            processImagePathCache,
            kProcessNameMap,
            result.entries,
            result.processImageMatchCount,
            result.loadedModuleMatchCount,
            options.progressCallback,
            options.cancellationCallback);
        if (isCancellationRequested(options.cancellationCallback))
        {
            kFinishCancelledScan();
            return result;
        }

        // Destructive unlock actions may execute long after user confirmation; save process creation time for each candidate to re-verify
        // identity using PID + creation time, preventing the PID from being reused by the system and affecting a different process.
        std::unordered_map<std::uint32_t, std::uint64_t> processCreationTimeCache;
        for (HandleUsageEntry& entry : result.entries)
        {
            if (isCancellationRequested(options.cancellationCallback))
            {
                kFinishCancelledScan();
                return result;
            }
            entry.processCreationTime = queryProcessCreationTimeCached(
                entry.processId,
                processCreationTimeCache);
        }

        std::sort(result.entries.begin(), result.entries.end(), [](const HandleUsageEntry& leftEntry, const HandleUsageEntry& rightEntry) {
            if (leftEntry.processId != rightEntry.processId) { return leftEntry.processId < rightEntry.processId; }
            if (leftEntry.handleValue != rightEntry.handleValue) { return leftEntry.handleValue < rightEntry.handleValue; }
            return leftEntry.objectName < rightEntry.objectName;
        });

        result.matchedHandleCount = result.entries.size();
        std::vector<std::wstring> diagnosticList;
        diagnosticList.push_back(result.diagnosticText);
        if (options.tryKernelHandleTable && !kernelUsable)
        {
            if (!trimWideCopy(kernelHandleResult.diagnosticText).empty())
            {
                diagnosticList.push_back(L"R0回退原因:" + kernelHandleResult.diagnosticText);
            }
            diagnosticList.push_back(L"文件句柄来源:R3 DuplicateHandle");
        }
        else if (kernelUsable)
        {
            diagnosticList.push_back(L"文件句柄来源:Kernel HandleTable");
        }
        if (result.processImageMatchCount > 0) { diagnosticList.push_back(L"进程映像占用:" + std::to_wstring(result.processImageMatchCount)); }
        if (result.loadedModuleMatchCount > 0) { diagnosticList.push_back(L"模块加载占用:" + std::to_wstring(result.loadedModuleMatchCount)); }
        result.diagnosticText = joinDiagnostic(diagnosticList);
        if (options.progressCallback) { options.progressCallback("占用扫描完成", 100.0f); }
        result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count());
        return result;
    }
}
