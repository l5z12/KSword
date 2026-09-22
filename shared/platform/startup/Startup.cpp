#include "Startup.h"

#include "StartupInternal.h"

#include "../string/String.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Aclapi.h>
#include <Windows.h>
#include <KnownFolders.h>
#include <Shellapi.h>
#include <ShlObj.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <sddl.h>
#include <winsvc.h>
#include <winver.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <regex>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wintrust.lib")

// The first two helper blocks live in ks::startup::detail instead of an anonymous namespace so that
// sibling translation units (startup_hidden.cpp) can reuse the same registry/entry plumbing.
// A file-scope using-directive after the second block keeps every later unqualified call site intact.
namespace ks::startup::detail
{
    // The backend stores all public strings as UTF-8 and converts to UTF-16 only at Win32 boundaries.
    std::string fromWide(const std::wstring& text)
    {
        return ks::str::utf16ToUtf8(text);
    }

    // Win32 APIs require UTF-16; empty conversion failures naturally produce empty Win32 strings.
    std::wstring toWide(const std::string& text)
    {
        return ks::str::utf8ToUtf16(text);
    }

    // TrimWide mirrors ks::str::TrimCopy for temporary UTF-16 values returned by Win32 APIs.
    std::wstring trimWide(const std::wstring& text)
    {
        std::size_t first = 0;
        while (first < text.size() && std::iswspace(text[first]))
        {
            ++first;
        }
        std::size_t last = text.size();
        while (last > first && std::iswspace(text[last - 1]))
        {
            --last;
        }
        return text.substr(first, last - first);
    }

    // lowerWideCopy is used for case-insensitive registry and command-line tests.
    std::wstring lowerWideCopy(std::wstring text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        return text;
    }

    // lowerAsciiCopy is sufficient for registry catalog roots and de-duplication keys.
    std::string lowerAsciiCopy(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return text;
    }

    // Case-insensitive prefix check for ASCII catalog and JSON field values.
    bool startsWithI(const std::string& text, const std::string& prefix)
    {
        if (text.size() < prefix.size())
        {
            return false;
        }
        return lowerAsciiCopy(text.substr(0, prefix.size())) == lowerAsciiCopy(prefix);
    }

    // Case-insensitive suffix check for UTF-16 registry subkey filtering.
    bool endsWithI(const std::wstring& text, const std::wstring& suffix)
    {
        if (text.size() < suffix.size())
        {
            return false;
        }
        return lowerWideCopy(text.substr(text.size() - suffix.size())) == lowerWideCopy(suffix);
    }

    // Replace all ASCII occurrences without changing unrelated non-ASCII display text.
    void replaceAll(std::string& text, const std::string& from, const std::string& to)
    {
        if (from.empty())
        {
            return;
        }
        std::size_t offset = 0;
        while ((offset = text.find(from, offset)) != std::string::npos)
        {
            text.replace(offset, from.size(), to);
            offset += to.size();
        }
    }

    // Case-insensitive replace for noisy registry catalog input lines.
    void replaceAllI(std::string& text, const std::string& from, const std::string& to)
    {
        if (from.empty())
        {
            return;
        }
        std::string lowerText = lowerAsciiCopy(text);
        const std::string kLowerFrom = lowerAsciiCopy(from);
        std::size_t offset = 0;
        while ((offset = lowerText.find(kLowerFrom, offset)) != std::string::npos)
        {
            text.replace(offset, from.size(), to);
            lowerText.replace(offset, from.size(), lowerAsciiCopy(to));
            offset += to.size();
        }
    }

    // Convert slash variants to Windows native separators for display and Explorer operations.
    std::string toNativeSeparators(std::string text)
    {
        std::replace(text.begin(), text.end(), '/', '\\');
        return text;
    }

    // Expand environment variables while preserving the original text on failure.
    std::wstring expandEnvironmentWide(const std::wstring& text)
    {
        if (trimWide(text).empty())
        {
            return std::wstring();
        }
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD kChars = ::ExpandEnvironmentStringsW(text.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (kChars == 0 || kChars >= buffer.size())
        {
            return trimWide(text);
        }
        return trimWide(buffer.data());
    }

    // Query an environment variable as UTF-16 and return an empty string when it is absent.
    std::wstring queryEnvironmentWide(const wchar_t* name)
    {
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD kChars = ::GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (kChars == 0 || kChars >= buffer.size())
        {
            return std::wstring();
        }
        return std::wstring(buffer.data(), kChars);
    }

    // knownFolderPath avoids trusting caller-controlled environment variables for security paths.
    std::wstring knownFolderPath(const KNOWNFOLDERID& folderId)
    {
        PWSTR rawPath = nullptr;
        const HRESULT kResult = ::SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, nullptr, &rawPath);
        if (FAILED(kResult) || rawPath == nullptr)
        {
            if (rawPath != nullptr)
            {
                ::CoTaskMemFree(rawPath);
            }
            return std::wstring();
        }
        std::wstring path(rawPath);
        ::CoTaskMemFree(rawPath);
        return path;
    }

    struct FileIdentitySnapshot
    {
        std::uint64_t volumeSerial = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t lastWriteTime = 0;
    };

    // queryFileIdentityNoReparse opens the final component itself and rejects links/directories.
    bool queryFileIdentityNoReparse(
        const std::wstring& pathText,
        FileIdentitySnapshot& identityOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        HANDLE fileHandle = ::CreateFileW(
            pathText.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        BY_HANDLE_FILE_INFORMATION information{};
        const BOOL kQueryOk = ::GetFileInformationByHandle(fileHandle, &information);
        const DWORD kQueryError = kQueryOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(fileHandle);
        if (kQueryOk == FALSE)
        {
            errorCodeOut = kQueryError;
            return false;
        }
        if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            errorCodeOut = ERROR_REPARSE_TAG_INVALID;
            return false;
        }
        ULARGE_INTEGER fileIndex{};
        fileIndex.HighPart = information.nFileIndexHigh;
        fileIndex.LowPart = information.nFileIndexLow;
        ULARGE_INTEGER fileSize{};
        fileSize.HighPart = information.nFileSizeHigh;
        fileSize.LowPart = information.nFileSizeLow;
        ULARGE_INTEGER lastWriteTime{};
        lastWriteTime.HighPart = information.ftLastWriteTime.dwHighDateTime;
        lastWriteTime.LowPart = information.ftLastWriteTime.dwLowDateTime;
        identityOut.volumeSerial = information.dwVolumeSerialNumber;
        identityOut.fileIndex = fileIndex.QuadPart;
        identityOut.fileSize = fileSize.QuadPart;
        identityOut.lastWriteTime = lastWriteTime.QuadPart;
        return true;
    }

    // Append detail fragments without forcing the UI layer to know how backend details were assembled.
    void appendDetailPart(std::string& detailText, const std::string& partText)
    {
        const std::string kTrimmedPart = ks::str::trimCopy(partText);
        if (kTrimmedPart.empty())
        {
            return;
        }
        if (!ks::str::trimCopy(detailText).empty())
        {
            detailText += fromWide(L"\uff1b");
        }
        detailText += kTrimmedPart;
    }

    // Join helper for registry value dumps and CSV-like action lists.
    std::string joinStrings(const std::vector<std::string>& values, const std::string& separator)
    {
        std::ostringstream stream;
        for (std::size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                stream << separator;
            }
            stream << values[index];
        }
        return stream.str();
    }

    // fileExists intentionally accepts a command-extracted path; callers decide whether absence is suspicious.
    bool fileExists(const std::string& pathText)
    {
        const std::wstring kPathWide = toWide(pathText);
        if (kPathWide.empty())
        {
            return false;
        }
        const DWORD kAttributes = ::GetFileAttributesW(kPathWide.c_str());
        return kAttributes != INVALID_FILE_ATTRIBUTES && (kAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    // formatBinaryText keeps binary registry values readable and bounded.
    std::string formatBinaryText(const std::vector<std::uint8_t>& rawBuffer)
    {
        static constexpr char kHexDigits[] = "0123456789ABCDEF";
        const std::size_t kDisplayCount = std::min<std::size_t>(rawBuffer.size(), 16);
        std::string text;
        for (std::size_t index = 0; index < kDisplayCount; ++index)
        {
            if (!text.empty())
            {
                text.push_back(' ');
            }
            text.push_back(kHexDigits[(rawBuffer[index] >> 4) & 0x0F]);
            text.push_back(kHexDigits[rawBuffer[index] & 0x0F]);
        }
        if (rawBuffer.size() > kDisplayCount)
        {
            text += " ... (" + std::to_string(rawBuffer.size()) + " bytes)";
        }
        return text;
    }

    // registryWideStringFromBuffer safely decodes REG_SZ/REG_EXPAND_SZ data.
    // Inputs:
    // - rawBuffer: raw bytes returned by RegQueryValueExW/RegEnumValueW.
    // Processing:
    // - Interpret only complete wchar_t units and trim one trailing NUL if present.
    // - Do not call wcslen because registry strings are not guaranteed to be terminated.
    // Return:
    // - UTF-16 string content without the terminator, or empty text for invalid/empty buffers.
    std::wstring registryWideStringFromBuffer(const std::vector<std::uint8_t>& rawBuffer)
    {
        const std::size_t kWcharCount = rawBuffer.size() / sizeof(wchar_t);
        if (kWcharCount == 0)
        {
            return std::wstring();
        }

        const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawBuffer.data());
        std::size_t visibleCount = kWcharCount;
        if (visibleCount > 0 && textBegin[visibleCount - 1] == L'\0')
        {
            --visibleCount;
        }
        return std::wstring(textBegin, textBegin + visibleCount);
    }

    // registryWideMultiStringFromBuffer safely decodes REG_MULTI_SZ data.
    // Inputs:
    // - rawBuffer: raw bytes returned for a multi-string registry value.
    // Processing:
    // - Walk bounded wchar_t units and split at NUL separators.
    // - Stop at an empty segment, which is the conventional REG_MULTI_SZ terminator.
    // Return:
    // - Non-empty UTF-16 segments; malformed missing double-NUL data is still bounded.
    std::vector<std::wstring> registryWideMultiStringFromBuffer(const std::vector<std::uint8_t>& rawBuffer)
    {
        std::vector<std::wstring> values;
        const std::size_t kWcharCount = rawBuffer.size() / sizeof(wchar_t);
        if (kWcharCount == 0)
        {
            return values;
        }

        const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawBuffer.data());
        std::size_t offset = 0;
        while (offset < kWcharCount)
        {
            const std::size_t kSegmentStart = offset;
            while (offset < kWcharCount && textBegin[offset] != L'\0')
            {
                ++offset;
            }

            if (offset == kSegmentStart)
            {
                break;
            }

            values.emplace_back(textBegin + kSegmentStart, textBegin + offset);
            if (offset < kWcharCount)
            {
                ++offset;
            }
        }
        return values;
    }

    // Read CompanyName from VERSIONINFO as the fast publisher fallback before WinVerifyTrust text.
    std::string queryCompanyNameByVersion(const std::string& filePathText)
    {
        const std::wstring kPathWide = toWide(filePathText);
        if (kPathWide.empty())
        {
            return std::string();
        }
        DWORD handleValue = 0;
        const DWORD kBytes = ::GetFileVersionInfoSizeW(kPathWide.c_str(), &handleValue);
        if (kBytes == 0)
        {
            return std::string();
        }
        std::vector<std::uint8_t> buffer(kBytes);
        if (::GetFileVersionInfoW(kPathWide.c_str(), 0, kBytes, buffer.data()) == FALSE)
        {
            return std::string();
        }
        struct LangAndCodePage { WORD language = 0; WORD codePage = 0; };
        LangAndCodePage* translation = nullptr;
        UINT translationBytes = 0;
        if (::VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translation), &translationBytes) == FALSE ||
            translation == nullptr || translationBytes < sizeof(LangAndCodePage))
        {
            return std::string();
        }
        wchar_t queryPath[64] = {};
        _snwprintf_s(queryPath, _countof(queryPath), _TRUNCATE, L"\\StringFileInfo\\%04x%04x\\CompanyName", translation[0].language, translation[0].codePage);
        wchar_t* companyName = nullptr;
        UINT companyChars = 0;
        if (::VerQueryValueW(buffer.data(), queryPath, reinterpret_cast<LPVOID*>(&companyName), &companyChars) == FALSE || companyName == nullptr || companyChars <= 1)
        {
            return std::string();
        }
        return fromWide(trimWide(companyName));
    }

    // WinVerifyTrust is used in cache-only mode to avoid UI/network prompts from the backend thread.
    bool isFileTrustedByWindows(const std::string& filePathText)
    {
        const std::wstring kPathWide = toWide(filePathText);
        if (kPathWide.empty())
        {
            return false;
        }
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = kPathWide.c_str();
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.pFile = &fileInfo;
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG kResult = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        return kResult == ERROR_SUCCESS;
    }
}

namespace ks::startup::detail
{
    // rootKeyText maps the limited root keys used by StartupDock-compatible enumerators.
    std::string rootKeyText(HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return "HKCU";
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return "HKLM";
        }
        if (rootKey == HKEY_CLASSES_ROOT)
        {
            return "HKCR";
        }
        return "UNKNOWN";
    }

    // buildRegistryLocationText creates the exact location syntax consumed by StartupDock actions.
    std::string buildRegistryLocationText(HKEY rootKey, const std::wstring& subKeyText)
    {
        return rootKeyText(rootKey) + "\\" + fromWide(subKeyText);
    }

    // equalWideI compares Win32 locator components without depending on display casing.
    bool equalWideI(const std::wstring& left, const std::wstring& right)
    {
        return ::CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
    }

    // publicRegistryRoot converts only the two hives accepted by reversible Run actions.
    ks::startup::StartupRegistryRoot publicRegistryRoot(HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return ks::startup::StartupRegistryRoot::kCurrentUser;
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return ks::startup::StartupRegistryRoot::kLocalMachine;
        }
        return ks::startup::StartupRegistryRoot::kNone;
    }

    // nativeRegistryRoot rejects unknown public roots instead of guessing from display text.
    HKEY nativeRegistryRoot(const ks::startup::StartupRegistryRoot root)
    {
        switch (root)
        {
        case ks::startup::StartupRegistryRoot::kCurrentUser:
            return HKEY_CURRENT_USER;
        case ks::startup::StartupRegistryRoot::kLocalMachine:
            return HKEY_LOCAL_MACHINE;
        case ks::startup::StartupRegistryRoot::kNone:
            break;
        }
        return nullptr;
    }

    // Registry backup metadata lives at the same integrity scope as its restore target.
    HKEY registryBackupMetadataHive(const ks::startup::StartupRegistryRoot root)
    {
        return nativeRegistryRoot(root);
    }

    // isKnownRunLocation recognizes records created by older builds so they remain visible.
    bool isKnownRunLocation(HKEY rootKey, const std::wstring& subKeyText)
    {
        static const std::wstring kRunKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        static const std::wstring kRunOnceKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        static const std::wstring kRun32Key = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
        static const std::wstring kRunOnce32Key = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        if (rootKey == HKEY_CURRENT_USER)
        {
            return equalWideI(subKeyText, kRunKey) || equalWideI(subKeyText, kRunOnceKey);
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return equalWideI(subKeyText, kRunKey) || equalWideI(subKeyText, kRunOnceKey)
                || equalWideI(subKeyText, kRun32Key) || equalWideI(subKeyText, kRunOnce32Key);
        }
        return false;
    }

    // Warning-gated registry actions accept values from every enumerated HKCU/HKLM source.
    bool isSupportedRunLocation(HKEY rootKey, const std::wstring& subKeyText)
    {
        return (rootKey == HKEY_CURRENT_USER || rootKey == HKEY_LOCAL_MACHINE)
            && !subKeyText.empty()
            && subKeyText.find(L'\0') == std::wstring::npos;
    }

    // Synthetic or corrupt diagnostic rows have no meaningful source object to mutate.
    void markEntryActionUnavailable(
        ks::startup::StartupEntry& entry,
        const ks::startup::StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText)
    {
        entry.actionKind = ks::startup::StartupActionKind::kNone;
        entry.actionLocator = ks::startup::StartupActionLocator{};
        entry.canEnable = false;
        entry.canDisable = false;
        entry.riskLevel = riskLevel;
        entry.riskReasonCode = reasonCode;
        entry.riskReasonText = reasonText;
        entry.canDelete = false;
    }

    void configureRegistryValueAction(
        ks::startup::StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText,
        const RegistryValueRecord& valueRecord,
        const ks::startup::StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText)
    {
        entry.actionKind = ks::startup::StartupActionKind::kRegistryRunValue;
        entry.actionLocator.registryRoot = publicRegistryRoot(rootKey);
        entry.actionLocator.registrySubKeyText = fromWide(subKeyText);
        entry.actionLocator.registryValueNameText = valueRecord.valueNameText;
        entry.actionLocator.registryValueSnapshotValid = true;
        entry.actionLocator.registryValueType = valueRecord.valueType;
        entry.actionLocator.registryRawData = valueRecord.rawData;
        entry.canEnable = false;
        entry.canDisable = true;
        entry.riskLevel = riskLevel;
        entry.riskReasonCode = reasonCode;
        entry.riskReasonText = reasonText;
        entry.canDelete = true;
    }

    LONG queryRegistryTreeSnapshot(
        HKEY rootKey,
        const std::wstring& subKeyText,
        ks::startup::StartupActionLocator& locator)
    {
        locator.registryTreeSnapshotValid = false;
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            subKeyText.c_str(),
            0,
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            return kOpenResult;
        }
        DWORD subKeyCount = 0;
        DWORD valueCount = 0;
        FILETIME lastWriteTime{};
        const LONG kQueryResult = ::RegQueryInfoKeyW(
            openedKey,
            nullptr,
            nullptr,
            nullptr,
            &subKeyCount,
            nullptr,
            nullptr,
            &valueCount,
            nullptr,
            nullptr,
            nullptr,
            &lastWriteTime);
        ::RegCloseKey(openedKey);
        if (kQueryResult != ERROR_SUCCESS)
        {
            return kQueryResult;
        }
        ULARGE_INTEGER lastWriteValue{};
        lastWriteValue.HighPart = lastWriteTime.dwHighDateTime;
        lastWriteValue.LowPart = lastWriteTime.dwLowDateTime;
        locator.registryTreeSubKeyCount = subKeyCount;
        locator.registryTreeValueCount = valueCount;
        locator.registryTreeLastWriteTime = lastWriteValue.QuadPart;
        locator.registryTreeSnapshotValid = true;
        return ERROR_SUCCESS;
    }

    bool captureRegistryTreeSnapshot(
        HKEY rootKey,
        const std::wstring& subKeyText,
        ks::startup::StartupActionLocator& locator)
    {
        return queryRegistryTreeSnapshot(rootKey, subKeyText, locator) == ERROR_SUCCESS;
    }

    void configureRegistryTreeDeletion(
        ks::startup::StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText)
    {
        entry.actionLocator.registryRoot = publicRegistryRoot(rootKey);
        entry.actionLocator.registrySubKeyText = fromWide(subKeyText);
        if (entry.actionKind == ks::startup::StartupActionKind::kNone)
        {
            entry.actionKind = ks::startup::StartupActionKind::kRegistryTree;
        }
        captureRegistryTreeSnapshot(rootKey, subKeyText, entry.actionLocator);
        entry.canDelete = entry.actionLocator.registryRoot != ks::startup::StartupRegistryRoot::kNone;
        entry.deleteRegistryTree = entry.canDelete;
    }

    // registryDataToText converts common registry types into compact UTF-8 display strings.
    std::string registryDataToText(DWORD valueType, const std::vector<std::uint8_t>& rawBuffer)
    {
        if (rawBuffer.empty())
        {
            return std::string();
        }
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
        {
            std::wstring valueText = registryWideStringFromBuffer(rawBuffer);
            if (valueType == REG_EXPAND_SZ)
            {
                valueText = expandEnvironmentWide(valueText);
            }
            return fromWide(trimWide(valueText));
        }
        if (valueType == REG_MULTI_SZ)
        {
            std::vector<std::string> items;
            for (const std::wstring& rawItemText : registryWideMultiStringFromBuffer(rawBuffer))
            {
                const std::wstring kItemText = expandEnvironmentWide(rawItemText);
                if (!trimWide(kItemText).empty())
                {
                    items.push_back(fromWide(kItemText));
                }
            }
            return joinStrings(items, " | ");
        }
        if (valueType == REG_DWORD && rawBuffer.size() >= sizeof(DWORD))
        {
            const DWORD kValue = *reinterpret_cast<const DWORD*>(rawBuffer.data());
            std::ostringstream stream;
            stream << kValue << " (0x" << std::uppercase << std::hex;
            stream.width(8);
            stream.fill('0');
            stream << kValue << ")";
            return stream.str();
        }
        if (valueType == REG_QWORD && rawBuffer.size() >= sizeof(unsigned long long))
        {
            const unsigned long long kValue = *reinterpret_cast<const unsigned long long*>(rawBuffer.data());
            std::ostringstream stream;
            stream << kValue << " (0x" << std::uppercase << std::hex;
            stream.width(16);
            stream.fill('0');
            stream << kValue << ")";
            return stream.str();
        }
        return formatBinaryText(rawBuffer);
    }

    // queryRegistryValueRecord reads a named or default value and converts it to a backend value record.
    std::optional<RegistryValueRecord> queryRegistryValueRecord(HKEY rootKey, const std::wstring& subKeyText, const std::wstring& valueNameText)
    {
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return std::nullopt;
        }
        DWORD valueType = REG_NONE;
        DWORD bufferBytes = 0;
        const wchar_t* valueNamePointer = valueNameText.empty() ? nullptr : valueNameText.c_str();
        const LONG kSizeResult = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, nullptr, &bufferBytes);
        if (kSizeResult != ERROR_SUCCESS || bufferBytes == 0)
        {
            ::RegCloseKey(openedKey);
            return std::nullopt;
        }
        std::vector<std::uint8_t> rawBuffer(static_cast<std::size_t>(bufferBytes));
        const LONG kDataResult = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, rawBuffer.data(), &bufferBytes);
        ::RegCloseKey(openedKey);
        if (kDataResult != ERROR_SUCCESS)
        {
            return std::nullopt;
        }
        rawBuffer.resize(bufferBytes);
        RegistryValueRecord record;
        record.valueNameText = fromWide(valueNameText);
        record.valueDataText = ks::str::trimCopy(registryDataToText(valueType, rawBuffer));
        record.valueType = valueType;
        record.rawData = std::move(rawBuffer);
        return record;
    }

    // enumerateRegistryValues returns all values under a key; inaccessible keys simply yield no rows.
    std::vector<RegistryValueRecord> enumerateRegistryValues(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<RegistryValueRecord> records;
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return records;
        }
        DWORD valueIndex = 0;
        while (true)
        {
            std::array<wchar_t, 1024> valueName{};
            DWORD valueNameChars = static_cast<DWORD>(valueName.size());
            DWORD valueType = REG_NONE;
            DWORD dataBytes = 0;
            const LONG kHeaderResult = ::RegEnumValueW(openedKey, valueIndex, valueName.data(), &valueNameChars, nullptr, &valueType, nullptr, &dataBytes);
            if (kHeaderResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (kHeaderResult != ERROR_SUCCESS)
            {
                ++valueIndex;
                continue;
            }
            std::vector<std::uint8_t> rawBuffer(static_cast<std::size_t>(dataBytes == 0 ? 2 : dataBytes));
            valueNameChars = static_cast<DWORD>(valueName.size());
            const LONG kDataResult = ::RegEnumValueW(openedKey, valueIndex, valueName.data(), &valueNameChars, nullptr, &valueType, rawBuffer.data(), &dataBytes);
            if (kDataResult == ERROR_SUCCESS)
            {
                rawBuffer.resize(dataBytes);
                RegistryValueRecord record;
                record.valueNameText = fromWide(std::wstring(valueName.data(), valueNameChars));
                record.valueDataText = ks::str::trimCopy(registryDataToText(valueType, rawBuffer));
                record.valueType = valueType;
                record.rawData = std::move(rawBuffer);
                records.push_back(std::move(record));
            }
            ++valueIndex;
        }
        ::RegCloseKey(openedKey);
        return records;
    }

    // enumerateRegistrySubKeys lists first-level subkey names for registry persistence families.
    std::vector<std::wstring> enumerateRegistrySubKeys(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<std::wstring> subKeys;
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return subKeys;
        }
        DWORD subKeyIndex = 0;
        while (true)
        {
            std::array<wchar_t, 1024> subKeyName{};
            DWORD subKeyChars = static_cast<DWORD>(subKeyName.size());
            const LONG kEnumResult = ::RegEnumKeyExW(openedKey, subKeyIndex, subKeyName.data(), &subKeyChars, nullptr, nullptr, nullptr, nullptr);
            if (kEnumResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (kEnumResult == ERROR_SUCCESS)
            {
                subKeys.emplace_back(subKeyName.data(), subKeyChars);
            }
            ++subKeyIndex;
        }
        ::RegCloseKey(openedKey);
        return subKeys;
    }

    // isClsidText accepts the same relaxed {GUID} shape used by the previous UI-side backend.
    bool isClsidText(const std::string& text)
    {
        const std::string kTrimmed = ks::str::trimCopy(text);
        return kTrimmed.size() >= 38 && kTrimmed.front() == '{' && kTrimmed.back() == '}';
    }

    // queryClsidFriendlyName gives COM rows a readable name when HKCR exposes one.
    std::string queryClsidFriendlyName(const std::string& clsidText)
    {
        if (!isClsidText(clsidText))
        {
            return std::string();
        }
        const auto kRecord = queryRegistryValueRecord(HKEY_CLASSES_ROOT, L"CLSID\\" + toWide(ks::str::trimCopy(clsidText)), L"");
        return kRecord.has_value() ? kRecord->valueDataText : std::string();
    }

    // queryClsidServerPath resolves COM server paths from InprocServer32 or LocalServer32.
    std::string queryClsidServerPath(const std::string& clsidText)
    {
        if (!isClsidText(clsidText))
        {
            return std::string();
        }
        const std::wstring kClsidSubKey = L"CLSID\\" + toWide(ks::str::trimCopy(clsidText));
        for (const std::wstring& candidate : { kClsidSubKey + L"\\InprocServer32", kClsidSubKey + L"\\LocalServer32" })
        {
            const auto kRecord = queryRegistryValueRecord(HKEY_CLASSES_ROOT, candidate, L"");
            if (kRecord.has_value() && !ks::str::trimCopy(kRecord->valueDataText).empty())
            {
                return ks::startup::normalizeFilePathText(kRecord->valueDataText);
            }
        }
        return std::string();
    }

    // finalizeRegistryEntry fills command, normalized path, publisher, and registry deletion metadata.
    void finalizeRegistryEntry(
        ks::startup::StartupEntry& entry,
        const std::string& rawCommandText,
        const std::string& fallbackClsidText,
        const std::string& registryValueNameText,
        bool deleteRegistryTree,
        bool resolveClsidFromValueData)
    {
        entry.commandText = ks::str::trimCopy(rawCommandText);
        entry.registryValueNameText = registryValueNameText;
        entry.deleteRegistryTree = deleteRegistryTree;
        entry.canOpenRegistryLocation = !ks::str::trimCopy(entry.locationText).empty();
        entry.canDelete = false;

        std::string resolvedImagePath;
        if (resolveClsidFromValueData && isClsidText(entry.commandText))
        {
            resolvedImagePath = queryClsidServerPath(entry.commandText);
            appendDetailPart(entry.detailText, "CLSID=" + entry.commandText);
        }
        if (ks::str::trimCopy(resolvedImagePath).empty() && isClsidText(fallbackClsidText))
        {
            resolvedImagePath = queryClsidServerPath(fallbackClsidText);
            appendDetailPart(entry.detailText, "CLSID=" + fallbackClsidText);
        }
        const std::string kClsidFriendlyName = isClsidText(fallbackClsidText)
            ? queryClsidFriendlyName(fallbackClsidText)
            : (isClsidText(entry.commandText) ? queryClsidFriendlyName(entry.commandText) : std::string());
        if (!ks::str::trimCopy(kClsidFriendlyName).empty())
        {
            appendDetailPart(entry.detailText, fromWide(L"\u7ec4\u4ef6=") + kClsidFriendlyName);
        }
        entry.imagePathText = ks::str::trimCopy(resolvedImagePath).empty()
            ? ks::startup::normalizeFilePathText(entry.commandText)
            : resolvedImagePath;
        entry.publisherText = ks::startup::queryPublisherTextByPath(entry.imagePathText);
        entry.canOpenFileLocation = !ks::str::trimCopy(entry.imagePathText).empty();
        entry.imagePathExists = fileExists(entry.imagePathText);
        entry.enabled = true;
    }

    // ProcessOutput contains captured stdout/stderr from a hidden child process.
    struct ProcessOutput
    {
        bool started = false;
        bool finished = false;
        DWORD exitCode = 0;
        DWORD errorCode = ERROR_SUCCESS;
        std::string stdoutText;
        std::string stderrText;
    };

    // appendPipeText drains available pipe bytes without blocking after process completion/timeout.
    void appendPipeText(HANDLE pipeHandle, std::string& outputText)
    {
        if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }
        while (true)
        {
            DWORD availableBytes = 0;
            if (::PeekNamedPipe(pipeHandle, nullptr, 0, nullptr, &availableBytes, nullptr) == FALSE || availableBytes == 0)
            {
                break;
            }
            std::vector<char> buffer(std::min<DWORD>(availableBytes, 8192));
            DWORD readBytes = 0;
            if (::ReadFile(pipeHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &readBytes, nullptr) == FALSE || readBytes == 0)
            {
                break;
            }
            outputText.append(buffer.data(), buffer.data() + readBytes);
        }
    }

    // runHiddenProcess executes one explicitly selected executable without PATH/CWD lookup.
    ProcessOutput runHiddenProcess(
        const std::wstring& applicationPath,
        const std::wstring& commandLine,
        DWORD timeoutMs)
    {
        ProcessOutput output;
        if (applicationPath.empty())
        {
            output.errorCode = ERROR_FILE_NOT_FOUND;
            return output;
        }
        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = TRUE;

        HANDLE stdinHandle = INVALID_HANDLE_VALUE;
        HANDLE stdoutRead = nullptr;
        HANDLE stdoutWrite = nullptr;
        HANDLE stderrRead = nullptr;
        HANDLE stderrWrite = nullptr;
        if (::CreatePipe(&stdoutRead, &stdoutWrite, &securityAttributes, 0) == FALSE ||
            ::CreatePipe(&stderrRead, &stderrWrite, &securityAttributes, 0) == FALSE)
        {
            output.errorCode = ::GetLastError();
            if (stdoutRead != nullptr) ::CloseHandle(stdoutRead);
            if (stdoutWrite != nullptr) ::CloseHandle(stdoutWrite);
            if (stderrRead != nullptr) ::CloseHandle(stderrRead);
            if (stderrWrite != nullptr) ::CloseHandle(stderrWrite);
            return output;
        }
        if (::SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) == FALSE
            || ::SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        stdinHandle = ::CreateFileW(
            L"NUL",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &securityAttributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (stdinHandle == INVALID_HANDLE_VALUE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        SIZE_T attributeListSize = 0;
        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
        std::vector<std::uint8_t> attributeListBuffer(attributeListSize);
        auto* attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attributeListBuffer.data());
        if (attributeListSize == 0
            || ::InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListSize) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdinHandle);
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }
        const std::array<HANDLE, 3> kInheritedHandles{
            stdinHandle,
            stdoutWrite,
            stderrWrite
        };
        if (::UpdateProcThreadAttribute(
                attributeList,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                const_cast<HANDLE*>(kInheritedHandles.data()),
                sizeof(kInheritedHandles),
                nullptr,
                nullptr) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::DeleteProcThreadAttributeList(attributeList);
            ::CloseHandle(stdinHandle);
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        STARTUPINFOEXW startupInfo{};
        startupInfo.StartupInfo.cb = sizeof(startupInfo);
        startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startupInfo.StartupInfo.wShowWindow = SW_HIDE;
        startupInfo.StartupInfo.hStdOutput = stdoutWrite;
        startupInfo.StartupInfo.hStdError = stderrWrite;
        startupInfo.StartupInfo.hStdInput = stdinHandle;
        startupInfo.lpAttributeList = attributeList;

        PROCESS_INFORMATION processInfo{};
        std::vector<wchar_t> commandBuffer(commandLine.begin(), commandLine.end());
        commandBuffer.push_back(L'\0');
        const std::wstring kApplicationDirectory =
            std::filesystem::path(applicationPath).parent_path().wstring();
        const BOOL kCreateOk = ::CreateProcessW(
            applicationPath.c_str(),
            commandBuffer.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr,
            kApplicationDirectory.empty() ? nullptr : kApplicationDirectory.c_str(),
            &startupInfo.StartupInfo,
            &processInfo);
        if (kCreateOk == FALSE)
        {
            output.errorCode = ::GetLastError();
        }
        ::DeleteProcThreadAttributeList(attributeList);
        ::CloseHandle(stdinHandle);
        ::CloseHandle(stdoutWrite);
        ::CloseHandle(stderrWrite);
        stdinHandle = INVALID_HANDLE_VALUE;
        stdoutWrite = nullptr;
        stderrWrite = nullptr;
        if (kCreateOk == FALSE)
        {
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stderrRead);
            return output;
        }

        output.started = true;
        const ULONGLONG kStartTick = ::GetTickCount64();
        DWORD waitResult = WAIT_TIMEOUT;
        while (true)
        {
            // Drain stdout/stderr while the child is running so large JSON output cannot fill
            // the inherited pipe and deadlock the PowerShell process before it exits.
            appendPipeText(stdoutRead, output.stdoutText);
            appendPipeText(stderrRead, output.stderrText);
            waitResult = ::WaitForSingleObject(processInfo.hProcess, 50);
            if (waitResult == WAIT_OBJECT_0)
            {
                break;
            }
            if (waitResult == WAIT_FAILED)
            {
                output.errorCode = ::GetLastError();
                break;
            }
            const ULONGLONG kElapsedMs = ::GetTickCount64() - kStartTick;
            if (kElapsedMs >= timeoutMs)
            {
                output.errorCode = WAIT_TIMEOUT;
                break;
            }
        }
        if (waitResult != WAIT_OBJECT_0)
        {
            ::TerminateProcess(processInfo.hProcess, 1);
            ::WaitForSingleObject(processInfo.hProcess, 1500);
        }
        output.finished = waitResult == WAIT_OBJECT_0;
        DWORD exitCode = ERROR_PROCESS_ABORTED;
        if (::GetExitCodeProcess(processInfo.hProcess, &exitCode) != FALSE)
        {
            output.exitCode = exitCode;
        }
        else if (output.errorCode == ERROR_SUCCESS)
        {
            const DWORD kExitCodeError = ::GetLastError();
            output.errorCode = kExitCodeError == ERROR_SUCCESS
                ? ERROR_GEN_FAILURE
                : kExitCodeError;
        }
        appendPipeText(stdoutRead, output.stdoutText);
        appendPipeText(stderrRead, output.stderrText);
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        ::CloseHandle(stdoutRead);
        ::CloseHandle(stderrRead);
        return output;
    }

    // processFailureCode preserves launch/wait failures and rejects a successful exit that did
    // not produce the expected protocol marker as malformed output.
    DWORD processFailureCode(const ProcessOutput& output)
    {
        if (output.errorCode != ERROR_SUCCESS)
        {
            return output.errorCode;
        }
        if (!output.started)
        {
            return ERROR_PROCESS_ABORTED;
        }
        if (!output.finished)
        {
            return WAIT_TIMEOUT;
        }
        if (output.exitCode != 0)
        {
            return output.exitCode;
        }
        return ERROR_INVALID_DATA;
    }

    // base64EncodeWideScript avoids command-line quoting bugs for complex PowerShell scripts.
    std::wstring base64EncodeWideScript(const std::wstring& scriptText)
    {
        static constexpr wchar_t kAlphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(scriptText.data());
        const std::size_t kByteCount = scriptText.size() * sizeof(wchar_t);
        std::wstring encoded;
        encoded.reserve(((kByteCount + 2) / 3) * 4);
        for (std::size_t index = 0; index < kByteCount; index += 3)
        {
            const std::uint32_t kB0 = bytes[index];
            const std::uint32_t kB1 = (index + 1 < kByteCount) ? bytes[index + 1] : 0;
            const std::uint32_t kB2 = (index + 2 < kByteCount) ? bytes[index + 2] : 0;
            encoded.push_back(kAlphabet[(kB0 >> 2) & 0x3F]);
            encoded.push_back(kAlphabet[((kB0 & 0x03) << 4) | ((kB1 >> 4) & 0x0F)]);
            encoded.push_back(index + 1 < kByteCount ? kAlphabet[((kB1 & 0x0F) << 2) | ((kB2 >> 6) & 0x03)] : L'=');
            encoded.push_back(index + 2 < kByteCount ? kAlphabet[kB2 & 0x3F] : L'=');
        }
        return encoded;
    }

    // trustedPowerShellPath resolves only the inbox Windows PowerShell under System32.
    std::wstring trustedPowerShellPath()
    {
        std::array<wchar_t, MAX_PATH + 1> systemDirectory{};
        const UINT kCharCount = ::GetSystemDirectoryW(
            systemDirectory.data(),
            static_cast<UINT>(systemDirectory.size()));
        if (kCharCount == 0 || kCharCount >= systemDirectory.size())
        {
            return std::wstring();
        }
        return (std::filesystem::path(systemDirectory.data())
            / L"WindowsPowerShell"
            / L"v1.0"
            / L"powershell.exe").wstring();
    }

    // runPowerShellScript runs an EncodedCommand script through the trusted inbox executable.
    ProcessOutput runPowerShellScript(const std::wstring& scriptText, DWORD timeoutMs)
    {
        const std::wstring kPowerShellPath = trustedPowerShellPath();
        if (kPowerShellPath.empty())
        {
            return ProcessOutput{};
        }
        const std::wstring kEncodedScript = base64EncodeWideScript(scriptText);
        const std::wstring kCommandLine = L"\"" + kPowerShellPath
            + L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
            + kEncodedScript;
        ProcessOutput output = runHiddenProcess(kPowerShellPath, kCommandLine, timeoutMs);
        // PowerShell scripts set OutputEncoding=UTF8; fall back to raw bytes if conversion is unnecessary.
        return output;
    }
}

// Every later block in this file was written against unqualified helper names; the using-directive
// keeps those call sites unchanged now that the helpers moved into ks::startup::detail.
using namespace ks::startup::detail;

namespace
{
    // JsonValue is a small JSON DOM sufficient for PowerShell ConvertTo-Json results.
    struct JsonValue
    {
        enum class Type
        {
            kNull,
            kBool,
            kNumber,
            kString,
            kArray,
            kObject
        };

        Type type = Type::kNull;
        bool boolValue = false;
        double numberValue = 0.0;
        std::string stringValue;
        std::vector<JsonValue> arrayValue;
        std::map<std::string, JsonValue> objectValue;
    };

    // appendUtf8CodePoint writes one Unicode scalar to a UTF-8 string.
    void appendUtf8CodePoint(std::string& text, std::uint32_t codePoint)
    {
        if (codePoint <= 0x7F)
        {
            text.push_back(static_cast<char>(codePoint));
        }
        else if (codePoint <= 0x7FF)
        {
            text.push_back(static_cast<char>(0xC0 | ((codePoint >> 6) & 0x1F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0xFFFF)
        {
            text.push_back(static_cast<char>(0xE0 | ((codePoint >> 12) & 0x0F)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else
        {
            text.push_back(static_cast<char>(0xF0 | ((codePoint >> 18) & 0x07)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    // JsonParser implements the small subset of RFC 8259 needed by PowerShell JSON output.
    class JsonParser
    {
    public:
        explicit JsonParser(std::string_view text) : text_(text) {}

        // Parse reads a single JSON value and ignores trailing whitespace.
        bool parse(JsonValue& valueOut)
        {
            skipWhitespace();
            if (!parseValue(valueOut))
            {
                return false;
            }
            skipWhitespace();
            return offset_ == text_.size();
        }

    private:
        // skipWhitespace advances over JSON insignificant whitespace.
        void skipWhitespace()
        {
            while (offset_ < text_.size())
            {
                const unsigned char kCh = static_cast<unsigned char>(text_[offset_]);
                if (kCh != ' ' && kCh != '\t' && kCh != '\r' && kCh != '\n')
                {
                    break;
                }
                ++offset_;
            }
        }

        // Consume checks and advances one expected byte.
        bool consume(char expected)
        {
            if (offset_ >= text_.size() || text_[offset_] != expected)
            {
                return false;
            }
            ++offset_;
            return true;
        }

        // parseValue dispatches by the current leading token.
        bool parseValue(JsonValue& valueOut)
        {
            skipWhitespace();
            if (offset_ >= text_.size())
            {
                return false;
            }
            const char kCh = text_[offset_];
            if (kCh == '"')
            {
                valueOut.type = JsonValue::Type::kString;
                return parseString(valueOut.stringValue);
            }
            if (kCh == '{')
            {
                return parseObject(valueOut);
            }
            if (kCh == '[')
            {
                return parseArray(valueOut);
            }
            if (kCh == 't' || kCh == 'f')
            {
                return parseBool(valueOut);
            }
            if (kCh == 'n')
            {
                return parseNull(valueOut);
            }
            return parseNumber(valueOut);
        }

        // parseHex4 decodes a JSON \uXXXX escape sequence.
        bool parseHex4(std::uint32_t& valueOut)
        {
            if (offset_ + 4 > text_.size())
            {
                return false;
            }
            std::uint32_t value = 0;
            for (int index = 0; index < 4; ++index)
            {
                const char kCh = text_[offset_++];
                value <<= 4;
                if (kCh >= '0' && kCh <= '9') value |= static_cast<std::uint32_t>(kCh - '0');
                else if (kCh >= 'a' && kCh <= 'f') value |= static_cast<std::uint32_t>(kCh - 'a' + 10);
                else if (kCh >= 'A' && kCh <= 'F') value |= static_cast<std::uint32_t>(kCh - 'A' + 10);
                else return false;
            }
            valueOut = value;
            return true;
        }

        // parseString handles ordinary JSON escapes and UTF-16 surrogate pairs.
        bool parseString(std::string& textOut)
        {
            if (!consume('"'))
            {
                return false;
            }
            std::string result;
            while (offset_ < text_.size())
            {
                const char kCh = text_[offset_++];
                if (kCh == '"')
                {
                    textOut = std::move(result);
                    return true;
                }
                if (kCh != '\\')
                {
                    result.push_back(kCh);
                    continue;
                }
                if (offset_ >= text_.size())
                {
                    return false;
                }
                const char kEsc = text_[offset_++];
                switch (kEsc)
                {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u':
                {
                    std::uint32_t codePoint = 0;
                    if (!parseHex4(codePoint))
                    {
                        return false;
                    }
                    if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                    {
                        const std::size_t kSavedOffset = offset_;
                        if (offset_ + 2 <= text_.size() && text_[offset_] == '\\' && text_[offset_ + 1] == 'u')
                        {
                            offset_ += 2;
                            std::uint32_t lowSurrogate = 0;
                            if (parseHex4(lowSurrogate) && lowSurrogate >= 0xDC00 && lowSurrogate <= 0xDFFF)
                            {
                                codePoint = 0x10000 + (((codePoint - 0xD800) << 10) | (lowSurrogate - 0xDC00));
                            }
                            else
                            {
                                offset_ = kSavedOffset;
                            }
                        }
                    }
                    appendUtf8CodePoint(result, codePoint);
                    break;
                }
                default:
                    return false;
                }
            }
            return false;
        }

        // parseObject reads a string-keyed JSON object.
        bool parseObject(JsonValue& valueOut)
        {
            if (!consume('{'))
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::kObject;
            skipWhitespace();
            if (consume('}'))
            {
                return true;
            }
            while (true)
            {
                skipWhitespace();
                std::string key;
                if (!parseString(key))
                {
                    return false;
                }
                skipWhitespace();
                if (!consume(':'))
                {
                    return false;
                }
                JsonValue child;
                if (!parseValue(child))
                {
                    return false;
                }
                valueOut.objectValue.emplace(std::move(key), std::move(child));
                skipWhitespace();
                if (consume('}'))
                {
                    return true;
                }
                if (!consume(','))
                {
                    return false;
                }
            }
        }

        // parseArray reads an ordered JSON array.
        bool parseArray(JsonValue& valueOut)
        {
            if (!consume('['))
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::kArray;
            skipWhitespace();
            if (consume(']'))
            {
                return true;
            }
            while (true)
            {
                JsonValue child;
                if (!parseValue(child))
                {
                    return false;
                }
                valueOut.arrayValue.push_back(std::move(child));
                skipWhitespace();
                if (consume(']'))
                {
                    return true;
                }
                if (!consume(','))
                {
                    return false;
                }
            }
        }

        // parseBool reads true/false literals.
        bool parseBool(JsonValue& valueOut)
        {
            if (text_.substr(offset_, 4) == "true")
            {
                valueOut = JsonValue{};
                valueOut.type = JsonValue::Type::kBool;
                valueOut.boolValue = true;
                offset_ += 4;
                return true;
            }
            if (text_.substr(offset_, 5) == "false")
            {
                valueOut = JsonValue{};
                valueOut.type = JsonValue::Type::kBool;
                valueOut.boolValue = false;
                offset_ += 5;
                return true;
            }
            return false;
        }

        // parseNull reads the null literal.
        bool parseNull(JsonValue& valueOut)
        {
            if (text_.substr(offset_, 4) != "null")
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::kNull;
            offset_ += 4;
            return true;
        }

        // parseNumber stores the double form and keeps exact display through jsonValueToText when needed.
        bool parseNumber(JsonValue& valueOut)
        {
            const std::size_t kStart = offset_;
            if (offset_ < text_.size() && text_[offset_] == '-')
            {
                ++offset_;
            }
            while (offset_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[offset_])))
            {
                ++offset_;
            }
            if (offset_ < text_.size() && text_[offset_] == '.')
            {
                ++offset_;
                while (offset_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[offset_])))
                {
                    ++offset_;
                }
            }
            if (offset_ < text_.size() && (text_[offset_] == 'e' || text_[offset_] == 'E'))
            {
                ++offset_;
                if (offset_ < text_.size() && (text_[offset_] == '+' || text_[offset_] == '-'))
                {
                    ++offset_;
                }
                while (offset_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[offset_])))
                {
                    ++offset_;
                }
            }
            if (offset_ == kStart)
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::kNumber;
            valueOut.numberValue = std::strtod(std::string(text_.substr(kStart, offset_ - kStart)).c_str(), nullptr);
            return true;
        }

        std::string_view text_;
        std::size_t offset_ = 0;
    };

    // jsonValueToText produces the display string used by StartupEntry fields.
    std::string jsonValueToText(const JsonValue& value)
    {
        switch (value.type)
        {
        case JsonValue::Type::kString:
            return ks::str::trimCopy(value.stringValue);
        case JsonValue::Type::kNumber:
        {
            std::ostringstream stream;
            stream << value.numberValue;
            return stream.str();
        }
        case JsonValue::Type::kBool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::kNull:
            return std::string();
        case JsonValue::Type::kArray:
        {
            std::vector<std::string> parts;
            for (const JsonValue& child : value.arrayValue)
            {
                parts.push_back(jsonValueToText(child));
            }
            return joinStrings(parts, " | ");
        }
        case JsonValue::Type::kObject:
            return "<object>";
        }
        return std::string();
    }

    // getJsonField returns a named object field as display text, or empty for absent fields.
    std::string getJsonField(const JsonValue& objectValue, const std::string& key)
    {
        if (objectValue.type != JsonValue::Type::kObject)
        {
            return std::string();
        }
        const auto kFieldIt = objectValue.objectValue.find(key);
        if (kFieldIt == objectValue.objectValue.end())
        {
            return std::string();
        }
        return jsonValueToText(kFieldIt->second);
    }

    // stripUtf8Bom removes a leading UTF-8 BOM because Windows PowerShell may emit it before JSON.
    std::string stripUtf8Bom(std::string text)
    {
        if (text.size() >= 3 &&
            static_cast<unsigned char>(text[0]) == 0xEF &&
            static_cast<unsigned char>(text[1]) == 0xBB &&
            static_cast<unsigned char>(text[2]) == 0xBF)
        {
            text.erase(0, 3);
        }
        return text;
    }

    // parseJsonObjects normalizes a single JSON object or an array of objects into a vector.
    std::vector<JsonValue> parseJsonObjects(const std::string& jsonText, bool* parseOkOut)
    {
        std::vector<JsonValue> objects;
        JsonValue root;
        JsonParser parser(jsonText);
        const bool kParseOk = parser.parse(root);
        if (parseOkOut != nullptr)
        {
            *parseOkOut = kParseOk;
        }
        if (!kParseOk)
        {
            return objects;
        }
        if (root.type == JsonValue::Type::kObject)
        {
            objects.push_back(std::move(root));
        }
        else if (root.type == JsonValue::Type::kArray)
        {
            for (JsonValue& value : root.arrayValue)
            {
                if (value.type == JsonValue::Type::kObject)
                {
                    objects.push_back(std::move(value));
                }
            }
        }
        return objects;
    }
}

namespace
{
    // RunKeySpec describes Run/RunOnce style locations whose values are startup commands.
    struct RunKeySpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // SingleValueSpec describes a fixed key/value startup persistence source.
    struct SingleValueSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const wchar_t* valueNameText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
    };

    // ValueEnumSpec describes a key where every value can represent a persistence item.
    struct ValueEnumSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
        bool resolveClsidFromValueName = false;
    };

    // SubKeyValueSpec describes sources where subkeys are enumerated and one value is read from each.
    struct SubKeyValueSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const wchar_t* valueNameText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
        bool resolveClsidFromSubKeyName = false;
        bool deleteRegistryTree = false;
    };

    // buildRunKeySpecList centralizes logon registry coverage.
    const std::array<RunKeySpec, 21>& buildRunKeySpecList()
    {
        static const std::array<RunKeySpec, 21> kSpecs{ {
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", L"当前用户", L"用户登录后自动运行" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", L"当前用户", L"当前用户一次性登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices", L"当前用户", L"兼容性 RunServices 登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce", L"当前用户", L"兼容性 RunServicesOnce 登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun", L"当前用户", L"策略控制的登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "WindowsRun", L"当前用户", L"Windows 兼容 Run/Load 位置" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Command Processor", "CommandProcessorAutorun", L"当前用户", L"命令行解释器 Autorun" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", L"本机", L"系统级登录后自动运行" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", L"本机", L"系统级一次性登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices", L"本机", L"兼容性 RunServices 登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce", L"本机", L"兼容性 RunServicesOnce 登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun", L"本机", L"策略控制的登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "WindowsRun", L"本机", L"Windows 兼容 Run/Load 位置" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Command Processor", "CommandProcessorAutorun", L"本机", L"命令行解释器 Autorun" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "TerminalServerRun", L"本机", L"终端服务安装模式 Run" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "TerminalServerRunOnce", L"本机", L"终端服务安装模式 RunOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run32", L"本机(32位)", L"32 位视图 Run" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce32", L"本机(32位)", L"32 位视图 RunOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices32", L"本机(32位)", L"32 位视图 RunServices" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce32", L"本机(32位)", L"32 位视图 RunServicesOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun32", L"本机(32位)", L"32 位视图策略 Run" }
        } };
        return kSpecs;
    }

    // buildSingleValueSpecList centralizes fixed-value advanced registry persistence coverage.
    const std::array<SingleValueSpec, 92>& buildSingleValueSpecList()
    {
        static const std::array<SingleValueSpec, 92> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", "WinlogonShell", L"本机", L"Winlogon Shell", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", "WinlogonUserinit", L"本机", L"Winlogon Userinit", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Taskman", "WinlogonTaskman", L"本机", L"Winlogon Taskman", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"VmApplet", "WinlogonVmApplet", L"本机", L"Winlogon VM Applet", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"GinaDLL", "WinlogonGinaDll", L"本机", L"旧式 GINA 登录 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AppSetup", "WinlogonAppSetup", L"本机", L"Winlogon AppSetup", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", "UserWinlogonShell", L"当前用户", L"用户级 Winlogon Shell", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", "UserWinlogonUserinit", L"当前用户", L"用户级 Winlogon Userinit", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", "AppInitDlls", L"本机", L"AppInit DLL 列表", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", "AppInitDlls32", L"本机(32位)", L"32 位 AppInit DLL 列表", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", "LsaAuthPackages", L"本机", L"LSA 认证包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Security Packages", "LsaSecurityPackages", L"本机", L"LSA 安全包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", "LsaNotificationPackages", L"本机", L"LSA 通知包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages", "LsaOsConfigSecurityPackages", L"本机", L"LSA OSConfig 安全包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", "BootExecute", L"本机", L"会话管理器启动前执行命令", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"SetupExecute", "SetupExecute", L"本机", L"会话管理器 SetupExecute", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"Execute", "SessionManagerExecute", L"本机", L"会话管理器 Execute", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"Shell", "PoliciesSystemShell", L"本机", L"策略指定系统 Shell", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Load", "WindowsLoad", L"当前用户", L"Windows 兼容 Load", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Load", "MachineWindowsLoad", L"本机", L"系统级 Windows Load", false },
            // Boot and session bring-up: these run before, or instead of, the normal logon chain.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SafeBoot", L"AlternateShell", "SafeBootAlternateShell", L"本机", L"安全模式备用 Shell", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"S0InitialCommand", "S0InitialCommand", L"本机", L"会话管理器 S0InitialCommand", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\BootVerificationProgram", L"ImagePath", "BootVerificationProgram", L"本机", L"引导验证程序", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd", L"StartupPrograms", "TerminalServerStartupPrograms", L"本机", L"远程桌面会话启动程序", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"InitialProgram", "TerminalServerInitialProgram", L"本机", L"远程桌面初始程序", false },
            // Winlogon slots that are not Shell/Userinit and therefore easy to overlook.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"mpnotify", "WinlogonMpNotify", L"本机", L"Winlogon 多重通知程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"System", "WinlogonSystem", L"本机", L"Winlogon System 登录执行项", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"IconServiceLib", "IconServiceLib", L"本机", L"图标服务库", false },
            // Authentication and networking providers loaded into long-lived system processes.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SecurityProviders", L"SecurityProviders", "SecurityProviders", L"本机", L"安全支持提供程序列表", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters", L"AutodialDLL", "AutodialDll", L"本机", L"自动拨号 DLL", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\NetworkProvider\\Order", L"ProviderOrder", "NetworkProviderOrder", L"本机", L"网络提供程序顺序", false },
            // Crash and hang handlers: a debugger here is executed whenever the trigger fires.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", L"Debugger", "AeDebug", L"本机", L"崩溃即时调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", L"Debugger", "AeDebug32", L"本机(32位)", L"32 位崩溃即时调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", L"Debugger", "WerHangsDebugger", L"本机", L"无响应进程调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", L"ReflectDebugger", "WerReflectDebugger", L"本机", L"无响应进程镜像调试器", false },
            // Per-user logon hooks that need no administrative rights to install.
            { HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript", "UserInitMprLogonScript", L"当前用户", L"用户登录脚本", false },
            { HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE", "ScreenSaver", L"当前用户", L"屏幕保护程序", false },
            // The undocumented Office test key loads a DLL into every Office application.
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTest", L"当前用户", L"Office Test 加载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTestMachine", L"本机", L"Office Test 加载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTest32", L"本机(32位)", L"32 位 Office Test 加载 DLL", false },
            // .NET profiler environment variables load an arbitrary DLL into every managed process.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_ENABLE_PROFILING", "DotNetProfilerEnableMachine", L"本机", L".NET 分析器开关", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_PROFILER", "DotNetProfilerClsidMachine", L"本机", L".NET 分析器 CLSID", true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_PROFILER_PATH", "DotNetProfilerPathMachine", L"本机", L".NET 分析器 DLL 路径", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_ENABLE_PROFILING", "CoreClrProfilerEnableMachine", L"本机", L".NET Core 分析器开关", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_PROFILER", "CoreClrProfilerClsidMachine", L"本机", L".NET Core 分析器 CLSID", true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_PROFILER_PATH", "CoreClrProfilerPathMachine", L"本机", L".NET Core 分析器 DLL 路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"COR_ENABLE_PROFILING", "DotNetProfilerEnableUser", L"当前用户", L".NET 分析器开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"COR_PROFILER", "DotNetProfilerClsidUser", L"当前用户", L".NET 分析器 CLSID", true },
            { HKEY_CURRENT_USER, L"Environment", L"COR_PROFILER_PATH", "DotNetProfilerPathUser", L"当前用户", L".NET 分析器 DLL 路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_ENABLE_PROFILING", "CoreClrProfilerEnableUser", L"当前用户", L".NET Core 分析器开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_PROFILER", "CoreClrProfilerClsidUser", L"当前用户", L".NET Core 分析器 CLSID", true },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_PROFILER_PATH", "CoreClrProfilerPathUser", L"当前用户", L".NET Core 分析器 DLL 路径", false },
            // AppDomainManager hijacking is configured through these two managed-runtime variables.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPDOMAIN_MANAGER_ASM", "AppDomainManagerAsmMachine", L"本机", L"AppDomainManager 程序集", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPDOMAIN_MANAGER_TYPE", "AppDomainManagerTypeMachine", L"本机", L"AppDomainManager 类型", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPDOMAIN_MANAGER_ASM", "AppDomainManagerAsmUser", L"当前用户", L"AppDomainManager 程序集", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPDOMAIN_MANAGER_TYPE", "AppDomainManagerTypeUser", L"当前用户", L"AppDomainManager 类型", false },
            // Additional debugger and DLL slots that no mainstream autostart tool inspects.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebugProtected", L"Debugger", "AeDebugProtected", L"本机", L"受保护进程崩溃调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebugProtected", L"Debugger", "AeDebugProtected32", L"本机(32位)", L"32 位受保护进程崩溃调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Cryptography\\Offload", L"ExpoOffload", "CryptoExpoOffload", L"本机", L"加密运算卸载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Terminal Server Client", L"ClxDllPath", "RdpClxDll", L"本机", L"远程桌面客户端扩展 DLL", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\TestDVCPlugin", L"Path", "RdpTestDvcPlugin", L"本机", L"远程桌面动态虚拟通道测试插件", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\SEMgr\\Wallet", L"DllName", "SeMgrWallet", L"本机", L"安全元件钱包 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PushRouter\\Test", L"TestDllPath2", "PushRouterTestDll", L"本机", L"推送路由测试 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\WSMAN", L"NitsInjector", "WsmanNitsInjector", L"本机", L"WSMAN 注入测试 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\AirDrop", L"DllName", "AirDropDll", L"本机", L"AirDrop 组件 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Test", L"AdmParseLibrary", "GroupPolicyAdmParser", L"本机", L"组策略模板解析库", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\PeerDist\\Extension", L"PeerdistDllName", "PeerDistExtension", L"本机", L"对等分发扩展 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Test", L"EventerHookDll", "WindowsUpdateTestHook", L"本机", L"Windows 更新测试钩子 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Setup\\Pending", L"SPReviewEnabler", "SetupPendingReview", L"本机", L"安装挂起复查程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Console", L"ConsoleIME", "ConsoleIme", L"本机", L"控制台输入法程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\SideBySide", L"PreferExternalManifest", "PreferExternalManifest", L"本机", L"优先使用外部清单开关", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Direct3D", L"LoadDebugRuntime", "Direct3DDebugRuntime", L"本机", L"Direct3D 调试运行时开关", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"RunGrpConv", "WinlogonRunGrpConv", L"当前用户", L"登录时运行组转换程序", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\HtmlHelp Author", L"location", "HtmlHelpAuthor", L"当前用户", L"HTML 帮助作者 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\TestHooks", L"TestAggregatorDll", "DiagTrackTestHook", L"本机", L"遥测聚合器测试 DLL", false },
            { HKEY_CURRENT_USER, L"Environment", L"UserInitLogonScript", "UserInitLogonScript", L"当前用户", L"用户登录脚本变量", false },
            { HKEY_CURRENT_USER, L"Environment", L"UserInitLogonServer", "UserInitLogonServer", L"当前用户", L"用户登录脚本服务器", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Radio Support", L"SupportDLL", "BluetoothRadioSupport", L"本机", L"蓝牙无线电支持 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\ServerCore\\Shell Launcher", L"Shell", "ServerCoreShellLauncher", L"本机", L"Server Core 外壳启动器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer", L"MicrosoftRedirectionProgram", "EventViewerRedirection", L"本机", L"事件查看器帮助重定向程序", false },
            // Runtime injection variables honoured by managed, Java, CUDA and OpenSSL loaders.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"JAVA_TOOL_OPTIONS", "JavaToolOptionsMachine", L"本机", L"Java 工具选项注入", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"_JAVA_OPTIONS", "JavaOptionsMachine", L"本机", L"Java 选项注入", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CUDA_INJECTION64_PATH", "CudaInjectionMachine", L"本机", L"CUDA 注入库路径", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"INTEL_LIBITTNOTIFY64", "IntelIttNotifyMachine", L"本机", L"Intel ITT 通知库", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"OPENSSL_MODULES", "OpenSslModulesMachine", L"本机", L"OpenSSL 模块目录", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPX_PROCESS", "AppxProcessMachine", L"本机", L"AppX 运行时加载开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"JAVA_TOOL_OPTIONS", "JavaToolOptionsUser", L"当前用户", L"Java 工具选项注入", false },
            { HKEY_CURRENT_USER, L"Environment", L"_JAVA_OPTIONS", "JavaOptionsUser", L"当前用户", L"Java 选项注入", false },
            { HKEY_CURRENT_USER, L"Environment", L"CUDA_INJECTION64_PATH", "CudaInjectionUser", L"当前用户", L"CUDA 注入库路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"INTEL_LIBITTNOTIFY64", "IntelIttNotifyUser", L"当前用户", L"Intel ITT 通知库", false },
            { HKEY_CURRENT_USER, L"Environment", L"OPENSSL_MODULES", "OpenSslModulesUser", L"当前用户", L"OpenSSL 模块目录", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPX_PROCESS", "AppxProcessUser", L"当前用户", L"AppX 运行时加载开关", false }
        } };
        return kSpecs;
    }

    // buildValueEnumSpecList centralizes advanced registry keys where all values are inspected.
    const std::array<ValueEnumSpec, 35>& buildValueEnumSpecList()
    {
        static const std::array<ValueEnumSpec, 35> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", "ShellExecuteHooks", L"本机", L"Explorer Shell Execute Hooks", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", "ShellExecuteHooksUser", L"当前用户", L"用户级 Explorer Shell Execute Hooks", true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", "SharedTaskScheduler", L"本机", L"Explorer Shared Task Scheduler", true, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad", "ShellDelayLoad", L"本机", L"Explorer 延迟加载 COM", true, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad", "ShellDelayLoadUser", L"当前用户", L"用户级 Explorer 延迟加载 COM", true, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", "ShellExtensionsApproved", L"本机", L"Shell 扩展白名单", false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", "ShellExtensionsApprovedUser", L"当前用户", L"用户级 Shell 扩展白名单", false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\URLSearchHooks", "IEUrlSearchHooks", L"本机", L"Internet Explorer URL Search Hooks", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\URLSearchHooks", "IEUrlSearchHooksUser", L"当前用户", L"用户级 URL Search Hooks", true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\Toolbar", "IEToolbar", L"本机", L"Internet Explorer Toolbar", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Toolbar", "IEToolbarUser", L"当前用户", L"用户级 Internet Explorer Toolbar", true, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", "AppCertDlls", L"本机", L"AppCert DLL 注入点", false, false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", "KnownDlls", L"本机", L"Known DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs32", "KnownDlls32", L"本机", L"32 位 Known DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32", "Drivers32", L"本机", L"系统解码器/媒体驱动", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32", "Drivers32Wow64", L"本机(32位)", L"32 位解码器/媒体驱动", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRoot", L"本机", L"RunOnceEx 根键直接值", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRootUser", L"当前用户", L"用户级 RunOnceEx 根键直接值", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRoot32", L"本机(32位)", L"32 位 RunOnceEx 根键直接值", false, false },
            // Font drivers and netsh helpers are DLL lists loaded by long-lived system components.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Font Drivers", "FontDrivers", L"本机", L"字体驱动列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Netsh", "NetshHelper", L"本机", L"netsh 助手 DLL", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Netsh", "NetshHelper32", L"本机(32位)", L"32 位 netsh 助手 DLL", false, false },
            // WER loads these modules into a crashing process before the report is produced.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\RuntimeExceptionHelperModules", "WerRuntimeExceptionHelper", L"本机", L"WER 运行时异常助手模块", false, false },
            // StartupApproved records which logon items were switched off outside this tool.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", "StartupApprovedRun", L"本机", L"登录项启用状态记录", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32", "StartupApprovedRun32", L"本机(32位)", L"32 位登录项启用状态记录", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder", "StartupApprovedFolder", L"本机", L"启动文件夹启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", "StartupApprovedRunUser", L"当前用户", L"登录项启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32", "StartupApprovedRun32User", L"当前用户", L"32 位登录项启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder", "StartupApprovedFolderUser", L"当前用户", L"启动文件夹启用状态记录", false, false },
            // DLL substitution lists consulted by the loader, the debugger and Explorer helpers.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Wow64\\x86", "Wow64x86Layer", L"本机", L"WOW64 x86 层 DLL 替换", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\KnownManagedDebuggingDlls", "KnownManagedDebuggingDlls", L"本机", L"托管调试 DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\MiniDumpAuxiliaryDlls", "MiniDumpAuxiliaryDlls", L"本机", L"小型转储辅助 DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer", "ExplorerMyComputerTools", L"本机", L"我的电脑工具路径", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\WirelessDocking\\DockingProviderDLLs", "WirelessDockingProviders", L"本机", L"无线扩展坞提供程序 DLL", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\MSDTC\\XADLL", "MsdtcXaDll", L"本机", L"MSDTC XA 事务 DLL", false, false }
        } };
        return kSpecs;
    }

    // buildSubKeyValueSpecList centralizes subkey-driven advanced registry persistence coverage.
    const std::array<SubKeyValueSpec, 56>& buildSubKeyValueSpecList()
    {
        static const std::array<SubKeyValueSpec, 56> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetup", L"本机", L"Active Setup StubPath", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"DLLName", "WinlogonNotify", L"本机", L"Winlogon Notify 包", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers", L"", "CredentialProvider", L"本机", L"Credential Provider", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters", L"", "CredentialProviderFilter", L"本机", L"Credential Provider Filter", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers", L"", "PlapProvider", L"本机", L"PLAP Provider", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO", L"本机", L"Browser Helper Object", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO-User", L"当前用户", L"用户级 Browser Helper Object", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\Explorer Bars", L"", "IEExplorerBar", L"本机", L"Internet Explorer Explorer Bar", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Explorer Bars", L"", "IEExplorerBar-User", L"当前用户", L"用户级 Explorer Bar", false, true, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Monitors", L"Driver", "PrintMonitor", L"本机", L"打印监视器驱动", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", "ShellIconOverlay", L"本机", L"Shell 图标覆盖标识符", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Sidebar\\Gadgets", L"Path", "SidebarGadget", L"本机", L"Sidebar Gadget 注册", false, false, true },
            // Service-hosted DLL providers: each subkey names a module a system service loads.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders", L"DllName", "TimeProvider", L"本机", L"时间提供程序", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions", L"DllName", "GroupPolicyExtension", L"本机", L"组策略客户端扩展", false, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors", L"Driver", "PrintProcessor", L"本机", L"打印处理器", false, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Environments\\Windows NT x86\\Print Processors", L"Driver", "PrintProcessor32", L"本机(32位)", L"32 位打印处理器", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\AMSI\\Providers", L"", "AmsiProvider", L"本机", L"AMSI 提供程序", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\TelemetryController", L"Command", "TelemetryController", L"本机", L"遥测控制器命令", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB", L"DatabasePath", "AppCompatShimDatabase", L"本机", L"已安装应用兼容性补丁库", false, false, true },
            // Protocol handlers are instantiated by Explorer, Office and every WinINet consumer.
            { HKEY_LOCAL_MACHINE, L"Software\\Classes\\Protocols\\Filter", L"CLSID", "ProtocolFilter", L"本机", L"协议过滤器", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Classes\\Protocols\\Handler", L"CLSID", "ProtocolHandler", L"本机", L"协议处理器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Classes\\Protocols\\Filter", L"CLSID", "ProtocolFilterUser", L"当前用户", L"用户级协议过滤器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Classes\\Protocols\\Handler", L"CLSID", "ProtocolHandlerUser", L"当前用户", L"用户级协议处理器", true, false, true },
            // Views of already-covered families that the previous table only checked in one hive.
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetup32", L"本机(32位)", L"32 位 Active Setup StubPath", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetupUser", L"当前用户", L"用户级 Active Setup StubPath", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", "ShellIconOverlayUser", L"当前用户", L"用户级 Shell 图标覆盖标识符", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO32", L"本机(32位)", L"32 位 Browser Helper Object", false, true, true },
            // Office add-ins load into a signed Microsoft host process on every document open.
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWordUser", L"当前用户", L"Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcelUser", L"当前用户", L"Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPointUser", L"当前用户", L"PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlookUser", L"当前用户", L"Outlook 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWord", L"本机", L"Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcel", L"本机", L"Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPoint", L"本机", L"PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlook", L"本机", L"Outlook 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWord32", L"本机(32位)", L"32 位 Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcel32", L"本机(32位)", L"32 位 Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPoint32", L"本机(32位)", L"32 位 PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlook32", L"本机(32位)", L"32 位 Outlook 加载项（子键名为 ProgID）", false, false, true },
            // Subkey-driven load points documented by persistence research but absent from Autoruns.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches", L"", "DiskCleanupHandler", L"本机", L"磁盘清理处理程序", true, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\MUI\\CallbackDlls", L"DllPath", "MuiCallbackDll", L"本机", L"MUI 回调 DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\IdentityStore\\Providers", L"ApPluginDLLPath", "IdentityStoreProvider", L"本机", L"标识存储提供程序 DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs", L"StartExe", "AccessibilityTool", L"本机", L"辅助功能工具", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\PostBootReminders", L"ShellExecute", "PostBootReminder", L"当前用户", L"启动后提醒程序", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey", L"ShellExecute", "AppKeyCommand", L"当前用户", L"多媒体按键命令", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Legacy CPL Map", L"ShellExecute", "LegacyCplMap", L"本机", L"旧式控制面板映射", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Active Setup\\Installed Components", L"RealStubPath", "ActiveSetupRealStubPath", L"本机", L"Active Setup 真实 StubPath", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Clients\\Mail", L"DLLPath", "MailClientDll", L"本机", L"邮件客户端 MAPI DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\VBA\\Monitors", L"CLSID", "VbaMonitor", L"本机", L"VBA 事件监视器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\VBA\\VBE\\6.0\\Addins", L"FriendlyName", "VbeAddin", L"当前用户", L"VBE 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\ALG\\ISV", L"", "AlgIsvPlugin", L"本机", L"应用层网关 ISV 插件", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Terminal Server Client\\Default\\Addins", L"Name", "RdpClientAddinUser", L"当前用户", L"远程桌面客户端插件", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Terminal Server Client\\Default\\Addins", L"Name", "RdpClientAddin", L"本机", L"远程桌面客户端插件", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\\Handlers", L"InvokeProgID", "AutoplayHandler", L"本机", L"自动播放处理程序", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\RunOnceEntries", L"", "InstallerRunOnceEntry", L"本机", L"Windows Installer 一次性执行项", false, false, true },
            // FailureCommand runs whenever the service crashes, which makes it a durable trigger.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", L"FailureCommand", "ServiceFailureCommand", L"本机", L"服务失败恢复命令", false, false, false }
        } };
        return kSpecs;
    }

    // appendValueBasedLogonEntry adapts a registry value under a Run-like key into StartupEntry.
    void appendValueBasedLogonEntry(std::vector<ks::startup::StartupEntry>& entries, const RunKeySpec& spec, const RegistryValueRecord& valueRecord)
    {
        if (ks::str::trimCopy(valueRecord.valueDataText).empty())
        {
            return;
        }
        const std::wstring kSubKeyText(spec.subKeyText);
        const std::string kLocationText = buildRegistryLocationText(spec.rootKey, kSubKeyText);
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::kLogon;
        entry.categoryText = ks::startup::categoryToText(entry.category);
        entry.itemNameText = ks::str::trimCopy(valueRecord.valueNameText).empty() ? fromWide(L"(\u9ed8\u8ba4\u503c)") : valueRecord.valueNameText;
        entry.locationText = kLocationText;
        entry.locationGroupText = kLocationText;
        entry.userText = fromWide(spec.userText);
        entry.sourceTypeText = spec.sourceTypeText;
        entry.detailText = fromWide(spec.detailText);
        entry.uniqueIdText = "REGLOGON|" + kLocationText + "|" + entry.itemNameText;
        finalizeRegistryEntry(entry, valueRecord.valueDataText, std::string(), valueRecord.valueNameText, false, false);
        const bool kPolicyManaged = lowerWideCopy(kSubKeyText).find(L"\\policies\\") != std::wstring::npos;
        const bool kMachineScope = spec.rootKey == HKEY_LOCAL_MACHINE;
        configureRegistryValueAction(
            entry,
            spec.rootKey,
            kSubKeyText,
            valueRecord,
            kPolicyManaged || kMachineScope
                ? ks::startup::StartupRiskLevel::kCritical
                : ks::startup::StartupRiskLevel::kElevated,
            kPolicyManaged ? "policy" : (kMachineScope ? "registry_machine" : "registry_user"),
            kPolicyManaged
                ? fromWide(L"策略管理的启动值允许修改，但系统策略可能立即将其恢复；继续前请确认影响范围。")
                : (kMachineScope
                    ? fromWide(L"修改机器范围启动值需要管理员权限，并会影响所有用户。")
                    : fromWide(L"修改前会保存原始注册表类型和数据；其他软件仍可能并发改写该值。")));
        entries.push_back(std::move(entry));
    }

    // appendRunOnceExEntries handles RunOnceEx subkey/value layout specially.
    void appendRunOnceExEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<RunKeySpec, 3> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx", L"本机", L"RunOnceEx 子键值" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExUser", L"当前用户", L"用户级 RunOnceEx 子键值" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx32", L"本机(32位)", L"32 位 RunOnceEx 子键值" }
        } };
        for (const RunKeySpec& spec : kSpecs)
        {
            const std::wstring kRootSubKey(spec.subKeyText);
            const std::string kGroupLocationText = buildRegistryLocationText(spec.rootKey, kRootSubKey);
            for (const std::wstring& subKeyName : enumerateRegistrySubKeys(spec.rootKey, kRootSubKey))
            {
                const std::wstring kItemSubKey = kRootSubKey + L"\\" + subKeyName;
                for (const RegistryValueRecord& valueRecord : enumerateRegistryValues(spec.rootKey, kItemSubKey))
                {
                    const std::string kValueName = ks::str::trimCopy(valueRecord.valueNameText);
                    if (ks::str::trimCopy(valueRecord.valueDataText).empty() || lowerAsciiCopy(kValueName) == "flags" || lowerAsciiCopy(kValueName) == "title")
                    {
                        continue;
                    }
                    const std::string kSubKeyNameText = fromWide(subKeyName);
                    ks::startup::StartupEntry entry;
                    entry.category = ks::startup::StartupCategory::kLogon;
                    entry.categoryText = ks::startup::categoryToText(entry.category);
                    entry.itemNameText = kValueName.empty()
                        ? kSubKeyNameText + fromWide(L"\\(\u9ed8\u8ba4\u503c)")
                        : kSubKeyNameText + "\\" + kValueName;
                    entry.locationText = buildRegistryLocationText(spec.rootKey, kItemSubKey);
                    entry.locationGroupText = kGroupLocationText;
                    entry.userText = fromWide(spec.userText);
                    entry.sourceTypeText = spec.sourceTypeText;
                    entry.detailText = fromWide(spec.detailText) + fromWide(L"\uff1b\u5b50\u952e=") + kSubKeyNameText;
                    entry.uniqueIdText = "RUNONCEEX|" + entry.locationText + "|" + entry.itemNameText;
                    finalizeRegistryEntry(entry, valueRecord.valueDataText, std::string(), valueRecord.valueNameText, false, false);
                    configureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        kItemSubKey,
                        valueRecord,
                        ks::startup::StartupRiskLevel::kElevated,
                        "unsupported_source",
                        fromWide(L"RunOnceEx 具有嵌套执行语义；修改单个值可能改变整组一次性启动命令的执行顺序。"));
                    entries.push_back(std::move(entry));
                }
            }
        }
    }

    // appendStartupFolderEntries enumerates per-user and machine Startup folders.
    void appendStartupFolderEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<std::pair<std::wstring, const wchar_t*>, 2> kFolders{ {
            { knownFolderPath(FOLDERID_Startup), L"当前用户" },
            { knownFolderPath(FOLDERID_CommonStartup), L"本机" }
        } };
        for (const auto& folder : kFolders)
        {
            if (folder.first.empty())
            {
                continue;
            }
            std::error_code ec;
            if (!std::filesystem::exists(folder.first, ec) || !std::filesystem::is_directory(folder.first, ec))
            {
                continue;
            }
            std::vector<std::filesystem::directory_entry> fileEntries;
            for (const auto& dirEntry : std::filesystem::directory_iterator(folder.first, ec))
            {
                const std::filesystem::file_status kLinkStatus = dirEntry.symlink_status(ec);
                if (!ec && !std::filesystem::is_directory(kLinkStatus))
                {
                    fileEntries.push_back(dirEntry);
                }
            }
            std::sort(fileEntries.begin(), fileEntries.end(), [](const auto& left, const auto& right) {
                return lowerWideCopy(left.path().filename().wstring()) < lowerWideCopy(right.path().filename().wstring());
            });
            for (const auto& fileEntry : fileEntries)
            {
                const std::string kFilePathText = toNativeSeparators(fromWide(fileEntry.path().wstring()));
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::kLogon;
                entry.categoryText = ks::startup::categoryToText(entry.category);
                entry.itemNameText = fromWide(fileEntry.path().filename().wstring());
                entry.commandText = kFilePathText;
                entry.imagePathText = kFilePathText;
                entry.publisherText = ks::startup::queryPublisherTextByPath(entry.imagePathText);
                entry.locationText = toNativeSeparators(fromWide(folder.first));
                entry.userText = fromWide(folder.second);
                entry.sourceTypeText = "StartupFolder";
                entry.detailText = fromWide(L"开始菜单启动文件夹");
                entry.enabled = true;
                FileIdentitySnapshot identity;
                DWORD identityError = ERROR_SUCCESS;
                const bool kIdentityValid = queryFileIdentityNoReparse(
                    fileEntry.path().wstring(),
                    identity,
                    identityError);
                entry.canOpenFileLocation = kIdentityValid;
                entry.canDelete = false;
                entry.imagePathExists = kIdentityValid;
                entry.uniqueIdText = "STARTUPFOLDER|" + kFilePathText;
                const bool kMachineScope = folder.second == std::wstring(L"\u672c\u673a");
                entry.actionKind = ks::startup::StartupActionKind::kStartupFolderFile;
                entry.actionLocator.originalFilePathText = kFilePathText;
                entry.actionLocator.fileIdentitySnapshotValid = kIdentityValid;
                entry.actionLocator.fileVolumeSerial = identity.volumeSerial;
                entry.actionLocator.fileIndex = identity.fileIndex;
                entry.actionLocator.fileSize = identity.fileSize;
                entry.actionLocator.fileLastWriteTime = identity.lastWriteTime;
                entry.canEnable = false;
                entry.canDisable = true;
                entry.riskLevel = kMachineScope || !kIdentityValid
                    ? ks::startup::StartupRiskLevel::kCritical
                    : ks::startup::StartupRiskLevel::kElevated;
                entry.riskReasonCode = kMachineScope ? "machine_scope" : "startup_folder";
                entry.riskReasonText = kMachineScope
                    ? fromWide(L"修改公共启动文件夹会影响所有用户，并且通常需要管理员权限。")
                    : (!kIdentityValid
                        ? fromWide(L"无法取得不跟随重解析点的稳定文件身份；继续操作可能移动链接目标或已变化的文件。")
                        : fromWide(L"文件会移动到 KSword 暂存目录；跨卷移动或并发文件操作仍可能失败。"));
                entry.canDelete = true;
                entry.lastErrorCode = kIdentityValid ? ERROR_SUCCESS : identityError;
                entries.push_back(std::move(entry));
            }
        }
    }

    // ScriptFileBase names the anchor a non-registry autostart path is resolved against.
    // Known folders are preferred over %ENV% so a poisoned environment cannot redirect the scan.
    enum class ScriptFileBase : int
    {
        kSystemRoot = 0, // %SystemRoot%: group policy scripts and machine-wide PowerShell profiles.
        kDocuments,      // Documents known folder: per-user PowerShell profiles (may be OneDrive-redirected).
        kRoamingAppData, // Roaming AppData: Office startup directories and VBA projects.
        kProgramFiles    // Program Files: PowerShell 7 machine-wide profiles.
    };

    // ScriptFileSpec describes one file-based autostart family that no registry key points at.
    struct ScriptFileSpec
    {
        ScriptFileBase baseKind = ScriptFileBase::kSystemRoot;
        const wchar_t* relativePathText = L""; // Path under the base; directory or single file.
        bool isDirectory = false;              // true: every file inside is an autostart payload.
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // buildScriptFileSpecList centralizes the file-based autostart families.
    // These execute without any Run key or scheduled task, which is exactly why they get missed.
    const std::array<ScriptFileSpec, 23>& buildScriptFileSpecList()
    {
        static const std::array<ScriptFileSpec, 23> kSpecs{ {
            // Group policy scripts run as SYSTEM at boot and as the user at logon.
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\Startup", true, "GpoStartupScript", L"本机", L"组策略计算机启动脚本" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\Shutdown", true, "GpoShutdownScript", L"本机", L"组策略计算机关机脚本" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\Logon", true, "GpoLogonScript", L"本机", L"组策略用户登录脚本" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\Logoff", true, "GpoLogoffScript", L"本机", L"组策略用户注销脚本" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\scripts.ini", false, "GpoScriptManifest", L"本机", L"组策略计算机脚本清单" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\psscripts.ini", false, "GpoPowerShellScriptManifest", L"本机", L"组策略计算机 PowerShell 脚本清单" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\scripts.ini", false, "GpoUserScriptManifest", L"本机", L"组策略用户脚本清单" },
            { ScriptFileBase::kSystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\psscripts.ini", false, "GpoUserPowerShellScriptManifest", L"本机", L"组策略用户 PowerShell 脚本清单" },
            // Every PowerShell profile runs on each interactive shell start.
            { ScriptFileBase::kSystemRoot, L"System32\\WindowsPowerShell\\v1.0\\profile.ps1", false, "PowerShellAllHostsProfile", L"本机", L"所有用户所有宿主 PowerShell 配置文件" },
            { ScriptFileBase::kSystemRoot, L"System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1", false, "PowerShellConsoleProfile", L"本机", L"所有用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::kSystemRoot, L"SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1", false, "PowerShellAllHostsProfile32", L"本机(32位)", L"32 位所有用户 PowerShell 配置文件" },
            { ScriptFileBase::kSystemRoot, L"SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1", false, "PowerShellConsoleProfile32", L"本机(32位)", L"32 位所有用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::kDocuments, L"WindowsPowerShell\\profile.ps1", false, "PowerShellUserAllHostsProfile", L"当前用户", L"用户所有宿主 PowerShell 配置文件" },
            { ScriptFileBase::kDocuments, L"WindowsPowerShell\\Microsoft.PowerShell_profile.ps1", false, "PowerShellUserConsoleProfile", L"当前用户", L"用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::kDocuments, L"PowerShell\\profile.ps1", false, "PwshUserAllHostsProfile", L"当前用户", L"用户 PowerShell 7 所有宿主配置文件" },
            { ScriptFileBase::kDocuments, L"PowerShell\\Microsoft.PowerShell_profile.ps1", false, "PwshUserConsoleProfile", L"当前用户", L"用户 PowerShell 7 控制台配置文件" },
            { ScriptFileBase::kProgramFiles, L"PowerShell\\7\\profile.ps1", false, "PwshAllHostsProfile", L"本机", L"PowerShell 7 所有用户配置文件" },
            { ScriptFileBase::kProgramFiles, L"PowerShell\\7\\Microsoft.PowerShell_profile.ps1", false, "PwshConsoleProfile", L"本机", L"PowerShell 7 所有用户控制台配置文件" },
            // Office loads these locations on every document open without any registry entry.
            { ScriptFileBase::kRoamingAppData, L"Microsoft\\Word\\STARTUP", true, "OfficeWordStartup", L"当前用户", L"Word 启动目录加载项" },
            { ScriptFileBase::kRoamingAppData, L"Microsoft\\Excel\\XLSTART", true, "OfficeExcelXlStart", L"当前用户", L"Excel 自动打开目录" },
            { ScriptFileBase::kRoamingAppData, L"Microsoft\\AddIns", true, "OfficeUserAddIns", L"当前用户", L"Office 用户加载项目录" },
            { ScriptFileBase::kRoamingAppData, L"Microsoft\\Outlook\\VbaProject.OTM", false, "OutlookVbaProject", L"当前用户", L"Outlook VBA 工程" },
            { ScriptFileBase::kRoamingAppData, L"Microsoft\\Templates\\Normal.dotm", false, "WordNormalTemplate", L"当前用户", L"Word 通用模板（可携带自动宏）" }
        } };
        return kSpecs;
    }

    // resolveScriptFileBase turns a base kind into an absolute directory, or empty when unavailable.
    std::wstring resolveScriptFileBase(const ScriptFileBase baseKind)
    {
        switch (baseKind)
        {
        case ScriptFileBase::kSystemRoot:
            return queryEnvironmentWide(L"SystemRoot");
        case ScriptFileBase::kDocuments:
            return knownFolderPath(FOLDERID_Documents);
        case ScriptFileBase::kRoamingAppData:
            return knownFolderPath(FOLDERID_RoamingAppData);
        case ScriptFileBase::kProgramFiles:
            return knownFolderPath(FOLDERID_ProgramFiles);
        }
        return std::wstring();
    }

    // appendScriptFileEntry adds one report-only record for a file-based autostart payload.
    // These files have no reversible backend operation: the enable/disable and delete paths only
    // accept the two known Startup folders, so revalidating them here would be a lie.
    void appendScriptFileEntry(
        std::vector<ks::startup::StartupEntry>& entries,
        const ScriptFileSpec& spec,
        const std::filesystem::path& filePath,
        const std::wstring& groupPathText)
    {
        const std::string kFilePathText = toNativeSeparators(fromWide(filePath.wstring()));
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::kLogon;
        entry.categoryText = ks::startup::categoryToText(entry.category);
        entry.itemNameText = fromWide(filePath.filename().wstring());
        entry.commandText = kFilePathText;
        entry.imagePathText = kFilePathText;
        entry.publisherText = ks::startup::queryPublisherTextByPath(entry.imagePathText);
        entry.locationText = toNativeSeparators(fromWide(groupPathText));
        entry.userText = fromWide(spec.userText);
        entry.sourceTypeText = spec.sourceTypeText;
        entry.detailText = fromWide(spec.detailText);
        entry.imagePathExists = true;
        entry.canOpenFileLocation = true;
        entry.uniqueIdText = "SCRIPTFILE|" + kFilePathText;
        markEntryActionUnavailable(
            entry,
            ks::startup::StartupRiskLevel::kCritical,
            "script_file",
            fromWide(L"脚本与加载项文件没有可逆的后端操作；请在确认内容后手工处理，删除组策略脚本还可能被策略刷新还原。"));
        entry.canOpenRegistryLocation = false;
        entries.push_back(std::move(entry));
    }

    // appendScriptFileEntries walks every file-based autostart family in the catalog.
    void appendScriptFileEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const ScriptFileSpec& spec : buildScriptFileSpecList())
        {
            const std::wstring kBaseText = resolveScriptFileBase(spec.baseKind);
            if (kBaseText.empty())
            {
                continue;
            }
            const std::filesystem::path kTargetPath =
                std::filesystem::path(kBaseText) / std::filesystem::path(spec.relativePathText);
            std::error_code errorCode;
            if (!spec.isDirectory)
            {
                // Single-file families: report the file only when it actually exists.
                if (std::filesystem::is_regular_file(kTargetPath, errorCode) && !errorCode)
                {
                    appendScriptFileEntry(entries, spec, kTargetPath, kTargetPath.parent_path().wstring());
                }
                continue;
            }
            if (!std::filesystem::is_directory(kTargetPath, errorCode) || errorCode)
            {
                continue;
            }
            // Directory families: every regular file inside is loaded, whatever its name.
            std::size_t reportedCount = 0;
            for (const auto& directoryEntry : std::filesystem::directory_iterator(kTargetPath, errorCode))
            {
                if (errorCode || reportedCount >= 64)
                {
                    break;
                }
                const std::filesystem::file_status kLinkStatus = directoryEntry.symlink_status(errorCode);
                if (errorCode || std::filesystem::is_directory(kLinkStatus))
                {
                    continue;
                }
                ++reportedCount;
                appendScriptFileEntry(entries, spec, directoryEntry.path(), kTargetPath.wstring());
            }
        }
    }

    // GroupPolicyScriptSpec describes one policy phase whose scripts live three levels deep.
    struct GroupPolicyScriptSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // appendGroupPolicyScriptEntries reads the policy script index that drives GPO script execution.
    // Layout: <phase>\{GPO GUID}\{index} with Script and Parameters values, so a flat table cannot
    // express it and the generic subkey walker would stop one level too early.
    void appendGroupPolicyScriptEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        static const std::array<GroupPolicyScriptSpec, 4> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup", "GpoScriptStartup", L"本机", L"组策略启动脚本注册" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown", "GpoScriptShutdown", L"本机", L"组策略关机脚本注册" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon", "GpoScriptLogon", L"当前用户", L"组策略登录脚本注册" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff", "GpoScriptLogoff", L"当前用户", L"组策略注销脚本注册" }
        } };

        for (const GroupPolicyScriptSpec& spec : kSpecs)
        {
            const std::wstring kPhaseSubKey(spec.subKeyText);
            const std::string kGroupLocationText = buildRegistryLocationText(spec.rootKey, kPhaseSubKey);
            for (const std::wstring& policyName : enumerateRegistrySubKeys(spec.rootKey, kPhaseSubKey))
            {
                const std::wstring kPolicySubKey = kPhaseSubKey + L"\\" + policyName;
                for (const std::wstring& indexName : enumerateRegistrySubKeys(spec.rootKey, kPolicySubKey))
                {
                    const std::wstring kItemSubKey = kPolicySubKey + L"\\" + indexName;
                    const auto kScriptRecord = queryRegistryValueRecord(spec.rootKey, kItemSubKey, L"Script");
                    if (!kScriptRecord.has_value() || ks::str::trimCopy(kScriptRecord->valueDataText).empty())
                    {
                        continue;
                    }
                    // Parameters are part of what actually executes, so they belong in the command text.
                    const auto kParameterRecord = queryRegistryValueRecord(spec.rootKey, kItemSubKey, L"Parameters");
                    std::string commandText = kScriptRecord->valueDataText;
                    if (kParameterRecord.has_value() && !ks::str::trimCopy(kParameterRecord->valueDataText).empty())
                    {
                        commandText += " " + kParameterRecord->valueDataText;
                    }
                    ks::startup::StartupEntry entry;
                    entry.category = ks::startup::StartupCategory::kRegistry;
                    entry.categoryText = ks::startup::categoryToText(entry.category);
                    entry.itemNameText = fromWide(policyName) + "\\" + fromWide(indexName);
                    entry.locationText = buildRegistryLocationText(spec.rootKey, kItemSubKey);
                    entry.locationGroupText = kGroupLocationText;
                    entry.userText = fromWide(spec.userText);
                    entry.sourceTypeText = spec.sourceTypeText;
                    entry.detailText = fromWide(spec.detailText);
                    entry.uniqueIdText = "GPOSCRIPT|" + entry.locationText;
                    finalizeRegistryEntry(
                        entry,
                        commandText,
                        std::string(),
                        kScriptRecord->valueNameText,
                        false,
                        false);
                    configureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        kItemSubKey,
                        *kScriptRecord,
                        ks::startup::StartupRiskLevel::kCritical,
                        "policy",
                        fromWide(L"组策略脚本由策略引擎下发；本地修改会在下一次策略刷新时被还原，应从策略源头处理。"));
                    entries.push_back(std::move(entry));
                }
            }
        }
    }
}

namespace
{
    // appendSingleValueEntries adds fixed key/value advanced registry records.
    void appendSingleValueEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const SingleValueSpec& spec : buildSingleValueSpecList())
        {
            const std::wstring kSubKeyText(spec.subKeyText);
            const std::wstring kValueNameText(spec.valueNameText);
            const auto kValueRecord = queryRegistryValueRecord(spec.rootKey, kSubKeyText, kValueNameText);
            if (!kValueRecord.has_value() || ks::str::trimCopy(kValueRecord->valueDataText).empty())
            {
                continue;
            }
            ks::startup::StartupEntry entry;
            entry.category = ks::startup::StartupCategory::kRegistry;
            entry.categoryText = ks::startup::categoryToText(entry.category);
            entry.itemNameText = kValueNameText.empty() ? fromWide(L"(\u9ed8\u8ba4\u503c)") : fromWide(kValueNameText);
            entry.locationText = buildRegistryLocationText(spec.rootKey, kSubKeyText);
            entry.locationGroupText = entry.locationText;
            entry.userText = fromWide(spec.userText);
            entry.sourceTypeText = spec.sourceTypeText;
            entry.detailText = fromWide(spec.detailText);
            entry.uniqueIdText = "SINGLE|" + entry.locationText + "|" + entry.itemNameText;
            finalizeRegistryEntry(entry, kValueRecord->valueDataText, std::string(), fromWide(kValueNameText), false, spec.resolveClsidFromValueData);
            const bool kPolicyManaged = lowerWideCopy(kSubKeyText).find(L"\\policies\\") != std::wstring::npos;
            configureRegistryValueAction(
                entry,
                spec.rootKey,
                kSubKeyText,
                *kValueRecord,
                ks::startup::StartupRiskLevel::kCritical,
                kPolicyManaged ? "policy" : "critical_registry",
                kPolicyManaged
                    ? fromWide(L"策略管理的注册表持久化项允许修改，但系统策略可能覆盖更改。")
                    : fromWide(L"此值属于 Winlogon、LSA 或会话管理器等关键启动路径；错误修改可能导致无法登录或系统异常。"));
            entries.push_back(std::move(entry));
        }
    }

    // appendValueEnumEntries adds one record for each non-empty value under known advanced keys.
    void appendValueEnumEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const ValueEnumSpec& spec : buildValueEnumSpecList())
        {
            const std::wstring kSubKeyText(spec.subKeyText);
            const std::string kLocationText = buildRegistryLocationText(spec.rootKey, kSubKeyText);
            for (const RegistryValueRecord& valueRecord : enumerateRegistryValues(spec.rootKey, kSubKeyText))
            {
                if (ks::str::trimCopy(valueRecord.valueDataText).empty())
                {
                    continue;
                }
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::kRegistry;
                entry.categoryText = ks::startup::categoryToText(entry.category);
                entry.itemNameText = ks::str::trimCopy(valueRecord.valueNameText).empty() ? fromWide(L"(\u9ed8\u8ba4\u503c)") : valueRecord.valueNameText;
                entry.locationText = kLocationText;
                entry.locationGroupText = kLocationText;
                entry.userText = fromWide(spec.userText);
                entry.sourceTypeText = spec.sourceTypeText;
                entry.detailText = fromWide(spec.detailText);
                entry.uniqueIdText = "VALUEENUM|" + kLocationText + "|" + entry.itemNameText;
                finalizeRegistryEntry(
                    entry,
                    valueRecord.valueDataText,
                    spec.resolveClsidFromValueName ? valueRecord.valueNameText : std::string(),
                    valueRecord.valueNameText,
                    false,
                    spec.resolveClsidFromValueData);
                configureRegistryValueAction(
                    entry,
                    spec.rootKey,
                    kSubKeyText,
                    valueRecord,
                    ks::startup::StartupRiskLevel::kCritical,
                    "critical_registry",
                    fromWide(L"此高级注册表持久化值允许修改；禁用后相关外壳、COM 或登录组件可能无法启动。"));
                entries.push_back(std::move(entry));
            }
        }
    }

    // appendSubKeyValueEntries adds records for subkey-driven advanced registry families.
    void appendSubKeyValueEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const SubKeyValueSpec& spec : buildSubKeyValueSpecList())
        {
            const std::wstring kRootSubKey(spec.subKeyText);
            const std::wstring kValueNameText(spec.valueNameText);
            const std::string kGroupLocationText = buildRegistryLocationText(spec.rootKey, kRootSubKey);
            for (const std::wstring& subKeyName : enumerateRegistrySubKeys(spec.rootKey, kRootSubKey))
            {
                const std::wstring kItemSubKey = kRootSubKey + L"\\" + subKeyName;
                const auto kValueRecord = queryRegistryValueRecord(spec.rootKey, kItemSubKey, kValueNameText);
                if (!kValueRecord.has_value() && !spec.resolveClsidFromSubKeyName)
                {
                    continue;
                }
                const std::string kSubKeyNameText = fromWide(subKeyName);
                std::string itemNameText = kSubKeyNameText;
                const std::string kClsidFallbackText = spec.resolveClsidFromSubKeyName ? kSubKeyNameText : std::string();
                const std::string kFriendlyNameText = queryClsidFriendlyName(kClsidFallbackText);
                if (!ks::str::trimCopy(kFriendlyNameText).empty())
                {
                    itemNameText = kFriendlyNameText;
                }
                std::string commandText = kValueRecord.has_value() ? kValueRecord->valueDataText : std::string();
                if (ks::str::trimCopy(commandText).empty() && spec.resolveClsidFromSubKeyName)
                {
                    commandText = kSubKeyNameText;
                }
                if (ks::str::trimCopy(commandText).empty())
                {
                    continue;
                }
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::kRegistry;
                entry.categoryText = ks::startup::categoryToText(entry.category);
                entry.itemNameText = itemNameText;
                entry.locationText = buildRegistryLocationText(spec.rootKey, kItemSubKey);
                entry.locationGroupText = kGroupLocationText;
                entry.userText = fromWide(spec.userText);
                entry.sourceTypeText = spec.sourceTypeText;
                entry.detailText = fromWide(spec.detailText) + fromWide(L"\uff1b\u5b50\u952e=") + kSubKeyNameText;
                entry.uniqueIdText = "SUBKEY|" + entry.locationText + "|" + fromWide(kValueNameText);
                finalizeRegistryEntry(
                    entry,
                    commandText,
                    kClsidFallbackText,
                    kValueRecord.has_value() ? kValueRecord->valueNameText : fromWide(kValueNameText),
                    spec.deleteRegistryTree,
                    spec.resolveClsidFromValueData);
                if (kValueRecord.has_value())
                {
                    configureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        kItemSubKey,
                        *kValueRecord,
                        ks::startup::StartupRiskLevel::kCritical,
                        "critical_registry",
                        fromWide(L"此基于子键的持久化值允许修改；禁用可能破坏对应 COM、外壳或登录扩展。"));
                }
                else
                {
                    entry.riskLevel = ks::startup::StartupRiskLevel::kCritical;
                    entry.riskReasonCode = "critical_registry";
                    entry.riskReasonText = fromWide(L"该持久化项由整个注册表子键表示；只能在不可恢复警告后永久删除。");
                }
                if (spec.deleteRegistryTree)
                {
                    configureRegistryTreeDeletion(entry, spec.rootKey, kItemSubKey);
                }
                entries.push_back(std::move(entry));
            }
        }
    }

    constexpr std::uint64_t kIfeoApplicationVerifierFlag = 0x100ULL;
    constexpr std::uint64_t kIfeoSilentProcessExitFlag = 0x200ULL;
    constexpr std::uint64_t kSilentExitLaunchMonitorProcessFlag = 0x1ULL;

    struct IfeoRegistryViewSpec
    {
        const wchar_t* rootSubKeyText = L"";
        const wchar_t* scopeText = L"";
        const char* identityText = "";
    };

    const std::array<IfeoRegistryViewSpec, 2>& buildIfeoRegistryViewSpecList()
    {
        static const std::array<IfeoRegistryViewSpec, 2> kSpecs{ {
            {
                L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                L"本机",
                "native"
            },
            {
                L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                L"本机(32位)",
                "wow64"
            }
        } };
        return kSpecs;
    }

    std::optional<std::uint64_t> parseRegistryUnsignedValue(const RegistryValueRecord& valueRecord)
    {
        if (valueRecord.valueType == REG_DWORD && valueRecord.rawData.size() >= sizeof(std::uint32_t))
        {
            std::uint32_t value = 0;
            std::memcpy(&value, valueRecord.rawData.data(), sizeof(value));
            return value;
        }
        if (valueRecord.valueType == REG_DWORD_BIG_ENDIAN && valueRecord.rawData.size() >= sizeof(std::uint32_t))
        {
            const auto* bytes = valueRecord.rawData.data();
            return (static_cast<std::uint64_t>(bytes[0]) << 24U)
                | (static_cast<std::uint64_t>(bytes[1]) << 16U)
                | (static_cast<std::uint64_t>(bytes[2]) << 8U)
                | static_cast<std::uint64_t>(bytes[3]);
        }
        if (valueRecord.valueType == REG_QWORD && valueRecord.rawData.size() >= sizeof(std::uint64_t))
        {
            std::uint64_t value = 0;
            std::memcpy(&value, valueRecord.rawData.data(), sizeof(value));
            return value;
        }

        const std::string kText = ks::str::trimCopy(valueRecord.valueDataText);
        if (kText.empty())
        {
            return std::nullopt;
        }
        const bool kHexadecimal = startsWithI(kText, "0x");
        const char* numberStart = kText.c_str() + (kHexadecimal ? 2 : 0);
        char* numberEnd = nullptr;
        errno = 0;
        const unsigned long long kValue = std::strtoull(numberStart, &numberEnd, kHexadecimal ? 16 : 10);
        if (numberEnd == numberStart || *numberEnd != '\0' || errno == ERANGE)
        {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(kValue);
    }

    bool registryFlagEnabled(
        const std::optional<RegistryValueRecord>& valueRecord,
        const std::uint64_t flagMask)
    {
        if (!valueRecord.has_value())
        {
            return false;
        }
        const auto kValue = parseRegistryUnsignedValue(*valueRecord);
        return kValue.has_value() && ((*kValue & flagMask) != 0ULL);
    }

    bool hasNonEmptyRegistryValue(const std::optional<RegistryValueRecord>& valueRecord)
    {
        return valueRecord.has_value()
            && !ks::str::trimCopy(valueRecord->valueDataText).empty();
    }

    std::string buildFilteredImageDisplayName(
        const std::wstring& imageName,
        const RegistryValueRecord& filterFullPathRecord)
    {
        std::string displayName = fromWide(imageName);
        const std::string kFilterFullPath = ks::str::trimCopy(filterFullPathRecord.valueDataText);
        if (!kFilterFullPath.empty())
        {
            displayName += " [" + kFilterFullPath + "]";
        }
        return displayName;
    }

    void appendImageHijackValueEntry(
        std::vector<ks::startup::StartupEntry>& entries,
        const std::wstring& itemSubKey,
        const std::wstring& groupSubKey,
        const std::string& imageDisplayName,
        const wchar_t* scopeText,
        const RegistryValueRecord& valueRecord,
        const char* sourceTypeText,
        const wchar_t* detailText,
        const bool active)
    {
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::kImageHijack;
        entry.categoryText = ks::startup::categoryToText(entry.category);
        entry.itemNameText = imageDisplayName;
        entry.locationText = buildRegistryLocationText(HKEY_LOCAL_MACHINE, itemSubKey);
        entry.locationGroupText = buildRegistryLocationText(HKEY_LOCAL_MACHINE, groupSubKey);
        entry.userText = fromWide(scopeText);
        entry.sourceTypeText = sourceTypeText;
        entry.detailText = fromWide(detailText);
        entry.uniqueIdText = "IMAGEHIJACK|" + entry.locationText + "|" + valueRecord.valueNameText;
        finalizeRegistryEntry(
            entry,
            valueRecord.valueDataText,
            std::string(),
            valueRecord.valueNameText,
            false,
            false);
        configureRegistryValueAction(
            entry,
            HKEY_LOCAL_MACHINE,
            itemSubKey,
            valueRecord,
            active
                ? ks::startup::StartupRiskLevel::kCritical
                : ks::startup::StartupRiskLevel::kElevated,
            "image_hijack",
            fromWide(L"映像劫持项能够在目标进程启动或退出时执行额外代码；禁用前请确认它不是受控调试或测试配置。"));
        entry.enabled = true;
        entries.push_back(std::move(entry));
    }

    void appendIfeoViewEntries(
        std::vector<ks::startup::StartupEntry>& entries,
        const IfeoRegistryViewSpec& viewSpec)
    {
        const std::wstring kRootSubKey(viewSpec.rootSubKeyText);
        for (const std::wstring& imageName : enumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, kRootSubKey))
        {
            const std::wstring kImageSubKey = kRootSubKey + L"\\" + imageName;
            const auto kGlobalFlagRecord = queryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                kImageSubKey,
                L"GlobalFlag");

            const auto kDebuggerRecord = queryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                kImageSubKey,
                L"Debugger");
            if (hasNonEmptyRegistryValue(kDebuggerRecord))
            {
                appendImageHijackValueEntry(
                    entries,
                    kImageSubKey,
                    kRootSubKey,
                    fromWide(imageName),
                    viewSpec.scopeText,
                    *kDebuggerRecord,
                    viewSpec.identityText[0] == 'w' ? "IFEO-Debugger32" : "IFEO-Debugger",
                    L"检测到 IFEO Debugger；目标进程启动时会先执行该命令。",
                    true);
            }

            const bool kVerifierEnabled = registryFlagEnabled(
                kGlobalFlagRecord,
                kIfeoApplicationVerifierFlag);
            const auto kVerifierDllsRecord = queryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                kImageSubKey,
                L"VerifierDlls");
            if (hasNonEmptyRegistryValue(kVerifierDllsRecord))
            {
                appendImageHijackValueEntry(
                    entries,
                    kImageSubKey,
                    kRootSubKey,
                    fromWide(imageName),
                    viewSpec.scopeText,
                    *kVerifierDllsRecord,
                    viewSpec.identityText[0] == 'w' ? "IFEO-VerifierDlls32" : "IFEO-VerifierDlls",
                    kVerifierEnabled
                        ? L"检测到已启用的 IFEO VerifierDlls；指定 DLL 会随目标进程加载。"
                        : L"检测到 IFEO VerifierDlls，但 GlobalFlag 未启用应用程序验证器。",
                    kVerifierEnabled);
            }

            const bool kUseFilterEnabled = registryFlagEnabled(
                queryRegistryValueRecord(HKEY_LOCAL_MACHINE, kImageSubKey, L"UseFilter"),
                0x1ULL);
            for (const std::wstring& filterName : enumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, kImageSubKey))
            {
                const std::wstring kFilterSubKey = kImageSubKey + L"\\" + filterName;
                const auto kFilterFullPathRecord = queryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    kFilterSubKey,
                    L"FilterFullPath");
                if (!hasNonEmptyRegistryValue(kFilterFullPathRecord))
                {
                    continue;
                }
                const std::string kFilteredDisplayName = buildFilteredImageDisplayName(
                    imageName,
                    *kFilterFullPathRecord);
                const auto kFilteredDebuggerRecord = queryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    kFilterSubKey,
                    L"Debugger");
                if (hasNonEmptyRegistryValue(kFilteredDebuggerRecord))
                {
                    appendImageHijackValueEntry(
                        entries,
                        kFilterSubKey,
                        kRootSubKey,
                        kFilteredDisplayName,
                        viewSpec.scopeText,
                        *kFilteredDebuggerRecord,
                        viewSpec.identityText[0] == 'w' ? "IFEO-FilteredDebugger32" : "IFEO-FilteredDebugger",
                        kUseFilterEnabled
                            ? L"检测到按完整路径生效的 IFEO Debugger。"
                            : L"检测到带 FilterFullPath 的 IFEO Debugger，但 UseFilter 未启用。",
                        kUseFilterEnabled);
                }

                const auto kFilteredGlobalFlagRecord = queryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    kFilterSubKey,
                    L"GlobalFlag");
                const bool kFilteredVerifierEnabled = kUseFilterEnabled
                    && (registryFlagEnabled(kFilteredGlobalFlagRecord, kIfeoApplicationVerifierFlag)
                        || kVerifierEnabled);
                const auto kFilteredVerifierDllsRecord = queryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    kFilterSubKey,
                    L"VerifierDlls");
                if (hasNonEmptyRegistryValue(kFilteredVerifierDllsRecord))
                {
                    appendImageHijackValueEntry(
                        entries,
                        kFilterSubKey,
                        kRootSubKey,
                        kFilteredDisplayName,
                        viewSpec.scopeText,
                        *kFilteredVerifierDllsRecord,
                        viewSpec.identityText[0] == 'w' ? "IFEO-FilteredVerifierDlls32" : "IFEO-FilteredVerifierDlls",
                        kFilteredVerifierEnabled
                            ? L"检测到按完整路径生效的 IFEO VerifierDlls；指定 DLL 会随目标进程加载。"
                            : L"检测到带 FilterFullPath 的 IFEO VerifierDlls，但路径过滤或应用程序验证器未启用。",
                        kFilteredVerifierEnabled);
                }
            }
        }
    }

    bool isIfeoFlagEnabledForImage(
        const std::wstring& imageName,
        const std::uint64_t flagMask)
    {
        for (const IfeoRegistryViewSpec& viewSpec : buildIfeoRegistryViewSpecList())
        {
            const std::wstring kImageSubKey = std::wstring(viewSpec.rootSubKeyText) + L"\\" + imageName;
            if (registryFlagEnabled(
                    queryRegistryValueRecord(HKEY_LOCAL_MACHINE, kImageSubKey, L"GlobalFlag"),
                    flagMask))
            {
                return true;
            }
            const bool kUseFilterEnabled = registryFlagEnabled(
                queryRegistryValueRecord(HKEY_LOCAL_MACHINE, kImageSubKey, L"UseFilter"),
                0x1ULL);
            if (!kUseFilterEnabled)
            {
                continue;
            }
            for (const std::wstring& filterName : enumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, kImageSubKey))
            {
                const std::wstring kFilterSubKey = kImageSubKey + L"\\" + filterName;
                if (!hasNonEmptyRegistryValue(queryRegistryValueRecord(
                        HKEY_LOCAL_MACHINE,
                        kFilterSubKey,
                        L"FilterFullPath")))
                {
                    continue;
                }
                if (registryFlagEnabled(
                        queryRegistryValueRecord(HKEY_LOCAL_MACHINE, kFilterSubKey, L"GlobalFlag"),
                        flagMask))
                {
                    return true;
                }
            }
        }
        return false;
    }

    void appendSilentProcessExitEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::wstring kSilentRoot =
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
        const auto kGlobalMonitorProcessRecord = queryRegistryValueRecord(
            HKEY_LOCAL_MACHINE,
            kSilentRoot,
            L"MonitorProcess");
        bool globalMonitorProcessActive = false;

        for (const std::wstring& imageName : enumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, kSilentRoot))
        {
            const std::wstring kImageSubKey = kSilentRoot + L"\\" + imageName;
            const bool kLaunchMonitorEnabled = registryFlagEnabled(
                queryRegistryValueRecord(HKEY_LOCAL_MACHINE, kImageSubKey, L"ReportingMode"),
                kSilentExitLaunchMonitorProcessFlag);
            const bool kSilentExitEnabled = isIfeoFlagEnabledForImage(
                imageName,
                kIfeoSilentProcessExitFlag);
            const bool kActive = kLaunchMonitorEnabled && kSilentExitEnabled;
            const auto kMonitorProcessRecord = queryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                kImageSubKey,
                L"MonitorProcess");
            if (hasNonEmptyRegistryValue(kMonitorProcessRecord))
            {
                appendImageHijackValueEntry(
                    entries,
                    kImageSubKey,
                    kSilentRoot,
                    fromWide(imageName),
                    L"本机",
                    *kMonitorProcessRecord,
                    "SilentProcessExit-MonitorProcess",
                    kActive
                        ? L"SilentProcessExit 已启用启动监视进程；目标进程静默退出时会执行该命令。"
                        : L"检测到 SilentProcessExit MonitorProcess，但 IFEO GlobalFlag 或 ReportingMode 未形成有效启动链。",
                    kActive);
            }
            else if (kActive && hasNonEmptyRegistryValue(kGlobalMonitorProcessRecord))
            {
                globalMonitorProcessActive = true;
            }
        }

        if (hasNonEmptyRegistryValue(kGlobalMonitorProcessRecord))
        {
            appendImageHijackValueEntry(
                entries,
                kSilentRoot,
                kSilentRoot,
                fromWide(L"全局 SilentProcessExit"),
                L"本机",
                *kGlobalMonitorProcessRecord,
                "SilentProcessExit-GlobalMonitorProcess",
                globalMonitorProcessActive
                    ? L"全局 SilentProcessExit 监视进程已被至少一个目标使用。"
                    : L"检测到全局 SilentProcessExit MonitorProcess，但当前未发现完整的启动链。",
                globalMonitorProcessActive);
        }
    }

    bool isImageHijackRegistrySubKey(const std::wstring& subKeyText)
    {
        const std::wstring kLowerSubKey = lowerWideCopy(subKeyText);
        const std::array<std::wstring, 3> kRoots{ {
            lowerWideCopy(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            lowerWideCopy(L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            lowerWideCopy(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit")
        } };
        for (const std::wstring& root : kRoots)
        {
            if (kLowerSubKey == root
                || (kLowerSubKey.size() > root.size()
                    && kLowerSubKey.starts_with(root)
                    && kLowerSubKey[root.size()] == L'\\'))
            {
                return true;
            }
        }
        return false;
    }

    // queryServiceBinaryPathText extracts the configured image path from queryServiceConfig.
    std::string queryServiceBinaryPathText(const QUERY_SERVICE_CONFIGW& serviceConfig)
    {
        if (serviceConfig.lpBinaryPathName == nullptr)
        {
            return std::string();
        }
        return toNativeSeparators(fromWide(trimWide(serviceConfig.lpBinaryPathName)));
    }

    ks::startup::StartupScmStartMode publicScmStartMode(const DWORD startType)
    {
        switch (startType)
        {
        case SERVICE_BOOT_START:
            return ks::startup::StartupScmStartMode::kBoot;
        case SERVICE_SYSTEM_START:
            return ks::startup::StartupScmStartMode::kSystem;
        case SERVICE_AUTO_START:
            return ks::startup::StartupScmStartMode::kAutomatic;
        case SERVICE_DEMAND_START:
            return ks::startup::StartupScmStartMode::kManual;
        case SERVICE_DISABLED:
            return ks::startup::StartupScmStartMode::kDisabled;
        default:
            return ks::startup::StartupScmStartMode::kNone;
        }
    }

    // enumerateScmEntries implements the shared service/driver backend with category-specific filters.
    std::vector<ks::startup::StartupEntry> enumerateScmEntries(bool drivers)
    {
        std::vector<ks::startup::StartupEntry> entries;
        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scmHandle == nullptr)
        {
            return entries;
        }
        DWORD requiredBytes = 0;
        DWORD serviceCount = 0;
        DWORD resumeHandle = 0;
        const DWORD kServiceType = drivers ? SERVICE_DRIVER : SERVICE_WIN32;
        ::EnumServicesStatusExW(scmHandle, SC_ENUM_PROCESS_INFO, kServiceType, SERVICE_STATE_ALL, nullptr, 0, &requiredBytes, &serviceCount, &resumeHandle, nullptr);
        if (requiredBytes == 0)
        {
            ::CloseServiceHandle(scmHandle);
            return entries;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        resumeHandle = 0;
        const BOOL kEnumOk = ::EnumServicesStatusExW(scmHandle, SC_ENUM_PROCESS_INFO, kServiceType, SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()), &requiredBytes, &serviceCount, &resumeHandle, nullptr);
        if (kEnumOk == FALSE)
        {
            ::CloseServiceHandle(scmHandle);
            return entries;
        }
        const auto* serviceArray = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD index = 0; index < serviceCount; ++index)
        {
            const ENUM_SERVICE_STATUS_PROCESSW& serviceItem = serviceArray[index];
            SC_HANDLE serviceHandle = ::OpenServiceW(scmHandle, serviceItem.lpServiceName, SERVICE_QUERY_CONFIG);
            if (serviceHandle == nullptr)
            {
                continue;
            }
            DWORD configBytes = 0;
            ::QueryServiceConfigW(serviceHandle, nullptr, 0, &configBytes);
            if (configBytes == 0)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }
            std::vector<std::uint8_t> configBuffer(configBytes);
            auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
            if (::QueryServiceConfigW(serviceHandle, config, configBytes, &configBytes) == FALSE)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }
            const DWORD kStartType = config->dwStartType;
            const ks::startup::StartupScmStartMode kStartMode =
                publicScmStartMode(kStartType);
            const std::string kServiceName = serviceItem.lpServiceName == nullptr ? std::string() : fromWide(serviceItem.lpServiceName);
            const std::string kDisplayName = serviceItem.lpDisplayName == nullptr ? std::string() : fromWide(trimWide(serviceItem.lpDisplayName));
            const std::string kCommandText = queryServiceBinaryPathText(*config);
            ks::startup::StartupEntry entry;
            entry.category = drivers ? ks::startup::StartupCategory::kDrivers : ks::startup::StartupCategory::kServices;
            entry.categoryText = ks::startup::categoryToText(entry.category);
            entry.itemNameText = kDisplayName.empty() ? kServiceName : kDisplayName;
            entry.imagePathText = ks::startup::normalizeFilePathText(kCommandText);
            entry.commandText = kCommandText;
            entry.publisherText = ks::startup::queryPublisherTextByPath(entry.imagePathText);
            entry.locationText = std::string(drivers ? "SCM\\Driver\\" : "SCM\\Service\\") + kServiceName;
            entry.userText = drivers ? fromWide(L"内核") : (config->lpServiceStartName == nullptr ? "N/A" : fromWide(config->lpServiceStartName));
            entry.enabled = kStartMode != ks::startup::StartupScmStartMode::kDisabled;
            entry.sourceTypeText = drivers ? "Driver" : "SCM Service";
            if (drivers && kStartType == SERVICE_BOOT_START)
            {
                entry.detailText = fromWide(L"引导启动驱动");
            }
            else if (drivers && kStartType == SERVICE_SYSTEM_START)
            {
                entry.detailText = fromWide(L"系统启动驱动");
            }
            else if (kStartType == SERVICE_AUTO_START)
            {
                entry.detailText = drivers
                    ? fromWide(L"自动启动驱动")
                    : fromWide(L"自动启动服务");
            }
            else if (kStartType == SERVICE_DEMAND_START)
            {
                entry.detailText = fromWide(L"手动启动的服务控制管理器项");
            }
            else if (kStartType == SERVICE_DISABLED)
            {
                entry.detailText = fromWide(L"已禁用的服务控制管理器启动项");
            }
            else
            {
                entry.detailText = fromWide(L"未知的服务控制管理器启动类型");
            }
            entry.canOpenFileLocation = !entry.imagePathText.empty();
            entry.canDelete = true;
            entry.imagePathExists = fileExists(entry.imagePathText);
            entry.uniqueIdText = std::string(drivers ? "DRIVER|" : "SERVICE|") + kServiceName;
            entry.actionKind = ks::startup::StartupActionKind::kScmStartType;
            entry.actionLocator.serviceNameText = kServiceName;
            entry.actionLocator.serviceIsDriver = drivers;
            entry.actionLocator.serviceStartMode = kStartMode;
            entry.actionLocator.serviceType = config->dwServiceType;
            entry.actionLocator.serviceStartType = kStartType;
            entry.actionLocator.serviceBinaryPathText = kCommandText;
            entry.canEnable = kStartMode == ks::startup::StartupScmStartMode::kDisabled;
            entry.canDisable = kStartMode != ks::startup::StartupScmStartMode::kDisabled
                && kStartMode != ks::startup::StartupScmStartMode::kNone;
            entry.riskLevel = drivers
                ? ks::startup::StartupRiskLevel::kCritical
                : ks::startup::StartupRiskLevel::kElevated;
            entry.riskReasonCode = drivers ? "driver" : "service";
            entry.riskReasonText = drivers
                ? fromWide(L"修改驱动启动类型可能导致设备失效、蓝屏或系统无法启动；重新启用时将使用系统启动类型。")
                : fromWide(L"修改服务启动类型会影响下次启动；重新启用时将使用自动启动类型。");
            entries.push_back(std::move(entry));
            ::CloseServiceHandle(serviceHandle);
        }
        ::CloseServiceHandle(scmHandle);
        return entries;
    }
}

namespace
{
    // WinsockKeySpec describes one Winsock catalog registry root.
    struct WinsockKeySpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // buildWinsockKeySpecList keeps Winsock provider/catalog coverage in one place.
    const std::array<WinsockKeySpec, 4>& buildWinsockKeySpecList()
    {
        static const std::array<WinsockKeySpec, 4> kSpecs{ {
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries", "Winsock-ProtocolCatalog", L"本机", L"Winsock Protocol Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64", "Winsock-ProtocolCatalog64", L"本机", L"Winsock 64 位 Protocol Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries", "Winsock-NameSpaceCatalog", L"本机", L"Winsock NameSpace Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64", "Winsock-NameSpaceCatalog64", L"本机", L"Winsock 64 位 NameSpace Catalog" }
        } };
        return kSpecs;
    }

    // enumerateRegistryValueTextList serializes every value in one registry key as name=value text.
    std::vector<std::string> enumerateRegistryValueTextList(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<std::string> values;
        for (const RegistryValueRecord& record : enumerateRegistryValues(rootKey, subKeyText))
        {
            const std::string kNameText = ks::str::trimCopy(record.valueNameText).empty() ? fromWide(L"(\u9ed8\u8ba4\u503c)") : record.valueNameText;
            values.push_back(kNameText + "=" + record.valueDataText);
        }
        return values;
    }

    // appendScheduledTaskJsonObject converts one PowerShell task object to StartupEntry.
    void appendScheduledTaskJsonObject(std::vector<ks::startup::StartupEntry>& entries, const JsonValue& taskObject)
    {
        const std::string kActionText = getJsonField(taskObject, "Actions");
        const std::string kTaskPathText = getJsonField(taskObject, "TaskPath");
        const std::string kTaskNameText = getJsonField(taskObject, "TaskName");
        const std::string kTaskDefinitionSha256Text =
            lowerAsciiCopy(getJsonField(taskObject, "XmlSha256"));
        if (ks::str::trimCopy(kTaskNameText).empty())
        {
            return;
        }
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::kTasks;
        entry.categoryText = ks::startup::categoryToText(entry.category);
        entry.itemNameText = kTaskNameText;
        entry.commandText = kActionText;
        entry.imagePathText = ks::startup::normalizeFilePathText(kActionText);
        entry.publisherText = ks::startup::queryPublisherTextByPath(entry.imagePathText);
        entry.locationText = kTaskPathText + kTaskNameText;
        entry.userText = getJsonField(taskObject, "UserId");
        const std::string kEnabledText = lowerAsciiCopy(getJsonField(taskObject, "Enabled"));
        entry.enabled = kEnabledText == "true"
            || (kEnabledText.empty()
                && lowerAsciiCopy(getJsonField(taskObject, "State")).find("disabled") == std::string::npos);
        entry.sourceTypeText = "ScheduledTask";
        entry.detailText = fromWide(L"\u72b6\u6001=") + getJsonField(taskObject, "State")
            + fromWide(L"\uff1b\u89e6\u53d1\u5668=") + getJsonField(taskObject, "Triggers")
            + fromWide(L"\uff1b\u63cf\u8ff0=") + getJsonField(taskObject, "Description");
        entry.canOpenFileLocation = !entry.imagePathText.empty();
        // Identity-valid tasks remain deletable after the explicit irreversible
        // warning. ProtectEntry below revokes this capability if the stable task
        // definition identity cannot be established.
        entry.canDelete = true;
        entry.imagePathExists = fileExists(entry.imagePathText);
        entry.uniqueIdText = "TASK|" + entry.locationText;
        entry.actionKind = ks::startup::StartupActionKind::kScheduledTask;
        entry.actionLocator.taskPathText = kTaskPathText;
        entry.actionLocator.taskNameText = kTaskNameText;
        entry.actionLocator.taskDefinitionSha256Text = kTaskDefinitionSha256Text;
        entry.canEnable = !entry.enabled;
        entry.canDisable = entry.enabled;
        entry.riskLevel = ks::startup::StartupRiskLevel::kElevated;
        entry.riskReasonCode = "scheduled_task";
        entry.riskReasonText = fromWide(L"仅列出 BootTrigger 和 LogonTrigger 任务；状态变更由 Windows 任务计划程序执行。");
        const bool kValidHash = kTaskDefinitionSha256Text.size() == 64
            && std::all_of(
                kTaskDefinitionSha256Text.begin(),
                kTaskDefinitionSha256Text.end(),
                [](const unsigned char ch) { return std::isxdigit(ch) != 0; });
        if (!kValidHash)
        {
            entry.riskLevel = ks::startup::StartupRiskLevel::kCritical;
            entry.riskReasonCode = "scheduled_task";
            entry.riskReasonText = fromWide(L"无法取得计划任务定义 XML 的稳定 SHA-256 身份；继续时只按精确任务路径和名称修改并验证最终状态。");
        }
        entries.push_back(std::move(entry));
    }

    // appendWmiJsonObject converts one PowerShell WMI persistence object to StartupEntry.
    void appendWmiJsonObject(std::vector<ks::startup::StartupEntry>& entries, const JsonValue& objectValue)
    {
        const std::string kTypeText = getJsonField(objectValue, "Type");
        const std::string kNameText = getJsonField(objectValue, "Name");
        const std::string kCommandText = getJsonField(objectValue, "Command");
        const std::string kImagePathText = ks::startup::normalizeFilePathText(getJsonField(objectValue, "Image"));
        const std::string kLocationText = getJsonField(objectValue, "Location");
        const std::string kDetailText = getJsonField(objectValue, "Detail");
        if (ks::str::trimCopy(kTypeText).empty() && ks::str::trimCopy(kNameText).empty() && ks::str::trimCopy(kCommandText).empty())
        {
            return;
        }
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::kWmi;
        entry.categoryText = ks::startup::categoryToText(entry.category);
        entry.itemNameText = ks::str::trimCopy(kNameText).empty() ? fromWide(L"(\u672a\u547d\u540dWMI\u9879)") : kNameText;
        entry.publisherText = ks::startup::queryPublisherTextByPath(kImagePathText);
        entry.imagePathText = kImagePathText;
        entry.commandText = kCommandText;
        entry.locationText = kLocationText;
        entry.userText = fromWide(L"本机");
        entry.detailText = kDetailText;
        entry.sourceTypeText = kTypeText;
        entry.enabled = true;
        entry.canOpenFileLocation = !entry.imagePathText.empty();
        entry.canOpenRegistryLocation = false;
        entry.canDelete = false;
        entry.imagePathExists = fileExists(entry.imagePathText);
        entry.uniqueIdText = "WMI|" + kTypeText + "|" + entry.itemNameText + "|" + kLocationText;
        if (kTypeText == "WMI-CommandLineConsumer")
        {
            entry.actionLocator.wmiClassNameText = "CommandLineEventConsumer";
        }
        else if (kTypeText == "WMI-ActiveScriptConsumer")
        {
            entry.actionLocator.wmiClassNameText = "ActiveScriptEventConsumer";
        }
        else if (kTypeText == "WMI-LogFileConsumer")
        {
            entry.actionLocator.wmiClassNameText = "LogFileEventConsumer";
        }
        else if (kTypeText == "WMI-NTEventLogConsumer")
        {
            entry.actionLocator.wmiClassNameText = "NTEventLogEventConsumer";
        }
        else if (kTypeText == "WMI-EventFilter")
        {
            entry.actionLocator.wmiClassNameText = "__EventFilter";
        }
        else if (kTypeText == "WMI-FilterToConsumerBinding")
        {
            entry.actionLocator.wmiClassNameText = "__FilterToConsumerBinding";
            entry.actionLocator.wmiConsumerText = kNameText;
            entry.actionLocator.wmiFilterText = kCommandText;
        }
        if (!entry.actionLocator.wmiClassNameText.empty())
        {
            entry.actionKind = ks::startup::StartupActionKind::kWmiEntryRemoval;
            entry.actionLocator.wmiNameText = kNameText;
            entry.canEnable = false;
            entry.canDisable = true;
            entry.riskLevel = ks::startup::StartupRiskLevel::kCritical;
            entry.riskReasonCode = "wmi";
            entry.riskReasonText = fromWide(L"禁用会永久删除精确匹配的 WMI 永久事件对象，KSword 不会自动重建该对象。");
        }
        else
        {
            markEntryActionUnavailable(
                entry,
                ks::startup::StartupRiskLevel::kCritical,
                "wmi",
                fromWide(L"无法识别该 WMI 对象类型，当前行没有可执行的修改定位器。"));
        }
        entries.push_back(std::move(entry));
    }

    // buildTaskPowerShellScript returns JSON for scheduled tasks while staying UI-framework-free.
    std::wstring buildTaskPowerShellScript()
    {
        return LR"PS(
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
function Get-KSwordTaskIdentityHash($task) {
  [xml]$document = [string](ScheduledTasks\Export-ScheduledTask -InputObject $task -ErrorAction Stop)
  $enabledNode = $document.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']")
  if ($null -ne $enabledNode) { $null = $enabledNode.ParentNode.RemoveChild($enabledNode) }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($document.OuterXml))
    ).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}
function Get-KSwordTaskEnabled($task) {
  if ($null -ne $task.Settings -and $null -ne $task.Settings.Enabled) {
    return [bool]$task.Settings.Enabled
  }
  return ([string]$task.State -ne 'Disabled')
}
$scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
$taskList = @(ScheduledTasks\Get-ScheduledTask | ForEach-Object {
  $actions = ($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
  $triggerKinds = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  $isBootOrLogon = @($triggerKinds | Where-Object { $_ -eq 'MSFT_TaskBootTrigger' -or $_ -eq 'MSFT_TaskLogonTrigger' }).Count -gt 0
  if ($isBootOrLogon) {
    $xmlSha256 = ''
    try { $xmlSha256 = Get-KSwordTaskIdentityHash $_ } catch { $xmlSha256 = '' }
    [PSCustomObject]@{
      TaskPath = $_.TaskPath
      TaskName = $_.TaskName
      State = [string]$_.State
      Enabled = Get-KSwordTaskEnabled $_
      Author = $_.Author
      Description = $_.Description
      Actions = $actions
      Triggers = ($triggerKinds -join ' | ')
      UserId = $_.Principal.UserId
      XmlSha256 = $xmlSha256
    }
  }
})
if ($taskList.Count -eq 0) { '[]' } else { $taskList | ConvertTo-Json -Depth 5 -Compress }
)PS";
    }

    // buildWmiPowerShellScript returns JSON for common root\subscription persistence classes.
    std::wstring buildWmiPowerShellScript()
    {
        return LR"PS(
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$cimCmdletsModule = Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $cimCmdletsModule -Force -ErrorAction Stop
$items = @()
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-CommandLineConsumer'; Name=$_.Name; Command=$_.CommandLineTemplate; Image=$_.ExecutablePath; Location='root\subscription\CommandLineEventConsumer'; Detail=('ExecutablePath=' + $_.ExecutablePath + '; WorkingDirectory=' + $_.WorkingDirectory) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-ActiveScriptConsumer'; Name=$_.Name; Command=$_.ScriptText; Image=''; Location='root\subscription\ActiveScriptEventConsumer'; Detail=('ScriptingEngine=' + $_.ScriptingEngine) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName LogFileEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-LogFileConsumer'; Name=$_.Name; Command=$_.Filename; Image=''; Location='root\subscription\LogFileEventConsumer'; Detail=('Text=' + $_.Text) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName NTEventLogEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-NTEventLogConsumer'; Name=$_.Name; Command=$_.SourceName; Image=''; Location='root\subscription\NTEventLogEventConsumer'; Detail=('EventId=' + $_.EventID + '; Category=' + $_.Category) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-EventFilter'; Name=$_.Name; Command=$_.Query; Image=''; Location='root\subscription\__EventFilter'; Detail=('QueryLanguage=' + $_.QueryLanguage + '; EventNamespace=' + $_.EventNamespace) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-FilterToConsumerBinding'; Name=$_.Consumer; Command=$_.Filter; Image=''; Location='root\subscription\__FilterToConsumerBinding'; Detail=('Consumer=' + $_.Consumer + '; Filter=' + $_.Filter + '; DeliveryQoS=' + $_.DeliveryQoS) }
}
if ($items.Count -eq 0) { '[]' } else { $items | ConvertTo-Json -Compress -Depth 4 }
)PS";
    }
}

namespace
{
    constexpr wchar_t kRegistryBackupRoot[] = L"Software\\KSword\\StartupManager\\RegistryBackups";
    constexpr wchar_t kStartupFolderBackupRoot[] = L"Software\\KSword\\StartupManager\\StartupFolderBackups";
    constexpr DWORD kBackupSchemaVersion = 1;
    constexpr DWORD kBackupStatePrepared = 0;
    constexpr DWORD kBackupStateDisabled = 1;
    constexpr DWORD kBackupStateRestored = 2;

    struct RegistryBackupRecord
    {
        std::wstring backupId;
        ks::startup::StartupRegistryRoot root = ks::startup::StartupRegistryRoot::kNone;
        std::wstring subKey;
        std::wstring valueName;
        std::wstring itemName;
        DWORD valueType = REG_NONE;
        std::vector<std::uint8_t> rawData;
        DWORD state = kBackupStatePrepared;
    };

    struct StartupFolderBackupRecord
    {
        std::wstring backupId;
        std::wstring originalPath;
        std::wstring parkedPath;
        std::wstring itemName;
        DWORD state = kBackupStatePrepared;
    };

    // makeActionResult keeps all action exits explicit and uniform for UI callers.
    ks::startup::ActionResult makeActionResult(
        const ks::startup::StartupActionStatus status,
        const bool success,
        const bool changed,
        const DWORD errorCode,
        const std::string& messageText)
    {
        ks::startup::ActionResult result;
        result.status = status;
        result.success = success;
        result.changed = changed;
        result.errorCode = errorCode;
        result.messageText = messageText;
        return result;
    }

    ks::startup::StartupActionStatus statusFromWin32(
        const DWORD errorCode,
        const ks::startup::StartupActionStatus fallback)
    {
        if (errorCode == ERROR_ACCESS_DENIED || errorCode == ERROR_PRIVILEGE_NOT_HELD)
        {
            return ks::startup::StartupActionStatus::kAccessDenied;
        }
        if (errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND)
        {
            return ks::startup::StartupActionStatus::kNotFound;
        }
        if (errorCode == ERROR_ALREADY_EXISTS || errorCode == ERROR_FILE_EXISTS)
        {
            return ks::startup::StartupActionStatus::kConflict;
        }
        return fallback;
    }

    // isSafeBackupId prevents a caller-provided backup locator from escaping its metadata root.
    bool isSafeBackupId(const std::wstring& backupId)
    {
        if (backupId.empty() || backupId.size() > 128)
        {
            return false;
        }
        return std::all_of(backupId.begin(), backupId.end(), [](const wchar_t ch) {
            return (ch >= L'0' && ch <= L'9')
                || (ch >= L'A' && ch <= L'F')
                || (ch >= L'a' && ch <= L'f')
                || ch == L'-';
        });
    }

    // generateBackupId combines wall-clock, process, thread, and atomic sequence identifiers.
    std::wstring generateBackupId()
    {
        static volatile LONG sequence = 0;
        FILETIME fileTime{};
        ::GetSystemTimeAsFileTime(&fileTime);
        ULARGE_INTEGER ticks{};
        ticks.LowPart = fileTime.dwLowDateTime;
        ticks.HighPart = fileTime.dwHighDateTime;
        const ULONG kSerial = static_cast<ULONG>(::InterlockedIncrement(&sequence));
        std::wostringstream stream;
        stream << std::uppercase << std::hex
            << ticks.QuadPart << L"-"
            << ::GetCurrentProcessId() << L"-"
            << ::GetCurrentThreadId() << L"-"
            << kSerial;
        return stream.str();
    }

    std::wstring metadataRecordPath(const wchar_t* metadataRoot, const std::wstring& backupId)
    {
        return std::wstring(metadataRoot) + L"\\" + backupId;
    }

    // queryOpenedRegistryValueRaw preserves the exact type and byte sequence stored in a value.
    LONG queryOpenedRegistryValueRaw(
        HKEY openedKey,
        const std::wstring& valueName,
        DWORD& valueTypeOut,
        std::vector<std::uint8_t>& rawDataOut)
    {
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            DWORD valueType = REG_NONE;
            DWORD dataBytes = 0;
            LONG result = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, nullptr, &dataBytes);
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            std::vector<std::uint8_t> rawData(static_cast<std::size_t>(dataBytes));
            DWORD actualBytes = dataBytes;
            result = ::RegQueryValueExW(
                openedKey,
                valueNamePointer,
                nullptr,
                &valueType,
                rawData.empty() ? nullptr : rawData.data(),
                &actualBytes);
            if (result == ERROR_MORE_DATA)
            {
                continue;
            }
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            rawData.resize(actualBytes);
            valueTypeOut = valueType;
            rawDataOut = std::move(rawData);
            return ERROR_SUCCESS;
        }
        return ERROR_MORE_DATA;
    }

    LONG queryRegistryValueRaw(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        DWORD& valueTypeOut,
        std::vector<std::uint8_t>& rawDataOut)
    {
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            return kOpenResult;
        }
        const LONG kQueryResult = queryOpenedRegistryValueRaw(openedKey, valueName, valueTypeOut, rawDataOut);
        ::RegCloseKey(openedKey);
        return kQueryResult;
    }

    LONG setMetadataDword(HKEY openedKey, const wchar_t* name, const DWORD value)
    {
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&value),
            sizeof(value));
    }

    LONG setMetadataString(HKEY openedKey, const wchar_t* name, const std::wstring& value)
    {
        const DWORD kDataBytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()),
            kDataBytes);
    }

    LONG setMetadataBinary(HKEY openedKey, const wchar_t* name, const std::vector<std::uint8_t>& value)
    {
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_BINARY,
            value.empty() ? nullptr : value.data(),
            static_cast<DWORD>(value.size()));
    }

    bool queryMetadataDword(HKEY openedKey, const wchar_t* name, DWORD& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (queryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS
            || type != REG_DWORD
            || rawData.size() != sizeof(DWORD))
        {
            return false;
        }
        std::memcpy(&valueOut, rawData.data(), sizeof(DWORD));
        return true;
    }

    bool queryMetadataString(HKEY openedKey, const wchar_t* name, std::wstring& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (queryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS
            || type != REG_SZ
            || rawData.size() < sizeof(wchar_t)
            || rawData.size() % sizeof(wchar_t) != 0)
        {
            return false;
        }
        std::size_t charCount = rawData.size() / sizeof(wchar_t);
        valueOut.resize(charCount);
        std::memcpy(valueOut.data(), rawData.data(), rawData.size());
        while (!valueOut.empty() && valueOut.back() == L'\0')
        {
            valueOut.pop_back();
        }
        return valueOut.find(L'\0') == std::wstring::npos;
    }

    bool queryMetadataBinary(HKEY openedKey, const wchar_t* name, std::vector<std::uint8_t>& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (queryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS || type != REG_BINARY)
        {
            return false;
        }
        valueOut = std::move(rawData);
        return true;
    }

    LONG openMetadataRootForCreate(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        HKEY& rootKeyOut)
    {
        rootKeyOut = nullptr;
        if ((metadataHive != HKEY_CURRENT_USER && metadataHive != HKEY_LOCAL_MACHINE)
            || metadataRoot == nullptr
            || metadataRoot[0] == L'\0')
        {
            return ERROR_INVALID_PARAMETER;
        }

        PSECURITY_DESCRIPTOR machineDescriptor = nullptr;
        SECURITY_ATTRIBUTES machineAttributes{};
        SECURITY_ATTRIBUTES* securityAttributes = nullptr;
        REGSAM desiredAccess = KEY_CREATE_SUB_KEY;
        if (metadataHive == HKEY_LOCAL_MACHINE)
        {
            // Machine-scope journals must not be writable by the medium-integrity user.
            if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)",
                    SDDL_REVISION_1,
                    &machineDescriptor,
                    nullptr) == FALSE)
            {
                return static_cast<LONG>(::GetLastError());
            }
            machineAttributes.nLength = sizeof(machineAttributes);
            machineAttributes.lpSecurityDescriptor = machineDescriptor;
            machineAttributes.bInheritHandle = FALSE;
            securityAttributes = &machineAttributes;
            desiredAccess |= WRITE_DAC;
        }

        LONG result = ::RegCreateKeyExW(
            metadataHive,
            metadataRoot,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            desiredAccess,
            securityAttributes,
            &rootKeyOut,
            nullptr);
        if (result == ERROR_SUCCESS && metadataHive == HKEY_LOCAL_MACHINE)
        {
            result = ::RegSetKeySecurity(
                rootKeyOut,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                machineDescriptor);
        }
        if (machineDescriptor != nullptr)
        {
            ::LocalFree(machineDescriptor);
        }
        if (result != ERROR_SUCCESS && rootKeyOut != nullptr)
        {
            ::RegCloseKey(rootKeyOut);
            rootKeyOut = nullptr;
        }
        return result;
    }

    // createUniqueMetadataKey never opens an existing backup record for writing.
    LONG createUniqueMetadataKey(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        std::wstring& backupIdOut,
        HKEY& recordKeyOut)
    {
        recordKeyOut = nullptr;
        HKEY rootKey = nullptr;
        LONG result = openMetadataRootForCreate(metadataHive, metadataRoot, rootKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        for (int attempt = 0; attempt < 64; ++attempt)
        {
            const std::wstring kBackupId = generateBackupId();
            DWORD disposition = 0;
            HKEY recordKey = nullptr;
            result = ::RegCreateKeyExW(
                rootKey,
                kBackupId.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                nullptr,
                &recordKey,
                &disposition);
            if (result == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY)
            {
                backupIdOut = kBackupId;
                recordKeyOut = recordKey;
                ::RegCloseKey(rootKey);
                return ERROR_SUCCESS;
            }
            if (recordKey != nullptr)
            {
                ::RegCloseKey(recordKey);
            }
            if (result != ERROR_SUCCESS)
            {
                ::RegCloseKey(rootKey);
                return result;
            }
        }
        ::RegCloseKey(rootKey);
        return ERROR_ALREADY_EXISTS;
    }

    LONG deleteMetadataRecord(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        const std::wstring& backupId)
    {
        if (!isSafeBackupId(backupId))
        {
            return ERROR_INVALID_NAME;
        }
        const LONG kResult = ::RegDeleteTreeW(
            metadataHive,
            metadataRecordPath(metadataRoot, backupId).c_str());
        return kResult == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : kResult;
    }

    LONG setAndVerifyMetadataState(HKEY recordKey, const DWORD state)
    {
        const LONG kSetResult = setMetadataDword(recordKey, L"State", state);
        if (kSetResult != ERROR_SUCCESS)
        {
            return kSetResult;
        }
        DWORD storedState = 0;
        return queryMetadataDword(recordKey, L"State", storedState) && storedState == state
            ? ERROR_SUCCESS
            : ERROR_INVALID_DATA;
    }

    LONG commitMetadataStateById(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        const std::wstring& backupId,
        const DWORD state)
    {
        if (!isSafeBackupId(backupId))
        {
            return ERROR_INVALID_NAME;
        }
        HKEY recordKey = nullptr;
        LONG result = ::RegOpenKeyExW(
            metadataHive,
            metadataRecordPath(metadataRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        if (result == ERROR_SUCCESS)
        {
            result = setAndVerifyMetadataState(recordKey, state);
        }
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        return result;
    }

    bool rawRegistryValuesEqual(
        const DWORD leftType,
        const std::vector<std::uint8_t>& leftData,
        const DWORD rightType,
        const std::vector<std::uint8_t>& rightData)
    {
        return leftType == rightType && leftData == rightData;
    }

    LONG setRegistryValueWithoutOverwrite(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        const DWORD valueType,
        const std::vector<std::uint8_t>& rawData)
    {
        HKEY openedKey = nullptr;
        LONG result = ::RegCreateKeyExW(
            rootKey,
            subKey.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            nullptr,
            &openedKey,
            nullptr);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        DWORD existingType = REG_NONE;
        std::vector<std::uint8_t> existingData;
        result = queryOpenedRegistryValueRaw(openedKey, valueName, existingType, existingData);
        if (result == ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return ERROR_ALREADY_EXISTS;
        }
        if (result != ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(openedKey);
            return result;
        }
        // Registry values do not have a native compare-and-set primitive. This final absence
        // check is performed on the exact write handle and RegSetValueExW follows immediately;
        // callers still verify the exact bytes after the best-effort no-overwrite write.
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        result = ::RegSetValueExW(
            openedKey,
            valueNamePointer,
            0,
            valueType,
            rawData.empty() ? nullptr : rawData.data(),
            static_cast<DWORD>(rawData.size()));
        ::RegCloseKey(openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        DWORD verifyType = REG_NONE;
        std::vector<std::uint8_t> verifyData;
        result = queryRegistryValueRaw(rootKey, subKey, valueName, verifyType, verifyData);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        return rawRegistryValuesEqual(valueType, rawData, verifyType, verifyData)
            ? ERROR_SUCCESS
            : ERROR_INVALID_DATA;
    }

    LONG deleteRegistryValueIfExact(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        const DWORD expectedType,
        const std::vector<std::uint8_t>& expectedData)
    {
        DWORD currentType = REG_NONE;
        std::vector<std::uint8_t> currentData;
        LONG result = queryRegistryValueRaw(rootKey, subKey, valueName, currentType, currentData);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        if (!rawRegistryValuesEqual(currentType, currentData, expectedType, expectedData))
        {
            return ERROR_ALREADY_EXISTS;
        }
        HKEY openedKey = nullptr;
        result = ::RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        currentType = REG_NONE;
        currentData.clear();
        result = queryOpenedRegistryValueRaw(openedKey, valueName, currentType, currentData);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return result;
        }
        if (!rawRegistryValuesEqual(currentType, currentData, expectedType, expectedData))
        {
            ::RegCloseKey(openedKey);
            return ERROR_ALREADY_EXISTS;
        }
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        result = ::RegDeleteValueW(openedKey, valueNamePointer);
        ::RegCloseKey(openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        result = queryRegistryValueRaw(rootKey, subKey, valueName, currentType, currentData);
        return result == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : (result == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : result);
    }
}

namespace
{
    LONG writeRegistryBackupMetadata(HKEY recordKey, const RegistryBackupRecord& record)
    {
        LONG result = setMetadataDword(recordKey, L"SchemaVersion", kBackupSchemaVersion);
        if (result == ERROR_SUCCESS) result = setMetadataDword(recordKey, L"State", record.state);
        if (result == ERROR_SUCCESS) result = setMetadataDword(recordKey, L"Root", static_cast<DWORD>(record.root));
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"SubKey", record.subKey);
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"ValueName", record.valueName);
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"ItemName", record.itemName);
        if (result == ERROR_SUCCESS) result = setMetadataDword(recordKey, L"ValueType", record.valueType);
        if (result == ERROR_SUCCESS) result = setMetadataBinary(recordKey, L"RawData", record.rawData);
        return result;
    }

    bool readRegistryBackupMetadata(
        HKEY recordKey,
        const std::wstring& backupId,
        RegistryBackupRecord& recordOut)
    {
        DWORD schemaVersion = 0;
        DWORD state = 0;
        DWORD rootValue = 0;
        DWORD valueType = REG_NONE;
        RegistryBackupRecord record;
        record.backupId = backupId;
        if (!queryMetadataDword(recordKey, L"SchemaVersion", schemaVersion)
            || schemaVersion != kBackupSchemaVersion
            || !queryMetadataDword(recordKey, L"State", state)
            || state > kBackupStateRestored
            || !queryMetadataDword(recordKey, L"Root", rootValue)
            || !queryMetadataString(recordKey, L"SubKey", record.subKey)
            || !queryMetadataString(recordKey, L"ValueName", record.valueName)
            || !queryMetadataString(recordKey, L"ItemName", record.itemName)
            || !queryMetadataDword(recordKey, L"ValueType", valueType)
            || !queryMetadataBinary(recordKey, L"RawData", record.rawData))
        {
            return false;
        }
        record.root = static_cast<ks::startup::StartupRegistryRoot>(rootValue);
        record.state = state;
        record.valueType = valueType;
        const HKEY kNativeRoot = nativeRegistryRoot(record.root);
        if (kNativeRoot == nullptr || !isSupportedRunLocation(kNativeRoot, record.subKey))
        {
            return false;
        }
        recordOut = std::move(record);
        return true;
    }

    bool readRegistryBackupById(
        HKEY metadataHive,
        const std::wstring& backupId,
        RegistryBackupRecord& recordOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (!isSafeBackupId(backupId))
        {
            errorCodeOut = ERROR_INVALID_NAME;
            return false;
        }
        HKEY recordKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            metadataHive,
            metadataRecordPath(kRegistryBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE,
            &recordKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            errorCodeOut = static_cast<DWORD>(kOpenResult);
            return false;
        }
        const bool kReadOk = readRegistryBackupMetadata(recordKey, backupId, recordOut)
            && registryBackupMetadataHive(recordOut.root) == metadataHive;
        ::RegCloseKey(recordKey);
        if (!kReadOk)
        {
            errorCodeOut = ERROR_INVALID_DATA;
        }
        return kReadOk;
    }

    bool registryBackupRecordsEqual(const RegistryBackupRecord& left, const RegistryBackupRecord& right)
    {
        return left.backupId == right.backupId
            && left.root == right.root
            && equalWideI(left.subKey, right.subKey)
            && left.valueName == right.valueName
            && left.itemName == right.itemName
            && left.valueType == right.valueType
            && left.rawData == right.rawData
            && left.state == right.state;
    }

    std::string runSourceTypeForSubKey(const std::wstring& subKey)
    {
        const std::wstring kLowerSubKey = lowerWideCopy(subKey);
        const bool kIs32 = kLowerSubKey.find(L"\\wow6432node\\") != std::wstring::npos;
        const bool kIsRunOnce = endsWithI(subKey, L"\\RunOnce");
        if (kIs32)
        {
            return kIsRunOnce ? "RunOnce32" : "Run32";
        }
        return kIsRunOnce ? "RunOnce" : "Run";
    }

    // rollbackDisabledRegistryValue restores only into an absent value and never overwrites a conflict.
    bool rollbackDisabledRegistryValue(const RegistryBackupRecord& record, DWORD& errorCodeOut)
    {
        const HKEY kRootKey = nativeRegistryRoot(record.root);
        const LONG kRestoreResult = setRegistryValueWithoutOverwrite(
            kRootKey,
            record.subKey,
            record.valueName,
            record.valueType,
            record.rawData);
        errorCodeOut = static_cast<DWORD>(kRestoreResult);
        return kRestoreResult == ERROR_SUCCESS;
    }

    ks::startup::ActionResult disableRegistryRunEntry(const ks::startup::StartupEntry& entry)
    {
        const HKEY kRootKey = nativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring kSubKey = toWide(entry.actionLocator.registrySubKeyText);
        const std::wstring kValueName = toWide(entry.actionLocator.registryValueNameText);
        if (kRootKey == nullptr
            || !isSupportedRunLocation(kRootKey, kSubKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"注册表操作定位器无效。"));
        }

        DWORD valueType = REG_NONE;
        std::vector<std::uint8_t> rawData;
        LONG result = queryRegistryValueRaw(kRootKey, kSubKey, kValueName, valueType, rawData);
        if (result != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法读取源注册表值。"));
        }
        if (entry.actionLocator.registryValueSnapshotValid
            && !rawRegistryValuesEqual(
                entry.actionLocator.registryValueType,
                entry.actionLocator.registryRawData,
                valueType,
                rawData))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"注册表值已在枚举后变化；请刷新后重试。"));
        }

        RegistryBackupRecord record;
        record.root = entry.actionLocator.registryRoot;
        record.subKey = kSubKey;
        record.valueName = kValueName;
        record.itemName = toWide(entry.itemNameText);
        record.valueType = valueType;
        record.rawData = rawData;
        record.state = kBackupStatePrepared;
        const HKEY kMetadataHive = registryBackupMetadataHive(record.root);
        if (kMetadataHive == nullptr)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"注册表备份的完整性范围无效。"));
        }

        HKEY recordKey = nullptr;
        result = createUniqueMetadataKey(
            kMetadataHive,
            kRegistryBackupRoot,
            record.backupId,
            recordKey);
        if (result != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法创建唯一的注册表备份记录。"));
        }

        result = writeRegistryBackupMetadata(recordKey, record);
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        RegistryBackupRecord verifiedRecord;
        const bool kMetadataVerified = result == ERROR_SUCCESS
            && readRegistryBackupMetadata(recordKey, record.backupId, verifiedRecord)
            && registryBackupRecordsEqual(record, verifiedRecord);
        if (!kMetadataVerified)
        {
            const DWORD kFailureCode = result == ERROR_SUCCESS ? ERROR_INVALID_DATA : static_cast<DWORD>(result);
            ::RegCloseKey(recordKey);
            deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, record.backupId);
            return makeActionResult(
                statusFromWin32(kFailureCode, ks::startup::StartupActionStatus::kVerificationFailed),
                false,
                false,
                kFailureCode,
                fromWide(L"注册表备份写入或校验失败；源值未被修改。"));
        }

        DWORD currentType = REG_NONE;
        std::vector<std::uint8_t> currentData;
        result = queryRegistryValueRaw(kRootKey, kSubKey, kValueName, currentType, currentData);
        if (result != ERROR_SUCCESS || !rawRegistryValuesEqual(valueType, rawData, currentType, currentData))
        {
            ::RegCloseKey(recordKey);
            deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, record.backupId);
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                result == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : static_cast<DWORD>(result),
                fromWide(L"源注册表值在备份后发生变化；未执行删除。"));
        }

        result = deleteRegistryValueIfExact(kRootKey, kSubKey, kValueName, valueType, rawData);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(recordKey);
            DWORD observedType = REG_NONE;
            std::vector<std::uint8_t> observedData;
            const LONG kObserveResult = queryRegistryValueRaw(kRootKey, kSubKey, kValueName, observedType, observedData);
            ks::startup::ActionResult failure = makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法安全删除源注册表值。"));
            failure.rollbackAttempted = true;
            if (kObserveResult == ERROR_SUCCESS && rawRegistryValuesEqual(valueType, rawData, observedType, observedData))
            {
                failure.rollbackSucceeded = deleteMetadataRecord(
                    kMetadataHive,
                    kRegistryBackupRoot,
                    record.backupId) == ERROR_SUCCESS;
            }
            else if (kObserveResult == ERROR_FILE_NOT_FOUND)
            {
                DWORD rollbackError = ERROR_SUCCESS;
                failure.rollbackSucceeded = rollbackDisabledRegistryValue(record, rollbackError);
                if (failure.rollbackSucceeded)
                {
                    deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, record.backupId);
                }
                else
                {
                    failure.status = ks::startup::StartupActionStatus::kRollbackFailed;
                    failure.errorCode = rollbackError;
                }
            }
            else
            {
                failure.status = ks::startup::StartupActionStatus::kRollbackFailed;
                failure.errorCode = kObserveResult == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : static_cast<DWORD>(kObserveResult);
            }
            return failure;
        }

        LONG stateResult = setAndVerifyMetadataState(recordKey, kBackupStateDisabled);
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        ::RegCloseKey(recordKey);
        if (stateResult != ERROR_SUCCESS)
        {
            DWORD rollbackError = ERROR_SUCCESS;
            const bool kRollbackOk = rollbackDisabledRegistryValue(record, rollbackError);
            ks::startup::ActionResult failure = makeActionResult(
                kRollbackOk
                    ? statusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::kWriteFailed)
                    : ks::startup::StartupActionStatus::kRollbackFailed,
                false,
                false,
                kRollbackOk ? static_cast<DWORD>(stateResult) : rollbackError,
                kRollbackOk
                    ? fromWide(L"禁用状态提交失败；原注册表值已恢复。")
                    : fromWide(L"禁用状态提交失败，且自动回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = kRollbackOk;
            if (kRollbackOk)
            {
                deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, record.backupId);
            }
            return failure;
        }

        return makeActionResult(
            ks::startup::StartupActionStatus::kSuccess,
            true,
            true,
            ERROR_SUCCESS,
            fromWide(L"注册表启动值已完成备份、校验并禁用。"));
    }

    ks::startup::ActionResult enableRegistryRunEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring kBackupId = toWide(entry.actionLocator.backupIdText);
        const HKEY kMetadataHive = registryBackupMetadataHive(entry.actionLocator.registryRoot);
        if (kMetadataHive == nullptr)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"注册表恢复记录的完整性范围无效。"));
        }
        RegistryBackupRecord record;
        DWORD readError = ERROR_SUCCESS;
        if (!readRegistryBackupById(kMetadataHive, kBackupId, record, readError))
        {
            return makeActionResult(
                statusFromWin32(readError, ks::startup::StartupActionStatus::kInvalidEntry),
                false,
                false,
                readError,
                fromWide(L"注册表备份记录缺失、格式无效，或使用了不受支持的版本。"));
        }
        if (record.state == kBackupStateRestored)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"注册表启动值已经恢复。"));
        }
        if (record.state != kBackupStateDisabled)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_STATE,
                fromWide(L"注册表备份事务尚未提交，不能通过此接口恢复。"));
        }
        if (record.root != entry.actionLocator.registryRoot
            || !equalWideI(record.subKey, toWide(entry.actionLocator.registrySubKeyText))
            || record.valueName != toWide(entry.actionLocator.registryValueNameText))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_DATA,
                fromWide(L"条目定位器与不可变备份元数据不匹配。"));
        }

        const HKEY kRootKey = nativeRegistryRoot(record.root);
        LONG result = setRegistryValueWithoutOverwrite(
            kRootKey,
            record.subKey,
            record.valueName,
            record.valueType,
            record.rawData);
        if (result != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                result == ERROR_ALREADY_EXISTS
                    ? fromWide(L"原名称下已存在注册表值；未执行覆盖。")
                    : fromWide(L"无法恢复原注册表值。"));
        }

        HKEY recordKey = nullptr;
        result = ::RegOpenKeyExW(
            kMetadataHive,
            metadataRecordPath(kRegistryBackupRoot, kBackupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        LONG stateResult = result;
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = setAndVerifyMetadataState(recordKey, kBackupStateRestored);
        }
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG kRollbackResult = deleteRegistryValueIfExact(
                kRootKey,
                record.subKey,
                record.valueName,
                record.valueType,
                record.rawData);
            ks::startup::ActionResult failure = makeActionResult(
                kRollbackResult == ERROR_SUCCESS
                    ? statusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::kWriteFailed)
                    : ks::startup::StartupActionStatus::kRollbackFailed,
                false,
                false,
                kRollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(kRollbackResult),
                kRollbackResult == ERROR_SUCCESS
                    ? fromWide(L"恢复元数据提交失败；已再次移除刚恢复的值。")
                    : fromWide(L"恢复元数据提交失败，且无法回滚刚恢复的值。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = kRollbackResult == ERROR_SUCCESS;
            return failure;
        }

        const LONG kCleanupResult = deleteMetadataRecord(
            kMetadataHive,
            kRegistryBackupRoot,
            kBackupId);
        return makeActionResult(
            ks::startup::StartupActionStatus::kSuccess,
            true,
            true,
            kCleanupResult == ERROR_SUCCESS ? ERROR_SUCCESS : static_cast<DWORD>(kCleanupResult),
            kCleanupResult == ERROR_SUCCESS
                ? fromWide(L"原注册表值已恢复，备份记录已移除。")
                : fromWide(L"原注册表值已恢复，但无法移除已退役的备份元数据。"));
    }

    // appendDisabledRegistryRunEntries exposes valid app-owned backups as enabled=false records.
    void appendDisabledRegistryRunEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<HKEY, 2> kMetadataHives{ HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        for (const HKEY kMetadataHive : kMetadataHives)
        {
            const std::string kMetadataScope = kMetadataHive == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU";
            for (const std::wstring& backupId : enumerateRegistrySubKeys(kMetadataHive, kRegistryBackupRoot))
            {
                RegistryBackupRecord record;
                DWORD readError = ERROR_SUCCESS;
                if (!readRegistryBackupById(kMetadataHive, backupId, record, readError))
                {
                    ks::startup::StartupEntry invalidEntry;
                    invalidEntry.category = ks::startup::StartupCategory::kLogon;
                    invalidEntry.categoryText = ks::startup::categoryToText(invalidEntry.category);
                    invalidEntry.itemNameText = fromWide(L"KSword 注册表恢复记录 ") + fromWide(backupId);
                    invalidEntry.detailText =
                        kMetadataScope + "|" + fromWide(L"KSword 备份=") + fromWide(backupId);
                    invalidEntry.sourceTypeText = "RunBackup";
                    invalidEntry.enabled = false;
                    invalidEntry.uniqueIdText =
                        "REGLOGON-RECOVERY-INVALID|" + kMetadataScope + "|" + fromWide(backupId);
                    invalidEntry.lastErrorCode = readError;
                    markEntryActionUnavailable(
                        invalidEntry,
                        ks::startup::StartupRiskLevel::kCritical,
                        "backup_record",
                        fromWide(L"注册表恢复元数据损坏、版本不受支持，或元数据完整性范围与目标不匹配。"));
                    entries.push_back(std::move(invalidEntry));
                    continue;
                }
            const HKEY kRootKey = nativeRegistryRoot(record.root);
            DWORD sourceType = REG_NONE;
            std::vector<std::uint8_t> sourceData;
            const LONG kSourceResult = queryRegistryValueRaw(
                kRootKey,
                record.subKey,
                record.valueName,
                sourceType,
                sourceData);
            const bool kRestoreConflict = kSourceResult == ERROR_SUCCESS;
            const bool kSourceConfirmedAbsent =
                kSourceResult == ERROR_FILE_NOT_FOUND || kSourceResult == ERROR_PATH_NOT_FOUND;
            const bool kSourceMatchesBackup = kRestoreConflict
                && rawRegistryValuesEqual(
                    sourceType,
                    sourceData,
                    record.valueType,
                    record.rawData);
            DWORD reconciliationError = ERROR_SUCCESS;
            if (record.state == kBackupStatePrepared)
            {
                if (kSourceMatchesBackup)
                {
                    reconciliationError = static_cast<DWORD>(
                        deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, backupId));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        continue;
                    }
                }
                else if (kSourceConfirmedAbsent)
                {
                    reconciliationError = static_cast<DWORD>(
                        commitMetadataStateById(
                            kMetadataHive,
                            kRegistryBackupRoot,
                            backupId,
                            kBackupStateDisabled));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        record.state = kBackupStateDisabled;
                    }
                }
            }
            else if (record.state == kBackupStateRestored && kSourceMatchesBackup)
            {
                reconciliationError = static_cast<DWORD>(
                    deleteMetadataRecord(kMetadataHive, kRegistryBackupRoot, backupId));
                if (reconciliationError == ERROR_SUCCESS)
                {
                    continue;
                }
            }

            ks::startup::StartupEntry entry;
            const bool kLogonSource = isKnownRunLocation(kRootKey, record.subKey)
                || lowerWideCopy(record.subKey).find(L"\\runonceex") != std::wstring::npos;
            const bool kImageHijackSource = isImageHijackRegistrySubKey(record.subKey);
            entry.category = kLogonSource
                ? ks::startup::StartupCategory::kLogon
                : (kImageHijackSource
                    ? ks::startup::StartupCategory::kImageHijack
                    : ks::startup::StartupCategory::kRegistry);
            entry.categoryText = ks::startup::categoryToText(entry.category);
            entry.itemNameText = record.itemName.empty()
                ? (record.valueName.empty() ? fromWide(L"(\u9ed8\u8ba4\u503c)") : fromWide(record.valueName))
                : fromWide(record.itemName);
            entry.locationText = buildRegistryLocationText(kRootKey, record.subKey);
            entry.locationGroupText = entry.locationText;
            entry.userText = record.root == ks::startup::StartupRegistryRoot::kCurrentUser
                ? fromWide(L"\u5f53\u524d\u7528\u6237")
                : fromWide(L"\u672c\u673a");
            entry.sourceTypeText = kLogonSource
                ? runSourceTypeForSubKey(record.subKey)
                : (kImageHijackSource ? "ImageHijackBackup" : "RegistryBackup");
            entry.detailText =
                kMetadataScope + "|" + fromWide(L"KSword 备份=") + fromWide(backupId);
            entry.uniqueIdText =
                "REGLOGON-RECOVERY|" + kMetadataScope + "|" + fromWide(backupId);
            finalizeRegistryEntry(
                entry,
                registryDataToText(record.valueType, record.rawData),
                std::string(),
                fromWide(record.valueName),
                false,
                false);
            entry.enabled = kSourceMatchesBackup;
            entry.lastErrorCode = reconciliationError != ERROR_SUCCESS
                ? reconciliationError
                : (kSourceConfirmedAbsent || kRestoreConflict
                    ? ERROR_SUCCESS
                    : static_cast<std::uint32_t>(kSourceResult));
            std::string reasonCode = "backup_record";
            std::string reasonText;
            if (record.root == ks::startup::StartupRegistryRoot::kLocalMachine)
            {
                reasonCode = "machine_scope";
                reasonText = fromWide(L"恢复机器范围注册表值需要管理员权限，并会影响所有用户。");
            }
            else if (record.state == kBackupStatePrepared && kSourceMatchesBackup)
            {
                reasonText = fromWide(L"Prepared 操作尚未发生，但清理恢复元数据失败；记录保持可见。");
            }
            else if (record.state == kBackupStatePrepared && kSourceConfirmedAbsent)
            {
                reasonText = fromWide(L"Prepared 记录对应的源值已缺失，但提交 Disabled 状态失败；记录保持可见。");
            }
            else if (kRestoreConflict && !kSourceMatchesBackup)
            {
                reasonText = fromWide(L"源位置已出现不同的同名注册表值；恢复操作会拒绝覆盖该值。");
            }
            else if (!kSourceConfirmedAbsent)
            {
                reasonText = fromWide(L"无法检查原注册表位置；恢复操作可能因访问错误而失败。");
            }
            else
            {
                reasonText = fromWide(L"恢复元数据已完成对账；警告确认后可以恢复原注册表值。");
            }
            if (record.state == kBackupStateDisabled)
            {
                entry.actionKind = ks::startup::StartupActionKind::kRegistryRunValue;
                entry.actionLocator.registryRoot = record.root;
                entry.actionLocator.registrySubKeyText = fromWide(record.subKey);
                entry.actionLocator.registryValueNameText = fromWide(record.valueName);
                entry.actionLocator.backupIdText = fromWide(backupId);
                entry.canEnable = true;
                entry.canDisable = false;
                entry.riskLevel = record.root == ks::startup::StartupRegistryRoot::kLocalMachine
                    || !kLogonSource
                    ? ks::startup::StartupRiskLevel::kCritical
                    : ks::startup::StartupRiskLevel::kElevated;
                entry.riskReasonCode = reasonCode;
                entry.riskReasonText = reasonText;
            }
            else
            {
                markEntryActionUnavailable(
                    entry,
                    ks::startup::StartupRiskLevel::kCritical,
                    reasonCode,
                    reasonText);
            }
            entries.push_back(std::move(entry));
            }
        }
    }
}

namespace
{
    std::wstring startupParkingRoot(HKEY metadataHive)
    {
        if (metadataHive == HKEY_CURRENT_USER)
        {
            const std::wstring kLocalAppData = knownFolderPath(FOLDERID_LocalAppData);
            return kLocalAppData.empty()
                ? std::wstring()
                : (std::filesystem::path(kLocalAppData) / L"KSword" / L"StartupManager" / L"Parking").wstring();
        }
        if (metadataHive == HKEY_LOCAL_MACHINE)
        {
            const std::wstring kProgramData = knownFolderPath(FOLDERID_ProgramData);
            const std::wstring kProtectedDirectoryName =
                std::wstring(L"KSword") + L"StartupManager";
            return kProgramData.empty()
                ? std::wstring()
                : (std::filesystem::path(kProgramData) / kProtectedDirectoryName / L"Parking").wstring();
        }
        return std::wstring();
    }

    LONG ensureProtectedMachineDirectory(const std::wstring& directoryPath)
    {
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
                SDDL_REVISION_1,
                &securityDescriptor,
                nullptr) == FALSE)
        {
            return static_cast<LONG>(::GetLastError());
        }

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.lpSecurityDescriptor = securityDescriptor;
        securityAttributes.bInheritHandle = FALSE;
        if (::CreateDirectoryW(directoryPath.c_str(), &securityAttributes) == FALSE)
        {
            const DWORD kCreateError = ::GetLastError();
            if (kCreateError != ERROR_ALREADY_EXISTS)
            {
                ::LocalFree(securityDescriptor);
                return static_cast<LONG>(kCreateError);
            }
        }

        HANDLE directoryHandle = ::CreateFileW(
            directoryPath.c_str(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (directoryHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD kOpenError = ::GetLastError();
            ::LocalFree(securityDescriptor);
            return static_cast<LONG>(kOpenError);
        }

        BY_HANDLE_FILE_INFORMATION fileInformation{};
        const bool kInformationValid =
            ::GetFileInformationByHandle(directoryHandle, &fileInformation) != FALSE;
        if (!kInformationValid
            || (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            || (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            const DWORD kValidationError = kInformationValid
                ? ERROR_REPARSE_TAG_INVALID
                : ::GetLastError();
            ::CloseHandle(directoryHandle);
            ::LocalFree(securityDescriptor);
            return static_cast<LONG>(kValidationError);
        }

        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL dacl = nullptr;
        const bool kDaclValid =
            ::GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl, &daclDefaulted) != FALSE
            && daclPresent
            && dacl != nullptr;
        const DWORD kSecurityResult = kDaclValid
            ? ::SetSecurityInfo(
                directoryHandle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                dacl,
                nullptr)
            : ERROR_INVALID_SECURITY_DESCR;
        ::CloseHandle(directoryHandle);
        ::LocalFree(securityDescriptor);
        return static_cast<LONG>(kSecurityResult);
    }

    LONG ensureMachineStartupParkingRoot()
    {
        const std::wstring kParkingRoot = startupParkingRoot(HKEY_LOCAL_MACHINE);
        if (kParkingRoot.empty())
        {
            return ERROR_PATH_NOT_FOUND;
        }
        const std::wstring kProtectedRoot =
            std::filesystem::path(kParkingRoot).parent_path().wstring();
        LONG result = ensureProtectedMachineDirectory(kProtectedRoot);
        if (result == ERROR_SUCCESS)
        {
            result = ensureProtectedMachineDirectory(kParkingRoot);
        }
        return result;
    }

    std::wstring normalizedPathText(const std::wstring& pathText)
    {
        if (pathText.empty())
        {
            return std::wstring();
        }
        return std::filesystem::path(pathText).lexically_normal().wstring();
    }

    bool equalPathI(const std::wstring& left, const std::wstring& right)
    {
        return equalWideI(normalizedPathText(left), normalizedPathText(right));
    }

    // isKnownStartupFolderFile recognizes current and legacy machine-wide records for display.
    bool isKnownStartupFolderFile(const std::wstring& pathText, bool* machineWideOut = nullptr)
    {
        const std::filesystem::path kFilePath = std::filesystem::path(pathText).lexically_normal();
        if (!kFilePath.is_absolute() || kFilePath.filename().empty())
        {
            return false;
        }
        const std::array<std::pair<std::wstring, bool>, 2> kFolders{ {
            { knownFolderPath(FOLDERID_Startup), false },
            { knownFolderPath(FOLDERID_CommonStartup), true }
        } };
        for (const auto& folder : kFolders)
        {
            if (!folder.first.empty() && equalPathI(kFilePath.parent_path().wstring(), folder.first))
            {
                if (machineWideOut != nullptr)
                {
                    *machineWideOut = folder.second;
                }
                return true;
            }
        }
        return false;
    }

    bool isSupportedStartupFolderFile(const std::wstring& pathText)
    {
        bool machineWide = false;
        return isKnownStartupFolderFile(pathText, &machineWide);
    }

    HKEY startupFolderMetadataHive(const std::wstring& originalPath)
    {
        bool machineWide = false;
        if (!isKnownStartupFolderFile(originalPath, &machineWide))
        {
            return nullptr;
        }
        return machineWide ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    }

    bool isRegularFileWide(const std::wstring& pathText)
    {
        const DWORD kAttributes = ::GetFileAttributesW(pathText.c_str());
        return kAttributes != INVALID_FILE_ATTRIBUTES && (kAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    LONG moveFileWithoutOverwrite(const std::wstring& sourcePath, const std::wstring& destinationPath)
    {
        if (isRegularFileWide(destinationPath) || ::GetFileAttributesW(destinationPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            return ERROR_ALREADY_EXISTS;
        }
        if (::MoveFileExW(
                sourcePath.c_str(),
                destinationPath.c_str(),
                MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH) == FALSE)
        {
            return static_cast<LONG>(::GetLastError());
        }
        if (isRegularFileWide(sourcePath) || !isRegularFileWide(destinationPath))
        {
            return ERROR_INVALID_DATA;
        }
        return ERROR_SUCCESS;
    }

    LONG writeStartupFolderBackupMetadata(HKEY recordKey, const StartupFolderBackupRecord& record)
    {
        LONG result = setMetadataDword(recordKey, L"SchemaVersion", kBackupSchemaVersion);
        if (result == ERROR_SUCCESS) result = setMetadataDword(recordKey, L"State", record.state);
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"OriginalPath", record.originalPath);
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"ParkedPath", record.parkedPath);
        if (result == ERROR_SUCCESS) result = setMetadataString(recordKey, L"ItemName", record.itemName);
        return result;
    }

    bool readStartupFolderBackupMetadata(
        HKEY metadataHive,
        HKEY recordKey,
        const std::wstring& backupId,
        StartupFolderBackupRecord& recordOut)
    {
        DWORD schemaVersion = 0;
        StartupFolderBackupRecord record;
        record.backupId = backupId;
        if (!queryMetadataDword(recordKey, L"SchemaVersion", schemaVersion)
            || schemaVersion != kBackupSchemaVersion
            || !queryMetadataDword(recordKey, L"State", record.state)
            || record.state > kBackupStateRestored
            || !queryMetadataString(recordKey, L"OriginalPath", record.originalPath)
            || !queryMetadataString(recordKey, L"ParkedPath", record.parkedPath)
            || !queryMetadataString(recordKey, L"ItemName", record.itemName)
            || startupFolderMetadataHive(record.originalPath) != metadataHive)
        {
            return false;
        }
        const std::wstring kParkingRoot = startupParkingRoot(metadataHive);
        if (kParkingRoot.empty())
        {
            return false;
        }
        const std::wstring kExpectedParkedPath =
            (std::filesystem::path(kParkingRoot) / backupId / std::filesystem::path(record.originalPath).filename()).wstring();
        if (!equalPathI(kExpectedParkedPath, record.parkedPath))
        {
            return false;
        }
        recordOut = std::move(record);
        return true;
    }

    bool readStartupFolderBackupById(
        HKEY metadataHive,
        const std::wstring& backupId,
        StartupFolderBackupRecord& recordOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (!isSafeBackupId(backupId))
        {
            errorCodeOut = ERROR_INVALID_NAME;
            return false;
        }
        HKEY recordKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            metadataHive,
            metadataRecordPath(kStartupFolderBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE,
            &recordKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            errorCodeOut = static_cast<DWORD>(kOpenResult);
            return false;
        }
        const bool kReadOk = readStartupFolderBackupMetadata(
            metadataHive,
            recordKey,
            backupId,
            recordOut);
        ::RegCloseKey(recordKey);
        if (!kReadOk)
        {
            errorCodeOut = ERROR_INVALID_DATA;
        }
        return kReadOk;
    }

    bool startupFolderBackupRecordsEqual(
        const StartupFolderBackupRecord& left,
        const StartupFolderBackupRecord& right)
    {
        return left.backupId == right.backupId
            && equalPathI(left.originalPath, right.originalPath)
            && equalPathI(left.parkedPath, right.parkedPath)
            && left.itemName == right.itemName
            && left.state == right.state;
    }

    LONG createUniqueStartupFolderBackup(
        const std::wstring& originalPath,
        StartupFolderBackupRecord& recordOut,
        HKEY& recordKeyOut)
    {
        const HKEY kMetadataHive = startupFolderMetadataHive(originalPath);
        const std::wstring kParkingRoot = startupParkingRoot(kMetadataHive);
        if (kParkingRoot.empty())
        {
            return ERROR_PATH_NOT_FOUND;
        }
        if (kMetadataHive == HKEY_LOCAL_MACHINE)
        {
            const LONG kDirectoryResult = ensureMachineStartupParkingRoot();
            if (kDirectoryResult != ERROR_SUCCESS)
            {
                return kDirectoryResult;
            }
        }
        else
        {
            std::error_code directoryError;
            std::filesystem::create_directories(kParkingRoot, directoryError);
            if (directoryError)
            {
                return static_cast<LONG>(directoryError.value());
            }
        }
        for (int attempt = 0; attempt < 64; ++attempt)
        {
            StartupFolderBackupRecord record;
            record.originalPath = normalizedPathText(originalPath);
            record.itemName = std::filesystem::path(record.originalPath).filename().wstring();
            record.state = kBackupStatePrepared;
            HKEY recordKey = nullptr;
            LONG result = createUniqueMetadataKey(
                kMetadataHive,
                kStartupFolderBackupRoot,
                record.backupId,
                recordKey);
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            const std::wstring kParkingDirectory =
                (std::filesystem::path(kParkingRoot) / record.backupId).wstring();
            record.parkedPath =
                (std::filesystem::path(kParkingDirectory) / record.itemName).wstring();
            if (::CreateDirectoryW(kParkingDirectory.c_str(), nullptr) != FALSE)
            {
                recordOut = std::move(record);
                recordKeyOut = recordKey;
                return ERROR_SUCCESS;
            }
            result = static_cast<LONG>(::GetLastError());
            ::RegCloseKey(recordKey);
            deleteMetadataRecord(kMetadataHive, kStartupFolderBackupRoot, record.backupId);
            if (result != ERROR_ALREADY_EXISTS)
            {
                return result;
            }
        }
        return ERROR_ALREADY_EXISTS;
    }

    void cleanupStartupFolderBackupArtifacts(const StartupFolderBackupRecord& record)
    {
        const HKEY kMetadataHive = startupFolderMetadataHive(record.originalPath);
        const std::wstring kParkingRoot = startupParkingRoot(kMetadataHive);
        if (kMetadataHive == nullptr || !isSafeBackupId(record.backupId) || kParkingRoot.empty())
        {
            return;
        }
        const std::wstring kExpectedDirectory =
            (std::filesystem::path(kParkingRoot) / record.backupId).wstring();
        const std::wstring kActualDirectory =
            std::filesystem::path(record.parkedPath).parent_path().wstring();
        const std::wstring kExpectedParkedPath =
            (std::filesystem::path(kExpectedDirectory) / record.itemName).wstring();
        if (!equalPathI(kExpectedDirectory, kActualDirectory)
            || !equalPathI(kExpectedParkedPath, record.parkedPath))
        {
            return;
        }
        const DWORD kAttributes = ::GetFileAttributesW(kExpectedDirectory.c_str());
        if (kAttributes == INVALID_FILE_ATTRIBUTES)
        {
            const DWORD kErrorCode = ::GetLastError();
            if (kErrorCode == ERROR_FILE_NOT_FOUND || kErrorCode == ERROR_PATH_NOT_FOUND)
            {
                deleteMetadataRecord(kMetadataHive, kStartupFolderBackupRoot, record.backupId);
            }
            return;
        }
        if ((kAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            || (kAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return;
        }
        if (::RemoveDirectoryW(kExpectedDirectory.c_str()) != FALSE)
        {
            deleteMetadataRecord(kMetadataHive, kStartupFolderBackupRoot, record.backupId);
        }
    }

    ks::startup::ActionResult disableStartupFolderEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring kOriginalPath = toWide(entry.actionLocator.originalFilePathText);
        const HKEY kMetadataHive = startupFolderMetadataHive(kOriginalPath);
        if (!entry.actionLocator.backupIdText.empty()
            || !entry.actionLocator.parkedFilePathText.empty()
            || kMetadataHive == nullptr)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"启动文件夹操作定位器无效，或目标不在 Windows 启动文件夹内。"));
        }
        if (!isRegularFileWide(kOriginalPath))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNotFound,
                false,
                false,
                ERROR_FILE_NOT_FOUND,
                fromWide(L"启动文件夹中的文件已不存在。"));
        }
        if (entry.actionLocator.fileIdentitySnapshotValid)
        {
            FileIdentitySnapshot observedIdentity;
            DWORD identityError = ERROR_SUCCESS;
            const bool kIdentityValid = queryFileIdentityNoReparse(
                kOriginalPath,
                observedIdentity,
                identityError);
            const bool kIdentityMatches = kIdentityValid
                && observedIdentity.volumeSerial == entry.actionLocator.fileVolumeSerial
                && observedIdentity.fileIndex == entry.actionLocator.fileIndex
                && observedIdentity.fileSize == entry.actionLocator.fileSize
                && observedIdentity.lastWriteTime == entry.actionLocator.fileLastWriteTime;
            if (!kIdentityMatches)
            {
                return makeActionResult(
                    ks::startup::StartupActionStatus::kConflict,
                    false,
                    false,
                    kIdentityValid ? ERROR_REVISION_MISMATCH : identityError,
                    fromWide(L"启动文件已在枚举后变化；请刷新后重试。"));
            }
        }

        StartupFolderBackupRecord record;
        HKEY recordKey = nullptr;
        LONG result = createUniqueStartupFolderBackup(kOriginalPath, record, recordKey);
        if (result != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法创建唯一的应用专用暂存位置。"));
        }

        result = writeStartupFolderBackupMetadata(recordKey, record);
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        StartupFolderBackupRecord verifiedRecord;
        const bool kMetadataVerified = result == ERROR_SUCCESS
            && readStartupFolderBackupMetadata(
                kMetadataHive,
                recordKey,
                record.backupId,
                verifiedRecord)
            && startupFolderBackupRecordsEqual(record, verifiedRecord);
        if (!kMetadataVerified)
        {
            const DWORD kFailureCode = result == ERROR_SUCCESS ? ERROR_INVALID_DATA : static_cast<DWORD>(result);
            ::RegCloseKey(recordKey);
            cleanupStartupFolderBackupArtifacts(record);
            return makeActionResult(
                statusFromWin32(kFailureCode, ks::startup::StartupActionStatus::kVerificationFailed),
                false,
                false,
                kFailureCode,
                fromWide(L"暂存元数据写入或校验失败；源文件未被移动。"));
        }

        result = moveFileWithoutOverwrite(record.originalPath, record.parkedPath);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(recordKey);
            ks::startup::ActionResult failure = makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法将启动文件夹文件移动到暂存位置。"));
            failure.rollbackAttempted = true;
            if (isRegularFileWide(record.originalPath) && !isRegularFileWide(record.parkedPath))
            {
                failure.rollbackSucceeded = true;
                cleanupStartupFolderBackupArtifacts(record);
            }
            else if (!isRegularFileWide(record.originalPath) && isRegularFileWide(record.parkedPath))
            {
                const LONG kRollbackResult = moveFileWithoutOverwrite(record.parkedPath, record.originalPath);
                failure.rollbackSucceeded = kRollbackResult == ERROR_SUCCESS;
                if (failure.rollbackSucceeded)
                {
                    cleanupStartupFolderBackupArtifacts(record);
                }
                else
                {
                    failure.status = ks::startup::StartupActionStatus::kRollbackFailed;
                    failure.errorCode = static_cast<DWORD>(kRollbackResult);
                }
            }
            else
            {
                failure.status = ks::startup::StartupActionStatus::kRollbackFailed;
                failure.errorCode = ERROR_ALREADY_EXISTS;
            }
            return failure;
        }

        LONG stateResult = setAndVerifyMetadataState(recordKey, kBackupStateDisabled);
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        ::RegCloseKey(recordKey);
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG kRollbackResult = moveFileWithoutOverwrite(record.parkedPath, record.originalPath);
            ks::startup::ActionResult failure = makeActionResult(
                kRollbackResult == ERROR_SUCCESS
                    ? statusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::kWriteFailed)
                    : ks::startup::StartupActionStatus::kRollbackFailed,
                false,
                false,
                kRollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(kRollbackResult),
                kRollbackResult == ERROR_SUCCESS
                    ? fromWide(L"暂存状态提交失败；启动文件夹文件已恢复。")
                    : fromWide(L"暂存状态提交失败，且文件自动回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = kRollbackResult == ERROR_SUCCESS;
            if (failure.rollbackSucceeded)
            {
                cleanupStartupFolderBackupArtifacts(record);
            }
            return failure;
        }

        return makeActionResult(
            ks::startup::StartupActionStatus::kSuccess,
            true,
            true,
            ERROR_SUCCESS,
            fromWide(L"启动文件夹文件已移动到唯一的应用专用暂存位置。"));
    }

    ks::startup::ActionResult enableStartupFolderEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring kBackupId = toWide(entry.actionLocator.backupIdText);
        const HKEY kMetadataHive =
            startupFolderMetadataHive(toWide(entry.actionLocator.originalFilePathText));
        if (kMetadataHive == nullptr)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"启动文件夹恢复记录的完整性范围无效。"));
        }
        StartupFolderBackupRecord record;
        DWORD readError = ERROR_SUCCESS;
        if (!readStartupFolderBackupById(kMetadataHive, kBackupId, record, readError))
        {
            return makeActionResult(
                statusFromWin32(readError, ks::startup::StartupActionStatus::kInvalidEntry),
                false,
                false,
                readError,
                fromWide(L"启动文件夹备份记录缺失、格式无效，或使用了不受支持的版本。"));
        }
        if (record.state == kBackupStateRestored)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"启动文件夹文件已经恢复。"));
        }
        if (record.state != kBackupStateDisabled)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_STATE,
                fromWide(L"暂存事务尚未提交，不能通过此接口恢复。"));
        }
        if (!equalPathI(record.originalPath, toWide(entry.actionLocator.originalFilePathText))
            || !equalPathI(record.parkedPath, toWide(entry.actionLocator.parkedFilePathText)))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_DATA,
                fromWide(L"条目定位器与不可变暂存元数据不匹配。"));
        }
        if (isRegularFileWide(record.originalPath))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_ALREADY_EXISTS,
                fromWide(L"原位置已存在同名文件；未执行覆盖。"));
        }
        if (!isRegularFileWide(record.parkedPath))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNotFound,
                false,
                false,
                ERROR_FILE_NOT_FOUND,
                fromWide(L"暂存的启动文件夹文件缺失。"));
        }

        LONG result = moveFileWithoutOverwrite(record.parkedPath, record.originalPath);
        if (result != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                fromWide(L"无法恢复暂存的启动文件夹文件。"));
        }

        HKEY recordKey = nullptr;
        result = ::RegOpenKeyExW(
            kMetadataHive,
            metadataRecordPath(kStartupFolderBackupRoot, kBackupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        LONG stateResult = result;
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = setAndVerifyMetadataState(recordKey, kBackupStateRestored);
        }
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG kRollbackResult = moveFileWithoutOverwrite(record.originalPath, record.parkedPath);
            ks::startup::ActionResult failure = makeActionResult(
                kRollbackResult == ERROR_SUCCESS
                    ? statusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::kWriteFailed)
                    : ks::startup::StartupActionStatus::kRollbackFailed,
                false,
                false,
                kRollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(kRollbackResult),
                kRollbackResult == ERROR_SUCCESS
                    ? fromWide(L"恢复元数据提交失败；文件已移回暂存位置。")
                    : fromWide(L"恢复元数据提交失败，且文件回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = kRollbackResult == ERROR_SUCCESS;
            return failure;
        }

        const LONG kCleanupResult = deleteMetadataRecord(
            kMetadataHive,
            kStartupFolderBackupRoot,
            kBackupId);
        ::RemoveDirectoryW(std::filesystem::path(record.parkedPath).parent_path().c_str());
        return makeActionResult(
            ks::startup::StartupActionStatus::kSuccess,
            true,
            true,
            kCleanupResult == ERROR_SUCCESS ? ERROR_SUCCESS : static_cast<DWORD>(kCleanupResult),
            kCleanupResult == ERROR_SUCCESS
                ? fromWide(L"启动文件夹文件已恢复，暂存元数据已移除。")
                : fromWide(L"启动文件夹文件已恢复，但无法移除已退役的暂存元数据。"));
    }

    void appendDisabledStartupFolderEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<HKEY, 2> kMetadataHives{ HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        for (const HKEY kMetadataHive : kMetadataHives)
        {
            const std::string kMetadataScope = kMetadataHive == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU";
            for (const std::wstring& backupId : enumerateRegistrySubKeys(kMetadataHive, kStartupFolderBackupRoot))
            {
                StartupFolderBackupRecord record;
                DWORD readError = ERROR_SUCCESS;
                if (!readStartupFolderBackupById(kMetadataHive, backupId, record, readError))
                {
                    ks::startup::StartupEntry invalidEntry;
                    invalidEntry.category = ks::startup::StartupCategory::kLogon;
                    invalidEntry.categoryText = ks::startup::categoryToText(invalidEntry.category);
                    invalidEntry.itemNameText = fromWide(L"KSword 启动文件恢复记录 ") + fromWide(backupId);
                    invalidEntry.detailText =
                        kMetadataScope + "|" + fromWide(L"KSword 暂存记录=") + fromWide(backupId);
                    invalidEntry.sourceTypeText = "StartupFolderBackup";
                    invalidEntry.enabled = false;
                    invalidEntry.uniqueIdText =
                        "STARTUPFOLDER-RECOVERY-INVALID|" + kMetadataScope + "|" + fromWide(backupId);
                    invalidEntry.lastErrorCode = readError;
                    markEntryActionUnavailable(
                        invalidEntry,
                        ks::startup::StartupRiskLevel::kCritical,
                        "backup_record",
                        fromWide(L"启动文件夹恢复元数据损坏、版本不受支持，或元数据完整性范围与目标不匹配。"));
                    entries.push_back(std::move(invalidEntry));
                    continue;
                }
            FileIdentitySnapshot originalIdentity;
            FileIdentitySnapshot parkedIdentity;
            DWORD originalError = ERROR_SUCCESS;
            DWORD parkedError = ERROR_SUCCESS;
            const bool kOriginalExists = queryFileIdentityNoReparse(
                record.originalPath,
                originalIdentity,
                originalError);
            const bool kParkedExists = queryFileIdentityNoReparse(
                record.parkedPath,
                parkedIdentity,
                parkedError);
            bool machineWide = false;
            isKnownStartupFolderFile(record.originalPath, &machineWide);
            DWORD reconciliationError = ERROR_SUCCESS;
            if (record.state == kBackupStatePrepared)
            {
                if (kOriginalExists && !kParkedExists
                    && (parkedError == ERROR_FILE_NOT_FOUND || parkedError == ERROR_PATH_NOT_FOUND))
                {
                    cleanupStartupFolderBackupArtifacts(record);
                    StartupFolderBackupRecord remainingRecord;
                    DWORD remainingError = ERROR_SUCCESS;
                    if (!readStartupFolderBackupById(
                            kMetadataHive,
                            backupId,
                            remainingRecord,
                            remainingError)
                        && remainingError == ERROR_FILE_NOT_FOUND)
                    {
                        continue;
                    }
                    reconciliationError = remainingError == ERROR_SUCCESS
                        ? ERROR_CANNOT_MAKE
                        : remainingError;
                }
                else if (!kOriginalExists && kParkedExists
                    && (originalError == ERROR_FILE_NOT_FOUND || originalError == ERROR_PATH_NOT_FOUND))
                {
                    reconciliationError = static_cast<DWORD>(
                        commitMetadataStateById(
                            kMetadataHive,
                            kStartupFolderBackupRoot,
                            backupId,
                            kBackupStateDisabled));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        record.state = kBackupStateDisabled;
                    }
                }
            }

            ks::startup::StartupEntry entry;
            entry.category = ks::startup::StartupCategory::kLogon;
            entry.categoryText = ks::startup::categoryToText(entry.category);
            entry.itemNameText = record.itemName.empty()
                ? fromWide(std::filesystem::path(record.originalPath).filename().wstring())
                : fromWide(record.itemName);
            entry.commandText = toNativeSeparators(fromWide(record.originalPath));
            entry.imagePathText = toNativeSeparators(fromWide(record.parkedPath));
            entry.publisherText = kParkedExists
                ? ks::startup::queryPublisherTextByPath(entry.imagePathText)
                : std::string();
            entry.locationText = toNativeSeparators(fromWide(std::filesystem::path(record.originalPath).parent_path().wstring()));
            entry.userText = machineWide ? fromWide(L"\u672c\u673a") : fromWide(L"\u5f53\u524d\u7528\u6237");
            entry.sourceTypeText = "StartupFolder";
            entry.detailText =
                kMetadataScope + "|" + fromWide(L"KSword 暂存=") + fromWide(record.parkedPath);
            entry.enabled = false;
            entry.canOpenFileLocation = kParkedExists;
            entry.canDelete = false;
            entry.imagePathExists = kParkedExists;
            entry.uniqueIdText =
                "STARTUPFOLDER-RECOVERY|" + kMetadataScope + "|" + fromWide(backupId);
            entry.lastErrorCode = reconciliationError != ERROR_SUCCESS
                ? reconciliationError
                : (!kOriginalExists && originalError != ERROR_FILE_NOT_FOUND
                    && originalError != ERROR_PATH_NOT_FOUND
                    ? originalError
                    : (!kParkedExists && parkedError != ERROR_FILE_NOT_FOUND
                        && parkedError != ERROR_PATH_NOT_FOUND
                        ? parkedError
                        : ERROR_SUCCESS));
            std::string reasonCode = machineWide ? "machine_scope" : "backup_record";
            std::string reasonText;
            if (machineWide)
            {
                reasonText = fromWide(L"恢复公共启动文件夹中的文件需要管理员权限，并会影响所有用户。");
            }
            else if (record.state == kBackupStatePrepared && kOriginalExists && !kParkedExists)
            {
                reasonText = fromWide(L"Prepared 操作尚未发生，但安全清理暂存记录失败；记录保持可见。");
            }
            else if (record.state == kBackupStatePrepared && !kOriginalExists && kParkedExists)
            {
                reasonText = fromWide(L"Prepared 记录对应文件已被暂存，但提交 Disabled 状态失败；记录保持可见。");
            }
            else if (kOriginalExists && kParkedExists)
            {
                reasonText = fromWide(L"原位置与暂存位置同时存在文件；恢复操作会拒绝覆盖原位置文件。");
            }
            else if (kOriginalExists)
            {
                reasonText = fromWide(L"原位置已存在文件；恢复操作会拒绝覆盖该文件。");
            }
            else if (!kParkedExists)
            {
                reasonText = fromWide(L"原位置与暂存位置均无可验证普通文件；恢复操作预计会失败。");
            }
            else
            {
                reasonText = fromWide(L"暂存记录已完成对账；警告确认后可以将文件移回启动文件夹。");
            }
            if (record.state == kBackupStateDisabled)
            {
                entry.actionKind = ks::startup::StartupActionKind::kStartupFolderFile;
                entry.actionLocator.originalFilePathText =
                    toNativeSeparators(fromWide(record.originalPath));
                entry.actionLocator.parkedFilePathText =
                    toNativeSeparators(fromWide(record.parkedPath));
                entry.actionLocator.backupIdText = fromWide(backupId);
                entry.canEnable = true;
                entry.canDisable = false;
                entry.riskLevel = machineWide
                    ? ks::startup::StartupRiskLevel::kCritical
                    : ks::startup::StartupRiskLevel::kElevated;
                entry.riskReasonCode = reasonCode;
                entry.riskReasonText = reasonText;
            }
            else
            {
                markEntryActionUnavailable(
                    entry,
                    ks::startup::StartupRiskLevel::kCritical,
                    reasonCode,
                    reasonText);
            }
            entries.push_back(std::move(entry));
            }
        }
    }
}

namespace
{
    std::wstring quotePowerShellLiteral(const std::wstring& text)
    {
        std::wstring escaped;
        escaped.reserve(text.size() + 2);
        escaped.push_back(L'\'');
        for (const wchar_t kCh : text)
        {
            escaped.push_back(kCh);
            if (kCh == L'\'')
            {
                escaped.push_back(L'\'');
            }
        }
        escaped.push_back(L'\'');
        return escaped;
    }

    bool isValidScheduledTaskLocator(const std::wstring& taskPath, const std::wstring& taskName)
    {
        const auto kContainsWildcard = [](const std::wstring& text) {
            return text.find_first_of(L"*?[]") != std::wstring::npos;
        };
        return !taskPath.empty()
            && taskPath.front() == L'\\'
            && taskPath.back() == L'\\'
            && taskPath.find(L'\0') == std::wstring::npos
            && !kContainsWildcard(taskPath)
            && !taskName.empty()
            && taskName.find(L'\0') == std::wstring::npos
            && taskName.find(L'\\') == std::wstring::npos
            && !kContainsWildcard(taskName);
    }

    std::wstring taskIdentityPowerShellFunction()
    {
        return LR"PS(
$ProgressPreference='SilentlyContinue'
function Get-KSwordTaskIdentityHash($task) {
  [xml]$document = [string](ScheduledTasks\Export-ScheduledTask -InputObject $task -ErrorAction Stop)
  $enabledNode = $document.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']")
  if ($null -ne $enabledNode) { $null = $enabledNode.ParentNode.RemoveChild($enabledNode) }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($document.OuterXml))
    ).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}
function Get-KSwordTaskEnabled($task) {
  if ($null -ne $task.Settings -and $null -ne $task.Settings.Enabled) {
    return [bool]$task.Settings.Enabled
  }
  return ([string]$task.State -ne 'Disabled')
}
function Test-KSwordBootOrLogon($task) {
  $kinds = @($task.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  return @($kinds | Where-Object {
    $_ -eq 'MSFT_TaskBootTrigger' -or $_ -eq 'MSFT_TaskLogonTrigger'
  }).Count -gt 0
}
)PS";
    }

    std::wstring buildSetTaskEnabledPowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash,
        const bool enabled)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += taskIdentityPowerShellFunction();
        script += LR"PS(
$taskPath = )PS";
        script += quotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += quotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += quotePowerShellLiteral(expectedHash);
        script += L"\n$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)";
        script += L"\n$desiredEnabled = ";
        script += enabled ? L"$true\n" : L"$false\n";
        script += LR"PS(
try {
$scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
$task = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_UNSUPPORTED'; exit 12 }
if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) { 'KSWORD_STALE'; exit 13 }
$currentEnabled = Get-KSwordTaskEnabled $task
if ($currentEnabled -eq $desiredEnabled) { 'KSWORD_NO_CHANGE'; exit 0 }
if ($currentEnabled) { 'KSWORD_ORIGINAL_ENABLED' } else { 'KSWORD_ORIGINAL_DISABLED' }
'KSWORD_MUTATION_ATTEMPTED'
[Console]::Out.Flush()
if ($desiredEnabled) {
  ScheduledTasks\Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
} else {
  ScheduledTasks\Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
}
$verifyTask = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
if (-not (Test-KSwordBootOrLogon $verifyTask)) { throw 'KSWORD_VERIFY_TRIGGER' }
if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $verifyTask) -ne $expectedHash) { throw 'KSWORD_VERIFY_HASH' }
if ((Get-KSwordTaskEnabled $verifyTask) -ne $desiredEnabled) { throw 'KSWORD_VERIFY_STATE' }
'KSWORD_CHANGED'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_TASK_ERROR'
  exit 1
}
)PS";
        return script;
    }

    std::wstring buildRecoverTaskStatePowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash,
        const bool originalEnabled)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += taskIdentityPowerShellFunction();
        script += LR"PS(
$taskPath = )PS";
        script += quotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += quotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += quotePowerShellLiteral(expectedHash);
        script += L"\n$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)";
        script += L"\n$originalEnabled = ";
        script += originalEnabled ? L"$true\n" : L"$false\n";
        script += LR"PS(
try {
  $scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
  Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
  $task = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
  if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_ROLLBACK_BLOCKED'; exit 21 }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) { 'KSWORD_ROLLBACK_BLOCKED'; exit 22 }
  if ((Get-KSwordTaskEnabled $task) -eq $originalEnabled) {
    'KSWORD_ROLLBACK_NOT_NEEDED'
    exit 0
  }
  if ($originalEnabled) {
    ScheduledTasks\Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
  } else {
    ScheduledTasks\Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
  }
  $verifyTask = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
  if (-not (Test-KSwordBootOrLogon $verifyTask)) { throw 'KSWORD_ROLLBACK_TRIGGER' }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $verifyTask) -ne $expectedHash) { throw 'KSWORD_ROLLBACK_HASH' }
  if ((Get-KSwordTaskEnabled $verifyTask) -ne $originalEnabled) { throw 'KSWORD_ROLLBACK_STATE' }
  'KSWORD_ROLLBACK_OK'
} catch {
  'KSWORD_ROLLBACK_FAILED'
  exit 23
}
)PS";
        return script;
    }

    std::wstring buildDeleteTaskPowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += taskIdentityPowerShellFunction();
        script += LR"PS(
function Test-KSwordTaskNotFoundError($record) {
  $hresult = [int]$record.Exception.HResult
  $errorId = [string]$record.FullyQualifiedErrorId
  return ($hresult -eq -2147024894) -or
    ($hresult -eq -2147024893) -or
    ($errorId -match 'NoMatchingMSFT_Task|CmdletizationQuery_NotFound|ObjectNotFound')
}
$taskPath = )PS";
        script += quotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += quotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += quotePowerShellLiteral(expectedHash);
        script += LR"PS(
$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)
try {
  $scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
  Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
  try {
    $tasks = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop)
  } catch {
    if (Test-KSwordTaskNotFoundError $_) { 'KSWORD_TASK_NOT_FOUND'; exit 0 }
    throw
  }
  if ($tasks.Count -eq 0) { 'KSWORD_TASK_NOT_FOUND'; exit 0 }
  if ($tasks.Count -ne 1) { 'KSWORD_TASK_AMBIGUOUS'; exit 14 }
  $task = $tasks[0]
  if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_UNSUPPORTED'; exit 12 }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) {
    'KSWORD_STALE'
    exit 13
  }
  ScheduledTasks\Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction Stop
  try {
    $remaining = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop)
  } catch {
    if (Test-KSwordTaskNotFoundError $_) { 'KSWORD_TASK_DELETED'; exit 0 }
    throw
  }
  if ($remaining.Count -eq 0) { 'KSWORD_TASK_DELETED'; exit 0 }
  throw 'KSWORD_TASK_VERIFY'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_TASK_ERROR'
  exit 1
}
)PS";
        return script;
    }

    bool queryScmStartType(SC_HANDLE serviceHandle, DWORD& startTypeOut)
    {
        startTypeOut = SERVICE_NO_CHANGE;
        DWORD requiredBytes = 0;
        ::QueryServiceConfigW(serviceHandle, nullptr, 0, &requiredBytes);
        if (requiredBytes == 0)
        {
            return false;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (::QueryServiceConfigW(serviceHandle, config, requiredBytes, &requiredBytes) == FALSE)
        {
            return false;
        }
        startTypeOut = config->dwStartType;
        return true;
    }

    ks::startup::ActionResult setScmEntryEnabled(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        const std::wstring kServiceName = toWide(entry.actionLocator.serviceNameText);
        if (kServiceName.empty()
            || kServiceName.find(L'\0') != std::wstring::npos
            || kServiceName.find_first_of(L"\\/") != std::wstring::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"服务控制管理器定位器无效。"));
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scmHandle == nullptr)
        {
            const DWORD kErrorCode = ::GetLastError();
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法打开服务控制管理器。"));
        }
        SC_HANDLE serviceHandle = ::OpenServiceW(
            scmHandle,
            kServiceName.c_str(),
            SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
        if (serviceHandle == nullptr)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法打开目标服务或驱动。"));
        }

        DWORD currentStartType = SERVICE_NO_CHANGE;
        if (!queryScmStartType(serviceHandle, currentStartType))
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法读取当前服务启动类型。"));
        }
        if (currentStartType != entry.actionLocator.serviceStartType)
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"服务启动类型已在枚举后变化；请刷新后重试。"));
        }

        const DWORD kDesiredStartType = enabled
            ? (entry.actionLocator.serviceIsDriver ? SERVICE_SYSTEM_START : SERVICE_AUTO_START)
            : SERVICE_DISABLED;
        if (currentStartType == kDesiredStartType)
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"服务启动类型已经处于请求的状态。"));
        }

        if (::ChangeServiceConfigW(
                serviceHandle,
                SERVICE_NO_CHANGE,
                kDesiredStartType,
                SERVICE_NO_CHANGE,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"修改服务启动类型失败。"));
        }

        DWORD observedStartType = SERVICE_NO_CHANGE;
        const bool kQuerySucceeded = queryScmStartType(serviceHandle, observedStartType);
        const DWORD kObservedError = kQuerySucceeded ? ERROR_INVALID_DATA : ::GetLastError();
        const bool kVerified = kQuerySucceeded && observedStartType == kDesiredStartType;
        if (!kVerified)
        {
            const DWORD kVerificationError = kObservedError == ERROR_SUCCESS
                ? ERROR_INVALID_DATA
                : kObservedError;
            const bool kRollbackSucceeded = ::ChangeServiceConfigW(
                serviceHandle,
                SERVICE_NO_CHANGE,
                currentStartType,
                SERVICE_NO_CHANGE,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr) != FALSE;
            const DWORD kRollbackError = kRollbackSucceeded ? ERROR_SUCCESS : ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            ks::startup::ActionResult failure = makeActionResult(
                kRollbackSucceeded
                    ? ks::startup::StartupActionStatus::kVerificationFailed
                    : ks::startup::StartupActionStatus::kRollbackFailed,
                false,
                !kRollbackSucceeded,
                kRollbackSucceeded ? kVerificationError : kRollbackError,
                kRollbackSucceeded
                    ? fromWide(L"服务启动类型验证失败；已恢复操作前配置。")
                    : fromWide(L"服务启动类型验证失败，且无法恢复操作前配置。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = kRollbackSucceeded;
            return failure;
        }

        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(scmHandle);
        return makeActionResult(
            ks::startup::StartupActionStatus::kSuccess,
            true,
            true,
            ERROR_SUCCESS,
            fromWide(L"服务启动类型已变更并验证。"));
    }

    bool isAllowedWmiClassName(const std::string& className)
    {
        static const std::array<const char*, 6> kAllowedClassNames{ {
            "CommandLineEventConsumer",
            "ActiveScriptEventConsumer",
            "LogFileEventConsumer",
            "NTEventLogEventConsumer",
            "__EventFilter",
            "__FilterToConsumerBinding"
        } };
        return std::any_of(
            kAllowedClassNames.begin(),
            kAllowedClassNames.end(),
            [&className](const char* allowedName) { return className == allowedName; });
    }

    std::wstring buildRemoveWmiEntryPowerShellScript(
        const ks::startup::StartupActionLocator& locator)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$cimCmdletsModule = Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $cimCmdletsModule -Force -ErrorAction Stop
$className = )PS";
        script += quotePowerShellLiteral(toWide(locator.wmiClassNameText));
        script += L"\n$name = ";
        script += quotePowerShellLiteral(toWide(locator.wmiNameText));
        script += L"\n$filterPath = ";
        script += quotePowerShellLiteral(toWide(locator.wmiFilterText));
        script += L"\n$consumerPath = ";
        script += quotePowerShellLiteral(toWide(locator.wmiConsumerText));
        script += LR"PS(
try {
  $allItems = @(CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName $className -ErrorAction Stop)
  if ($className -eq '__FilterToConsumerBinding') {
    $matches = @($allItems | Where-Object {
      ([string]$_.Filter -eq $filterPath) -and ([string]$_.Consumer -eq $consumerPath)
    })
  } else {
    $matches = @($allItems | Where-Object { [string]$_.Name -eq $name })
  }
  if ($matches.Count -eq 0) { 'KSWORD_WMI_NO_CHANGE'; exit 0 }
  if ($matches.Count -ne 1) { 'KSWORD_WMI_AMBIGUOUS'; exit 14 }
  $matches[0] | CimCmdlets\Remove-CimInstance -ErrorAction Stop
  $verifyItems = @(CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName $className -ErrorAction Stop)
  if ($className -eq '__FilterToConsumerBinding') {
    $remaining = @($verifyItems | Where-Object {
      ([string]$_.Filter -eq $filterPath) -and ([string]$_.Consumer -eq $consumerPath)
    })
  } else {
    $remaining = @($verifyItems | Where-Object { [string]$_.Name -eq $name })
  }
  if ($remaining.Count -ne 0) { throw 'KSWORD_WMI_VERIFY' }
  'KSWORD_WMI_REMOVED'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_WMI_ERROR'
  exit 1
}
)PS";
        return script;
    }

    ks::startup::ActionResult removeWmiEntry(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        if (enabled)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNotSupported,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                fromWide(L"WMI 对象删除后无法由 KSword 自动重建。"));
        }
        if (!isAllowedWmiClassName(entry.actionLocator.wmiClassNameText))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"WMI 修改定位器无效。"));
        }
        const ProcessOutput kOutput = runPowerShellScript(
            buildRemoveWmiEntryPowerShellScript(entry.actionLocator),
            20000);
        const std::string kStdoutText = stripUtf8Bom(ks::str::trimCopy(kOutput.stdoutText));
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_WMI_NO_CHANGE") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"WMI 对象已经不存在。"));
        }
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_WMI_REMOVED") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"WMI 永久事件对象已删除并验证。"));
        }
        if (kStdoutText.find("KSWORD_WMI_AMBIGUOUS") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_DUP_NAME,
                fromWide(L"存在多个匹配的 WMI 对象；为避免误删，未执行修改。"));
        }
        const bool kAccessDenied =
            kStdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD kErrorCode = kAccessDenied
            ? ERROR_ACCESS_DENIED
            : processFailureCode(kOutput);
        return makeActionResult(
            kAccessDenied
                ? ks::startup::StartupActionStatus::kAccessDenied
                : ks::startup::StartupActionStatus::kProcessFailed,
            false,
            false,
            kErrorCode,
            fromWide(L"删除 WMI 永久事件对象失败。"));
    }

    ks::startup::ActionResult setScheduledTaskEnabled(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        const std::wstring kTaskPath = toWide(entry.actionLocator.taskPathText);
        const std::wstring kTaskName = toWide(entry.actionLocator.taskNameText);
        const std::wstring kExpectedHash =
            toWide(lowerAsciiCopy(entry.actionLocator.taskDefinitionSha256Text));
        const bool kHashProvided = !kExpectedHash.empty();
        const bool kValidHash = kExpectedHash.size() == 64
            && std::all_of(kExpectedHash.begin(), kExpectedHash.end(), [](const wchar_t ch) {
                return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
            });
        if (!isValidScheduledTaskLocator(kTaskPath, kTaskName) || (kHashProvided && !kValidHash))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"计划任务定位器无效。"));
        }
        const ProcessOutput kOutput = runPowerShellScript(
            buildSetTaskEnabledPowerShellScript(kTaskPath, kTaskName, kExpectedHash, enabled),
            20000);
        const std::string kStdoutText = stripUtf8Bom(ks::str::trimCopy(kOutput.stdoutText));
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_NO_CHANGE") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"计划任务已经处于请求的状态。"));
        }
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_CHANGED") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"Windows 任务计划程序已变更并校验任务状态。"));
        }
        if (kStdoutText.find("KSWORD_STALE") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"计划任务定义已在枚举后变化；未修改陈旧对象。"));
        }
        if (kStdoutText.find("KSWORD_UNSUPPORTED") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                fromWide(L"计划任务已不再包含 Boot 或 Logon 触发器；请刷新启动项列表。"));
        }

        const bool kAccessDenied =
            kStdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD kErrorCode = kAccessDenied
            ? ERROR_ACCESS_DENIED
            : processFailureCode(kOutput);
        ks::startup::ActionResult failure = makeActionResult(
            kAccessDenied
                ? ks::startup::StartupActionStatus::kAccessDenied
                : ks::startup::StartupActionStatus::kProcessFailed,
            false,
            false,
            kErrorCode,
            fromWide(L"计划任务状态变更失败。"));
        const bool kMutationAttempted =
            kStdoutText.find("KSWORD_MUTATION_ATTEMPTED") != std::string::npos;
        const bool kOriginalEnabled =
            kStdoutText.find("KSWORD_ORIGINAL_ENABLED") != std::string::npos;
        const bool kOriginalDisabled =
            kStdoutText.find("KSWORD_ORIGINAL_DISABLED") != std::string::npos;
        if (!kMutationAttempted || kOriginalEnabled == kOriginalDisabled)
        {
            return failure;
        }

        const ProcessOutput kRecoveryOutput = runPowerShellScript(
            buildRecoverTaskStatePowerShellScript(
                kTaskPath,
                kTaskName,
                kExpectedHash,
                kOriginalEnabled),
            20000);
        const std::string kRecoveryText =
            stripUtf8Bom(ks::str::trimCopy(kRecoveryOutput.stdoutText));
        failure.messageText =
            fromWide(L"计划任务状态变更失败；后端已使用独立进程重查原状态。");
        if (kRecoveryOutput.started && kRecoveryOutput.finished
            && kRecoveryOutput.exitCode == 0
            && kRecoveryText.find("KSWORD_ROLLBACK_NOT_NEEDED") != std::string::npos)
        {
            return failure;
        }
        failure.rollbackAttempted = true;
        failure.rollbackSucceeded = kRecoveryOutput.started
            && kRecoveryOutput.finished
            && kRecoveryOutput.exitCode == 0
            && kRecoveryText.find("KSWORD_ROLLBACK_OK") != std::string::npos;
        if (!failure.rollbackSucceeded)
        {
            failure.status = ks::startup::StartupActionStatus::kRollbackFailed;
            failure.changed = true;
            failure.errorCode = processFailureCode(kRecoveryOutput);
            failure.messageText =
                fromWide(L"计划任务状态变更失败，且独立恢复无法确认已回到原状态。");
        }
        return failure;
    }

    bool isMissingStartupSourceError(const DWORD errorCode)
    {
        return errorCode == ERROR_FILE_NOT_FOUND
            || errorCode == ERROR_PATH_NOT_FOUND
            || errorCode == ERROR_KEY_DELETED
            || errorCode == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    ks::startup::ActionResult deleteStartupFolderFile(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring kPathText = toWide(entry.actionLocator.originalFilePathText);
        if (kPathText.empty()
            || !entry.actionLocator.parkedFilePathText.empty()
            || !isKnownStartupFolderFile(kPathText))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"启动文件删除定位器无效。"));
        }

        HANDLE fileHandle = ::CreateFileW(
            kPathText.c_str(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD kErrorCode = ::GetLastError();
            if (isMissingStartupSourceError(kErrorCode))
            {
                return makeActionResult(
                    ks::startup::StartupActionStatus::kNoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    fromWide(L"启动文件已经不存在。"));
            }
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法打开要永久删除的启动文件。"));
        }

        BY_HANDLE_FILE_INFORMATION information{};
        if (::GetFileInformationByHandle(fileHandle, &information) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseHandle(fileHandle);
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法读取启动文件身份。"));
        }
        if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            ::CloseHandle(fileHandle);
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REPARSE_TAG_INVALID,
                fromWide(L"启动文件已变成目录或重解析点；未执行删除。"));
        }

        ULARGE_INTEGER fileIndex{};
        fileIndex.HighPart = information.nFileIndexHigh;
        fileIndex.LowPart = information.nFileIndexLow;
        ULARGE_INTEGER fileSize{};
        fileSize.HighPart = information.nFileSizeHigh;
        fileSize.LowPart = information.nFileSizeLow;
        ULARGE_INTEGER lastWriteTime{};
        lastWriteTime.HighPart = information.ftLastWriteTime.dwHighDateTime;
        lastWriteTime.LowPart = information.ftLastWriteTime.dwLowDateTime;
        if (entry.actionLocator.fileIdentitySnapshotValid
            && (entry.actionLocator.fileVolumeSerial != information.dwVolumeSerialNumber
                || entry.actionLocator.fileIndex != fileIndex.QuadPart
                || entry.actionLocator.fileSize != fileSize.QuadPart
                || entry.actionLocator.fileLastWriteTime != lastWriteTime.QuadPart))
        {
            ::CloseHandle(fileHandle);
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"启动文件已在枚举后被替换或修改；请刷新后重试。"));
        }

        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfo,
                &disposition,
                sizeof(disposition)) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseHandle(fileHandle);
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法永久删除启动文件。"));
        }
        ::CloseHandle(fileHandle);

        FileIdentitySnapshot remainingIdentity;
        DWORD verifyError = ERROR_SUCCESS;
        if (!queryFileIdentityNoReparse(kPathText, remainingIdentity, verifyError)
            && isMissingStartupSourceError(verifyError))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"启动文件已按句柄永久删除并验证。"));
        }
        return makeActionResult(
            ks::startup::StartupActionStatus::kVerificationFailed,
            false,
            true,
            verifyError == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : verifyError,
            fromWide(L"已提交启动文件删除，但无法确认目标路径保持不存在。"));
    }

    ks::startup::ActionResult deleteRegistryValueEntry(
        const ks::startup::StartupEntry& entry)
    {
        const HKEY kRootKey = nativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring kSubKey = toWide(entry.actionLocator.registrySubKeyText);
        const std::wstring kValueName = toWide(entry.actionLocator.registryValueNameText);
        if (kRootKey == nullptr
            || !isSupportedRunLocation(kRootKey, kSubKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"注册表删除定位器无效。"));
        }

        DWORD expectedType = entry.actionLocator.registryValueType;
        std::vector<std::uint8_t> expectedData = entry.actionLocator.registryRawData;
        if (!entry.actionLocator.registryValueSnapshotValid)
        {
            const LONG kQueryResult = queryRegistryValueRaw(
                kRootKey,
                kSubKey,
                kValueName,
                expectedType,
                expectedData);
            if (isMissingStartupSourceError(static_cast<DWORD>(kQueryResult)))
            {
                return makeActionResult(
                    ks::startup::StartupActionStatus::kNoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    fromWide(L"注册表启动值已经不存在。"));
            }
            if (kQueryResult != ERROR_SUCCESS)
            {
                return makeActionResult(
                    statusFromWin32(
                        static_cast<DWORD>(kQueryResult),
                        ks::startup::StartupActionStatus::kWriteFailed),
                    false,
                    false,
                    static_cast<DWORD>(kQueryResult),
                    fromWide(L"无法读取要永久删除的注册表值。"));
            }
        }

        const LONG kDeleteResult = deleteRegistryValueIfExact(
            kRootKey,
            kSubKey,
            kValueName,
            expectedType,
            expectedData);
        if (kDeleteResult == ERROR_SUCCESS)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"注册表启动值已按原始数据快照永久删除并验证。"));
        }
        if (isMissingStartupSourceError(static_cast<DWORD>(kDeleteResult)))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"注册表启动值已经不存在。"));
        }
        if (kDeleteResult == ERROR_ALREADY_EXISTS)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"注册表值已在枚举后变化；未删除陈旧目标。"));
        }
        return makeActionResult(
            statusFromWin32(
                static_cast<DWORD>(kDeleteResult),
                ks::startup::StartupActionStatus::kWriteFailed),
            false,
            false,
            static_cast<DWORD>(kDeleteResult),
            fromWide(L"无法永久删除注册表启动值。"));
    }

    ks::startup::ActionResult deleteRegistryTreeEntry(
        const ks::startup::StartupEntry& entry)
    {
        const HKEY kRootKey = nativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring kSubKey = toWide(entry.actionLocator.registrySubKeyText);
        if (kRootKey == nullptr
            || !isSupportedRunLocation(kRootKey, kSubKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"注册表子树删除定位器无效。"));
        }

        ks::startup::StartupActionLocator currentSnapshot;
        const LONG kSnapshotResult = queryRegistryTreeSnapshot(kRootKey, kSubKey, currentSnapshot);
        if (isMissingStartupSourceError(static_cast<DWORD>(kSnapshotResult)))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"注册表子树已经不存在。"));
        }
        if (kSnapshotResult != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(
                    static_cast<DWORD>(kSnapshotResult),
                    ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(kSnapshotResult),
                fromWide(L"无法读取要永久删除的注册表子树快照。"));
        }
        if (entry.actionLocator.registryTreeSnapshotValid
            && (entry.actionLocator.registryTreeSubKeyCount
                    != currentSnapshot.registryTreeSubKeyCount
                || entry.actionLocator.registryTreeValueCount
                    != currentSnapshot.registryTreeValueCount
                || entry.actionLocator.registryTreeLastWriteTime
                    != currentSnapshot.registryTreeLastWriteTime))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"注册表子树已在枚举后变化；未删除陈旧目标。"));
        }

        const LONG kDeleteResult = ::RegDeleteTreeW(kRootKey, kSubKey.c_str());
        if (isMissingStartupSourceError(static_cast<DWORD>(kDeleteResult)))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"注册表子树已经不存在。"));
        }
        if (kDeleteResult != ERROR_SUCCESS)
        {
            return makeActionResult(
                statusFromWin32(
                    static_cast<DWORD>(kDeleteResult),
                    ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                static_cast<DWORD>(kDeleteResult),
                fromWide(L"无法永久删除注册表子树。"));
        }

        HKEY verifyKey = nullptr;
        const LONG kVerifyResult = ::RegOpenKeyExW(
            kRootKey,
            kSubKey.c_str(),
            0,
            KEY_QUERY_VALUE,
            &verifyKey);
        if (verifyKey != nullptr)
        {
            ::RegCloseKey(verifyKey);
        }
        if (isMissingStartupSourceError(static_cast<DWORD>(kVerifyResult)))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"注册表子树已按结构化定位器永久删除并验证。"));
        }
        return makeActionResult(
            ks::startup::StartupActionStatus::kVerificationFailed,
            false,
            true,
            kVerifyResult == ERROR_SUCCESS
                ? ERROR_ALREADY_EXISTS
                : static_cast<DWORD>(kVerifyResult),
            fromWide(L"已提交注册表子树删除，但无法确认目标保持不存在。"));
    }

    bool queryScmConfigurationSnapshot(
        SC_HANDLE serviceHandle,
        DWORD& serviceTypeOut,
        DWORD& startTypeOut,
        std::string& binaryPathTextOut,
        DWORD& errorCodeOut)
    {
        serviceTypeOut = 0;
        startTypeOut = SERVICE_NO_CHANGE;
        binaryPathTextOut.clear();
        errorCodeOut = ERROR_SUCCESS;
        DWORD requiredBytes = 0;
        ::QueryServiceConfigW(serviceHandle, nullptr, 0, &requiredBytes);
        if (requiredBytes == 0)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (::QueryServiceConfigW(
                serviceHandle,
                config,
                requiredBytes,
                &requiredBytes) == FALSE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        serviceTypeOut = config->dwServiceType;
        startTypeOut = config->dwStartType;
        binaryPathTextOut = queryServiceBinaryPathText(*config);
        return true;
    }

    ks::startup::ActionResult deleteScmEntry(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring kServiceName = toWide(entry.actionLocator.serviceNameText);
        if (kServiceName.empty()
            || kServiceName.find(L'\0') != std::wstring::npos
            || kServiceName.find_first_of(L"\\/") != std::wstring::npos
            || entry.actionLocator.serviceType == 0)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"服务删除定位器无效。"));
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scmHandle == nullptr)
        {
            const DWORD kErrorCode = ::GetLastError();
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法打开服务控制管理器。"));
        }
        SC_HANDLE serviceHandle = ::OpenServiceW(
            scmHandle,
            kServiceName.c_str(),
            SERVICE_QUERY_CONFIG | DELETE);
        if (serviceHandle == nullptr)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseServiceHandle(scmHandle);
            if (isMissingStartupSourceError(kErrorCode)
                || kErrorCode == ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                return makeActionResult(
                    ks::startup::StartupActionStatus::kNoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    fromWide(L"服务或驱动已经不存在，或已标记为删除。"));
            }
            return makeActionResult(
                statusFromWin32(kErrorCode, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                kErrorCode,
                fromWide(L"无法打开要永久删除的服务或驱动。"));
        }

        DWORD currentServiceType = 0;
        DWORD currentStartType = SERVICE_NO_CHANGE;
        DWORD queryError = ERROR_SUCCESS;
        std::string currentBinaryPathText;
        if (!queryScmConfigurationSnapshot(
                serviceHandle,
                currentServiceType,
                currentStartType,
                currentBinaryPathText,
                queryError))
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                statusFromWin32(queryError, ks::startup::StartupActionStatus::kWriteFailed),
                false,
                false,
                queryError,
                fromWide(L"无法读取服务或驱动配置快照。"));
        }
        if (currentServiceType != entry.actionLocator.serviceType
            || currentStartType != entry.actionLocator.serviceStartType
            || !equalWideI(
                toWide(currentBinaryPathText),
                toWide(entry.actionLocator.serviceBinaryPathText)))
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"服务或驱动配置已在枚举后变化；未删除陈旧目标。"));
        }

        const BOOL kDeleteOk = ::DeleteService(serviceHandle);
        const DWORD kDeleteError = kDeleteOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(scmHandle);
        if (kDeleteOk != FALSE)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"服务或驱动已由原始 SCM 句柄标记为永久删除。"));
        }
        if (kDeleteError == ERROR_SERVICE_MARKED_FOR_DELETE
            || isMissingStartupSourceError(kDeleteError))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"服务或驱动已经不存在，或已标记为删除。"));
        }
        return makeActionResult(
            statusFromWin32(kDeleteError, ks::startup::StartupActionStatus::kWriteFailed),
            false,
            false,
            kDeleteError,
            fromWide(L"无法永久删除服务或驱动。"));
    }

    ks::startup::ActionResult deleteScheduledTaskEntry(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring kTaskPath = toWide(entry.actionLocator.taskPathText);
        const std::wstring kTaskName = toWide(entry.actionLocator.taskNameText);
        const std::wstring kExpectedHash =
            toWide(lowerAsciiCopy(entry.actionLocator.taskDefinitionSha256Text));
        const bool kHashProvided = !kExpectedHash.empty();
        const bool kValidHash = kExpectedHash.size() == 64
            && std::all_of(kExpectedHash.begin(), kExpectedHash.end(), [](const wchar_t ch) {
                return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
            });
        if (!isValidScheduledTaskLocator(kTaskPath, kTaskName)
            || (kHashProvided && !kValidHash))
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kInvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                fromWide(L"计划任务删除定位器无效。"));
        }

        const ProcessOutput kOutput = runPowerShellScript(
            buildDeleteTaskPowerShellScript(kTaskPath, kTaskName, kExpectedHash),
            20000);
        const std::string kStdoutText =
            stripUtf8Bom(ks::str::trimCopy(kOutput.stdoutText));
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_TASK_NOT_FOUND") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kNoChange,
                true,
                false,
                ERROR_SUCCESS,
                fromWide(L"计划任务已经不存在。"));
        }
        if (kOutput.started && kOutput.finished && kOutput.exitCode == 0
            && kStdoutText.find("KSWORD_TASK_DELETED") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kSuccess,
                true,
                true,
                ERROR_SUCCESS,
                fromWide(L"计划任务已按路径、名称和定义快照永久删除并验证。"));
        }
        if (kStdoutText.find("KSWORD_STALE") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                fromWide(L"计划任务定义已在枚举后变化；未删除陈旧目标。"));
        }
        if (kStdoutText.find("KSWORD_UNSUPPORTED") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                fromWide(L"计划任务已不再包含 Boot 或 Logon 触发器；请刷新启动项列表。"));
        }
        if (kStdoutText.find("KSWORD_TASK_AMBIGUOUS") != std::string::npos)
        {
            return makeActionResult(
                ks::startup::StartupActionStatus::kConflict,
                false,
                false,
                ERROR_DUP_NAME,
                fromWide(L"计划任务定位器匹配到多个对象；未执行删除。"));
        }

        const bool kAccessDenied =
            kStdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD kErrorCode = kAccessDenied
            ? ERROR_ACCESS_DENIED
            : processFailureCode(kOutput);
        return makeActionResult(
            kAccessDenied
                ? ks::startup::StartupActionStatus::kAccessDenied
                : ks::startup::StartupActionStatus::kProcessFailed,
            false,
            false,
            kErrorCode,
            fromWide(L"永久删除计划任务失败。"));
    }
}

namespace ks::startup
{
    std::string categoryToText(const StartupCategory category)
    {
        switch (category)
        {
        case StartupCategory::kAll:
            return fromWide(L"\u603b\u89c8");
        case StartupCategory::kLogon:
            return fromWide(L"\u767b\u5f55");
        case StartupCategory::kServices:
            return fromWide(L"\u670d\u52a1");
        case StartupCategory::kDrivers:
            return fromWide(L"\u9a71\u52a8");
        case StartupCategory::kTasks:
            return fromWide(L"\u8ba1\u5212\u4efb\u52a1");
        case StartupCategory::kImageHijack:
            return fromWide(L"映像劫持");
        case StartupCategory::kRegistry:
            return fromWide(L"\u9ad8\u7ea7\u6ce8\u518c\u8868");
        case StartupCategory::kWmi:
            return "WMI";
        case StartupCategory::kHidden:
            return fromWide(L"隐藏项");
        default:
            return fromWide(L"\u672a\u77e5");
        }
    }

    std::string normalizeFilePathText(const std::string& commandText)
    {
        std::wstring text = trimWide(toWide(commandText));
        if (text.empty())
        {
            return std::string();
        }
        text = expandEnvironmentWide(text);
        if (text.starts_with(L"\\??\\"))
        {
            text.erase(0, 4);
        }
        if (text.starts_with(L"\\SystemRoot\\"))
        {
            const std::wstring kSystemRoot = queryEnvironmentWide(L"SystemRoot");
            if (!kSystemRoot.empty())
            {
                text = kSystemRoot + text.substr(std::wstring(L"\\SystemRoot").size());
            }
        }
        if (!text.empty() && text.front() == L'\"')
        {
            const std::size_t kEndQuote = text.find(L'\"', 1);
            if (kEndQuote != std::wstring::npos && kEndQuote > 1)
            {
                return toNativeSeparators(fromWide(text.substr(1, kEndQuote - 1)));
            }
        }
        const std::wstring kLowerText = lowerWideCopy(text);
        for (const std::wstring& extension : { L".exe", L".dll", L".sys" })
        {
            const std::size_t kIndex = kLowerText.find(extension);
            if (kIndex != std::wstring::npos && kIndex > 0)
            {
                return toNativeSeparators(fromWide(text.substr(0, kIndex + extension.size())));
            }
        }
        const std::size_t kSpaceIndex = text.find(L' ');
        if (kSpaceIndex != std::wstring::npos && kSpaceIndex > 0)
        {
            return toNativeSeparators(fromWide(text.substr(0, kSpaceIndex)));
        }
        return toNativeSeparators(fromWide(text));
    }

    std::string queryPublisherTextByPath(const std::string& filePathText)
    {
        const std::string kTrimmedPath = ks::str::trimCopy(filePathText);
        if (kTrimmedPath.empty() || !fileExists(kTrimmedPath))
        {
            return std::string();
        }
        const std::string kCompanyName = queryCompanyNameByVersion(kTrimmedPath);
        const bool kTrusted = isFileTrustedByWindows(kTrimmedPath);
        if (!kCompanyName.empty())
        {
            return kCompanyName + (kTrusted ? " (Trusted)" : " (Untrusted)");
        }
        return kTrusted ? "Signed (Trusted)" : std::string();
    }

    std::string normalizeRegistryLocationLine(const std::string& rawLineText)
    {
        std::string text = ks::str::trimCopy(rawLineText);
        if (text.empty() || (!startsWithI(text, "HKLM") && !startsWithI(text, "HKCU") && !startsWithI(text, "HKCR")))
        {
            return std::string();
        }
        std::replace(text.begin(), text.end(), '/', '\\');
        text = std::regex_replace(
            text,
            std::regex("^(HKLM|HKCU|HKCR)\\s+(SOFTWARE|SYSTEM|Software|System|Classes|Environment|Control Panel)", std::regex_constants::icase),
            "$1\\$2");
        text = std::regex_replace(text, std::regex("\\s*\\\\\\s*"), "\\");
        text = std::regex_replace(text, std::regex("\\\\{2,}"), "\\");
        const std::array<std::pair<const char*, const char*>, 28> kReplacements{ {
            { "HKLMSOFTWARE", "HKLM\\SOFTWARE" }, { "HKLMSoftware", "HKLM\\Software" }, { "HKLMSystem", "HKLM\\System" }, { "HKLMSYSTEM", "HKLM\\SYSTEM" },
            { "HKCU\\SOFTWAREClasses", "HKCU\\SOFTWARE\\Classes" }, { "HKCU\\SOFTWARE Classes", "HKCU\\SOFTWARE\\Classes" }, { "HKLM\\SOFTWAREWow6432Node", "HKLM\\SOFTWARE\\Wow6432Node" },
            { "SOFTWAREClasses", "SOFTWARE\\Classes" }, { "SOFTWARE Classes", "SOFTWARE\\Classes" }, { "ShelllconOverlayldentifiers", "ShellIconOverlayIdentifiers" },
            { "Catalog Entries64", "Catalog_Entries64" }, { "Folder ShellEx", "Folder\\ShellEx" }, { "Explorer ShellExecuteHooks", "Explorer\\ShellExecuteHooks" },
            { "Explorer ShellServiceObjects", "Explorer\\ShellServiceObjects" }, { "ShellExecute Hooks", "ShellExecuteHooks" }, { "Internet ExplorerExtensions", "Internet Explorer\\Extensions" },
            { "Intemet", "Internet" }, { "Interet", "Internet" }, { "Userlnit", "Userinit" }, { "Scmsave.exe", "Scrnsave.exe" }, { "AutoStartDisconnect", "AutoStartOnDisconnect" },
            { "Appinit Dlls", "AppInit_DLLs" }, { "Appinit_Dlls", "AppInit_DLLs" }, { "Session Manager\\SOInitialCommand", "Session Manager\\S0InitialCommand" },
            { "HKCU\\Software\\Classes\\M\\ShellEx\\ContextMenuHandlers", "HKCU\\Software\\Classes\\*\\ShellEx\\ContextMenuHandlers" },
            { "HKCU\\Software\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKCU\\Software\\Classes\\*\\ShellEx\\PropertySheetHandlers" },
            { "HKLM\\Software\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKLM\\Software\\Classes\\*\\ShellEx\\PropertySheetHandlers" },
            { "HKLM\\Software\\Wow6432Node\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKLM\\Software\\Wow6432Node\\Classes\\*\\ShellEx\\PropertySheetHandlers" }
        } };
        for (const auto& rule : kReplacements)
        {
            replaceAllI(text, rule.first, rule.second);
        }
        text = std::regex_replace(
            text,
            std::regex("\\\\CLSID\\\\\\{?\\(?([0-9A-Fa-f\\-]{36})\\)?\\}?\\\\"),
            "\\\\CLSID\\\\{$1}\\\\");
        if ((startsWithI(text, "HKLM") || startsWithI(text, "HKCU") || startsWithI(text, "HKCR")) && text.size() > 4 && text[4] != '\\')
        {
            text.insert(4, "\\");
        }
        text = std::regex_replace(text, std::regex("\\s*\\\\\\s*"), "\\");
        text = std::regex_replace(text, std::regex("\\\\{2,}"), "\\");
        text = ks::str::trimCopy(text);
        if (!startsWithI(text, "HKLM\\") && !startsWithI(text, "HKCU\\") && !startsWithI(text, "HKCR\\"))
        {
            return std::string();
        }
        text.replace(0, 4, lowerAsciiCopy(text.substr(0, 4)) == "hklm" ? "HKLM" : (lowerAsciiCopy(text.substr(0, 4)) == "hkcu" ? "HKCU" : "HKCR"));
        replaceAllI(text, "}\\)\\InProcServer32", "}\\InProcServer32");
        replaceAllI(text, "}\\)\\Instance", "}\\Instance");
        if (lowerAsciiCopy(text).ends_with("\\(default)"))
        {
            text.erase(text.size() - std::string("\\(Default)").size());
        }
        return text;
    }

    std::vector<std::string> buildKnownStartupRegistryLocationList(const std::vector<std::string>& rawLineList)
    {
        std::vector<std::string> locations;
        std::vector<std::string> dedupeKeys;
        for (const std::string& rawLine : rawLineList)
        {
            const std::string kNormalized = normalizeRegistryLocationLine(rawLine);
            if (kNormalized.empty())
            {
                continue;
            }
            const std::string kKey = lowerAsciiCopy(kNormalized);
            if (std::find(dedupeKeys.begin(), dedupeKeys.end(), kKey) != dedupeKeys.end())
            {
                continue;
            }
            dedupeKeys.push_back(kKey);
            locations.push_back(kNormalized);
        }
        return locations;
    }

    std::vector<StartupEntry> enumerateLogonEntries()
    {
        std::vector<StartupEntry> entries;
        for (const RunKeySpec& spec : buildRunKeySpecList())
        {
            const std::wstring kSubKeyText(spec.subKeyText);
            for (const RegistryValueRecord& valueRecord : enumerateRegistryValues(spec.rootKey, kSubKeyText))
            {
                if (ks::str::trimCopy(valueRecord.valueDataText).empty())
                {
                    continue;
                }
                if (endsWithI(kSubKeyText, L"\\Windows"))
                {
                    const std::string kLowerName = lowerAsciiCopy(ks::str::trimCopy(valueRecord.valueNameText));
                    if (kLowerName != "run" && kLowerName != "load")
                    {
                        continue;
                    }
                }
                if (endsWithI(kSubKeyText, L"Command Processor") && lowerAsciiCopy(valueRecord.valueNameText) != "autorun")
                {
                    continue;
                }
                appendValueBasedLogonEntry(entries, spec, valueRecord);
            }
        }
        appendRunOnceExEntries(entries);
        appendStartupFolderEntries(entries);
        // Script and add-in files execute at logon without any registry pointer of their own.
        appendScriptFileEntries(entries);
        appendDisabledRegistryRunEntries(entries);
        appendDisabledStartupFolderEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> enumerateServiceEntries()
    {
        return enumerateScmEntries(false);
    }

    std::vector<StartupEntry> enumerateDriverEntries()
    {
        return enumerateScmEntries(true);
    }

    std::vector<StartupEntry> enumerateTaskEntries()
    {
        std::vector<StartupEntry> entries;
        const ProcessOutput kOutput = runPowerShellScript(buildTaskPowerShellScript(), 20000);
        if (!kOutput.started || !kOutput.finished || kOutput.stdoutText.empty())
        {
            return entries;
        }
        bool parseOk = false;
        const std::vector<JsonValue> kTaskObjects = parseJsonObjects(stripUtf8Bom(ks::str::trimCopy(kOutput.stdoutText)), &parseOk);
        if (!parseOk)
        {
            return entries;
        }
        for (const JsonValue& taskObject : kTaskObjects)
        {
            appendScheduledTaskJsonObject(entries, taskObject);
        }
        return entries;
    }

    std::vector<StartupEntry> enumerateImageHijackEntries()
    {
        std::vector<StartupEntry> entries;
        for (const IfeoRegistryViewSpec& viewSpec : buildIfeoRegistryViewSpecList())
        {
            appendIfeoViewEntries(entries, viewSpec);
        }
        appendSilentProcessExitEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> enumerateAdvancedRegistryEntries()
    {
        std::vector<StartupEntry> entries;
        appendSingleValueEntries(entries);
        appendValueEnumEntries(entries);
        appendSubKeyValueEntries(entries);
        // Policy scripts sit three levels deep, so they need their own walker.
        appendGroupPolicyScriptEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> enumerateWinsockEntries()
    {
        std::vector<StartupEntry> entries;
        for (const WinsockKeySpec& spec : buildWinsockKeySpecList())
        {
            const std::wstring kRootSubKey(spec.subKeyText);
            const std::string kGroupLocationText = buildRegistryLocationText(spec.rootKey, kRootSubKey);
            for (const std::wstring& subKeyName : enumerateRegistrySubKeys(spec.rootKey, kRootSubKey))
            {
                const std::wstring kItemSubKey = kRootSubKey + L"\\" + subKeyName;
                const std::string kSubKeyNameText = fromWide(subKeyName);
                const std::vector<std::string> kValueTexts = enumerateRegistryValueTextList(spec.rootKey, kItemSubKey);
                StartupEntry entry;
                entry.category = StartupCategory::kRegistry;
                entry.categoryText = categoryToText(entry.category);
                entry.itemNameText = fromWide(L"Winsock \u9879 ") + kSubKeyNameText;
                entry.commandText = joinStrings(kValueTexts, fromWide(L"\uff1b"));
                entry.locationText = buildRegistryLocationText(spec.rootKey, kItemSubKey);
                entry.locationGroupText = kGroupLocationText;
                entry.userText = fromWide(spec.userText);
                entry.detailText = fromWide(spec.detailText) + fromWide(L"\uff1b\u952e\u503c\u6570\u91cf=") + std::to_string(kValueTexts.size());
                entry.sourceTypeText = spec.sourceTypeText;
                entry.enabled = true;
                entry.canOpenFileLocation = false;
                entry.canOpenRegistryLocation = true;
                configureRegistryTreeDeletion(entry, spec.rootKey, kItemSubKey);
                entry.uniqueIdText = "WINSOCK|" + entry.locationText;
                entry.riskLevel = StartupRiskLevel::kCritical;
                entry.riskReasonCode = "winsock";
                entry.riskReasonText = fromWide(L"该 Winsock 目录子键只能永久删除；错误修改可能导致网络协议栈或网络访问失效。");
                entries.push_back(std::move(entry));
            }
        }
        return entries;
    }

    std::vector<StartupEntry> enumerateWmiEntries()
    {
        std::vector<StartupEntry> entries;
        const ProcessOutput kOutput = runPowerShellScript(buildWmiPowerShellScript(), 15000);
        if (!kOutput.started || !kOutput.finished)
        {
            return entries;
        }
        const std::string kStdoutText = stripUtf8Bom(ks::str::trimCopy(kOutput.stdoutText));
        if (kStdoutText.empty())
        {
            return entries;
        }
        bool parseOk = false;
        const std::vector<JsonValue> kWmiObjects = parseJsonObjects(kStdoutText, &parseOk);
        if (!parseOk)
        {
            StartupEntry errorEntry;
            errorEntry.category = StartupCategory::kWmi;
            errorEntry.categoryText = categoryToText(errorEntry.category);
            errorEntry.itemNameText = fromWide(L"WMI \u679a\u4e3e\u89e3\u6790\u5931\u8d25");
            errorEntry.commandText = kStdoutText;
            errorEntry.locationText = "root\\subscription";
            errorEntry.userText = fromWide(L"本机");
            errorEntry.detailText = fromWide(L"JSON \u89e3\u6790\u5931\u8d25");
            errorEntry.sourceTypeText = "WMI-ParseError";
            errorEntry.enabled = false;
            errorEntry.uniqueIdText = "WMI|ParseError";
            markEntryActionUnavailable(
                errorEntry,
                StartupRiskLevel::kCritical,
                "wmi",
                fromWide(L"WMI 枚举失败；合成的错误记录不能修改。"));
            entries.push_back(std::move(errorEntry));
            return entries;
        }
        for (const JsonValue& wmiObject : kWmiObjects)
        {
            appendWmiJsonObject(entries, wmiObject);
        }
        return entries;
    }

    std::vector<StartupEntry> enumerateAllStartupEntries()
    {
        return enumerateAllStartupEntries(
            StartupEnumerationProgressCallback{},
            StartupEnumerationStageResultCallback{});
    }

    std::vector<StartupEntry> enumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback)
    {
        return enumerateAllStartupEntries(
            progressCallback,
            StartupEnumerationStageResultCallback{});
    }

    std::vector<StartupEntry> enumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback,
        const StartupEnumerationStageResultCallback& stageResultCallback)
    {
        std::vector<StartupEntry> entries;
        constexpr std::size_t kStageCount = 9U;
        auto append = [&entries, &progressCallback, &stageResultCallback, kStageCount](
            const StartupEnumerationStage stage,
            const std::size_t stageIndex,
            auto&& enumerateStage)
        {
            if (progressCallback)
            {
                progressCallback(stage, stageIndex, kStageCount);
            }
            std::vector<StartupEntry> part = enumerateStage();
            if (stageResultCallback)
            {
                stageResultCallback(stage, stageIndex, kStageCount, part);
            }
            entries.insert(entries.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));
        };
        append(StartupEnumerationStage::kLogon, 0U, []() { return enumerateLogonEntries(); });
        append(StartupEnumerationStage::kServices, 1U, []() { return enumerateServiceEntries(); });
        append(StartupEnumerationStage::kDrivers, 2U, []() { return enumerateDriverEntries(); });
        append(StartupEnumerationStage::kTasks, 3U, []() { return enumerateTaskEntries(); });
        append(StartupEnumerationStage::kImageHijack, 4U, []() { return enumerateImageHijackEntries(); });
        append(StartupEnumerationStage::kAdvancedRegistry, 5U, []() { return enumerateAdvancedRegistryEntries(); });
        append(StartupEnumerationStage::kWinsock, 6U, []() { return enumerateWinsockEntries(); });
        append(StartupEnumerationStage::kWmi, 7U, []() { return enumerateWmiEntries(); });
        // Hidden findings run last: they cross-check the same objects the enumerators above walked.
        append(StartupEnumerationStage::kHidden, 8U, []() { return enumerateHiddenEntries(); });
        return entries;
    }

    ActionResult setStartupEntryEnabled(const StartupEntry& entry, const bool enabled)
    {
        switch (entry.actionKind)
        {
        case StartupActionKind::kRegistryRunValue:
            return enabled ? enableRegistryRunEntry(entry) : disableRegistryRunEntry(entry);
        case StartupActionKind::kRegistryTree:
            break;
        case StartupActionKind::kStartupFolderFile:
            return enabled ? enableStartupFolderEntry(entry) : disableStartupFolderEntry(entry);
        case StartupActionKind::kScheduledTask:
            return setScheduledTaskEnabled(entry, enabled);
        case StartupActionKind::kScmStartType:
            return setScmEntryEnabled(entry, enabled);
        case StartupActionKind::kWmiEntryRemoval:
            return removeWmiEntry(entry, enabled);
        case StartupActionKind::kNone:
            break;
        }
        return makeActionResult(
            StartupActionStatus::kNotSupported,
            false,
            false,
            ERROR_NOT_SUPPORTED,
            fromWide(L"此启动项没有可逆的后端操作。"));
    }

    ActionResult deleteStartupEntry(const StartupEntry& entry)
    {
        if (!entry.canDelete)
        {
            return makeActionResult(
                StartupActionStatus::kNotSupported,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                fromWide(L"此启动项没有可用的永久删除操作。"));
        }
        if (entry.deleteRegistryTree)
        {
            return deleteRegistryTreeEntry(entry);
        }

        switch (entry.actionKind)
        {
        case StartupActionKind::kRegistryRunValue:
            return deleteRegistryValueEntry(entry);
        case StartupActionKind::kRegistryTree:
            return deleteRegistryTreeEntry(entry);
        case StartupActionKind::kStartupFolderFile:
            return deleteStartupFolderFile(entry);
        case StartupActionKind::kScheduledTask:
            return deleteScheduledTaskEntry(entry);
        case StartupActionKind::kScmStartType:
            return deleteScmEntry(entry);
        case StartupActionKind::kWmiEntryRemoval:
        case StartupActionKind::kNone:
            break;
        }
        return makeActionResult(
            StartupActionStatus::kNotSupported,
            false,
            false,
            ERROR_NOT_SUPPORTED,
            fromWide(L"此启动项来源不支持永久删除。"));
    }
}
