#include "String.h"

// Windows string conversion relies on Win32 APIs.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm> // std::find_if_not: Used for trim logic.
#include <cctype>    // std::isspace: Check for whitespace characters.
#include <cstdio>    // std::snprintf: Formats time text.
#include <vector>    // std::vector<wchar_t>/char: Conversion buffer.

namespace ks::str
{
    std::string utf16ToUtf8(const std::wstring& utf16Text)
    {
        // Quick return for empty string to avoid API calls.
        if (utf16Text.empty())
        {
            return std::string();
        }

        // Step 1: Query the target UTF-8 length (including the trailing '\0').
        const int kTargetLengthWithNull = ::WideCharToMultiByte(
            CP_UTF8,
            0,
            utf16Text.c_str(),
            -1,
            nullptr,
            0,
            nullptr,
            nullptr);

        if (kTargetLengthWithNull <= 0)
        {
            return std::string();
        }

        // Allocate the buffer and perform the conversion.
        std::vector<char> utf8Buffer(static_cast<std::size_t>(kTargetLengthWithNull), '\0');
        const int kConvertedLengthWithNull = ::WideCharToMultiByte(
            CP_UTF8,
            0,
            utf16Text.c_str(),
            -1,
            utf8Buffer.data(),
            kTargetLengthWithNull,
            nullptr,
            nullptr);

        if (kConvertedLengthWithNull <= 0)
        {
            return std::string();
        }

        // Strip the trailing '\0' and construct a std::string.
        return std::string(utf8Buffer.data());
    }

    std::wstring utf8ToUtf16(const std::string& utf8Text)
    {
        // Fast return for empty string.
        if (utf8Text.empty())
        {
            return std::wstring();
        }

        // Step 1: Query the UTF-16 target length (including the terminating L'\0').
        const int kTargetLengthWithNull = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            utf8Text.c_str(),
            -1,
            nullptr,
            0);

        if (kTargetLengthWithNull <= 0)
        {
            return std::wstring();
        }

        // Allocate the buffer and perform the conversion.
        std::vector<wchar_t> utf16Buffer(static_cast<std::size_t>(kTargetLengthWithNull), L'\0');
        const int kConvertedLengthWithNull = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            utf8Text.c_str(),
            -1,
            utf16Buffer.data(),
            kTargetLengthWithNull);

        if (kConvertedLengthWithNull <= 0)
        {
            return std::wstring();
        }

        // Remove trailing L'\0' and construct a std::wstring.
        return std::wstring(utf16Buffer.data());
    }

    std::string trimCopy(const std::string& textValue)
    {
        // Local lambda: unifies the check for 'whitespace character'.
        const auto kIsSpace = [](const unsigned char charValue) -> bool
            {
                return std::isspace(charValue) != 0;
            };

        // Left trim: find the first non-whitespace position.
        auto beginIterator = std::find_if_not(
            textValue.begin(),
            textValue.end(),
            [&](const char currentChar) { return kIsSpace(static_cast<unsigned char>(currentChar)); });

        // If the entire string is whitespace, return an empty string directly.
        if (beginIterator == textValue.end())
        {
            return std::string();
        }

        // Right trim: Find the first non-whitespace position from the end in reverse.
        auto reverseEndIterator = std::find_if_not(
            textValue.rbegin(),
            textValue.rend(),
            [&](const char currentChar) { return kIsSpace(static_cast<unsigned char>(currentChar)); });

        const auto kEndIterator = reverseEndIterator.base();
        return std::string(beginIterator, kEndIterator);
    }

    std::uint64_t fileTimeToUint64(const std::uint32_t highPart, const std::uint32_t lowPart)
    {
        // Bitwise concatenate the high and low 32 bits of FILETIME.
        return (static_cast<std::uint64_t>(highPart) << 32) | static_cast<std::uint64_t>(lowPart);
    }

    std::string fileTime100nsToLocalText(const std::uint64_t fileTime100ns)
    {
        // Split the 64-bit value back into a FILETIME structure.
        FILETIME utcFileTime{};
        utcFileTime.dwLowDateTime = static_cast<DWORD>(fileTime100ns & 0xFFFFFFFFULL);
        utcFileTime.dwHighDateTime = static_cast<DWORD>((fileTime100ns >> 32) & 0xFFFFFFFFULL);

        // Convert UTC FILETIME to local FILETIME.
        FILETIME localFileTime{};
        if (::FileTimeToLocalFileTime(&utcFileTime, &localFileTime) == FALSE)
        {
            return std::string();
        }

        // Convert FILETIME to SYSTEMTIME for easier formatting.
        SYSTEMTIME localSystemTime{};
        if (::FileTimeToSystemTime(&localFileTime, &localSystemTime) == FALSE)
        {
            return std::string();
        }

        // Use a safe formatting function to construct fixed-format time text.
        char timeBuffer[64] = {};
        const int kWrittenLength = std::snprintf(
            timeBuffer,
            sizeof(timeBuffer),
            "%04u-%02u-%02u %02u:%02u:%02u",
            static_cast<unsigned>(localSystemTime.wYear),
            static_cast<unsigned>(localSystemTime.wMonth),
            static_cast<unsigned>(localSystemTime.wDay),
            static_cast<unsigned>(localSystemTime.wHour),
            static_cast<unsigned>(localSystemTime.wMinute),
            static_cast<unsigned>(localSystemTime.wSecond));

        if (kWrittenLength <= 0)
        {
            return std::string();
        }

        return std::string(timeBuffer);
    }

    void replaceAllInPlace(std::string& textValue, const std::string& fromText, const std::string& toText)
    {
        // An empty fromText causes an infinite loop; return directly.
        if (fromText.empty())
        {
            return;
        }

        // Find and replace segment by segment until no matches remain.
        std::size_t currentPosition = 0;
        while (true)
        {
            currentPosition = textValue.find(fromText, currentPosition);
            if (currentPosition == std::string::npos)
            {
                break;
            }

            textValue.replace(currentPosition, fromText.length(), toText);
            currentPosition += toText.length();
        }
    }
}
