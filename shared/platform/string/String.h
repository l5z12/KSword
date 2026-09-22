#pragma once

// ============================================================
// ksword/string/string.h
// Namespace: ks::str
// Purpose:
// - Provides cross-module reusable string/time conversion utilities.
// - Avoid business layer repeatedly writing WideChar/MultiByte API;
// - Acts as a foundational capability module within the ksword portable toolkit.
// ============================================================

#include <cstdint> // std::uint64_t: Used for FILETIME value conversion.
#include <string>  // std::string/std::wstring: fundamental types for text transmission.

namespace ks::str
{
    // utf16ToUtf8:
    // - Convert UTF-16 wide strings (native to Windows) to UTF-8;
    // Parameter utf16Text: text to be converted.
    // Return value: UTF-8 encoded string; returns an empty string on failure.
    std::string utf16ToUtf8(const std::wstring& utf16Text);

    // utf8ToUtf16:
    // Converts UTF-8 text to a UTF-16 wide string;
    // Parameter utf8Text: text to convert;
    // Return value: UTF-16 encoded wide string; returns an empty string on failure.
    std::wstring utf8ToUtf16(const std::string& utf8Text);

    // TrimCopy:
    // - Removes leading and trailing whitespace characters (spaces, tabs, newlines) from the string.
    // Parameter textValue: Original text;
    // Return value: A copy with leading and trailing whitespace removed.
    std::string trimCopy(const std::string& textValue);

    // fileTimeToUint64:
    // - Concatenate FILETIME high and low parts into a 64-bit integer (100ns base);
    // Parameters highPart/lowPart: The two parts of a FILETIME structure.
    // Return value: The merged 64-bit value.
    std::uint64_t fileTimeToUint64(std::uint32_t highPart, std::uint32_t lowPart);

    // fileTime100nsToLocalText:
    // - Convert the FILETIME 100ns value to local time text;
    // Parameter fileTime100ns: 100ns count since 1601-01-01;
    // Return value: Returns the formatted "YYYY-MM-DD HH:MM:SS" text; returns an empty string on failure.
    std::string fileTime100nsToLocalText(std::uint64_t fileTime100ns);

    // replaceAllInPlace:
    // - Replace all matching fragments in the string in-place;
    // Parameter textValue: Reference to the target string;
    // Parameter fromText: content to be replaced;
    // Parameter toText: content after replacement;
    // Return value: None (modifies textValue directly).
    void replaceAllInPlace(std::string& textValue, const std::string& fromText, const std::string& toText);
}
