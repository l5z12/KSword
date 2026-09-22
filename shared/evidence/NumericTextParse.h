#pragma once

// ============================================================
// NumericTextParse.h
// Purpose:
// - Parses user-input numeric text into uint64, and **distinguishes between
//   "address" and "count" at the type level**, as their default number bases differ.
//
// Why this module is needed:
// - The original address and quantity fields shared a single parser that tried decimal first, then fell back to hexadecimal.
//   That hexadecimal fallback **only applies to strings containing a–f**: for pure digit strings, decimal parsing always
//   succeeds, so the fallback is never reached. In a tool that echoes all addresses with a 0x prefix, inputting `1233` is
//   interpreted as decimal 1233 (= 0x4D1), **silently jumping to a different address**—no error, no warning, just reading from
//   the wrong location. Smaller addresses look more like "read failures" and are less likely to be recognized as parsing issues.
// - Logic that 'does not error on calculation mistakes but instead reads/writes another location' must be exhaustively tested
//   in this project (similar cases include DDMA LBA encoding and CDB encoding). Therefore, the rules are extracted here:
//   No Qt or Win32 dependencies; can run directly in the offline bundle.
//
// Rule:
// - `0x` / `0X` prefix is always hexadecimal, independent of the default base.
// - Without a prefix, parse using the default radix declared by the caller. Addresses are in hexadecimal; quantities (sectors/LBA,
//   byte values, lengths) are in decimal—quantities are inherently spoken in decimal by humans, so they cannot be changed.
// - Default decimal mode retains a fallback for "hex without prefix" (strings containing a–f); default hex mode
//   has no fallback, as the hex character set is a superset of the decimal set, making a fallback unnecessary.
// - Treat any overflow as a failure; **never wrap around**: a wrapped value is still a valid address and would be read sequentially.
// - Does not accept signs, thousand separators, or internal spaces. Trim leading and trailing whitespace first.
// ============================================================

#include <cstdint>
#include <string_view>

namespace ksword::evidence
{
    // NumericTextRadix: The actual radix used. Returning it allows the UI to display
    // "what I interpreted it as" instead of just showing a number for the user to guess.
    enum class NumericTextRadix : int
    {
        kNone = 0,
        kDecimal = 10,
        kHexadecimal = 16,
    };

    // NumericTextDefaultRadix: Specifies the radix for interpretation when no prefix is present. The caller must explicitly select it; there
    // is no default value. Choosing incorrectly does not trigger an error, so default parameters cannot be used to bypass this requirement.
    enum class NumericTextDefaultRadix : int
    {
        kHexadecimal = 0,
        kDecimal = 1,
    };

    struct NumericTextParseResult
    {
        bool ok = false;
        std::uint64_t value = 0;
        NumericTextRadix radix = NumericTextRadix::kNone;
        bool hadHexPrefix = false;
    };

    // numericTextDigitValue: Returns the digit value of a single character in the given radix; returns -1 if not a valid digit.
    inline int numericTextDigitValue(const char character, const int radix)
    {
        int digit = -1;
        if (character >= '0' && character <= '9')
        {
            digit = character - '0';
        }
        else if (character >= 'a' && character <= 'f')
        {
            digit = character - 'a' + 10;
        }
        else if (character >= 'A' && character <= 'F')
        {
            digit = character - 'A' + 10;
        }
        else
        {
            return -1;
        }
        return (digit < radix) ? digit : -1;
    }

    // numericTextTrim: trim whitespace from both ends. Internal
    // whitespace is not trimmed—"12 34" is an input error, not "1234".
    inline std::string_view numericTextTrim(std::string_view text)
    {
        const auto kIsSpace = [](const char character) {
            return character == ' ' || character == '\t' || character == '\r'
                || character == '\n' || character == '\f' || character == '\v';
        };
        while (!text.empty() && kIsSpace(text.front()))
        {
            text.remove_prefix(1);
        }
        while (!text.empty() && kIsSpace(text.back()))
        {
            text.remove_suffix(1);
        }
        return text;
    }

    // numericTextParseDigits: Parse the entire string using the given radix; any invalid character causes failure.
    // Leading zeros are allowed; empty strings are not.
    inline bool numericTextParseDigits(
        const std::string_view text,
        const int radix,
        std::uint64_t& valueOut)
    {
        if (text.empty())
        {
            return false;
        }
        constexpr std::uint64_t kMaxValue = ~0ULL;
        const std::uint64_t kRadixValue = static_cast<std::uint64_t>(radix);
        std::uint64_t accumulated = 0;
        for (const char kCharacter : text)
        {
            const int kDigit = numericTextDigitValue(kCharacter, radix);
            if (kDigit < 0)
            {
                return false;
            }
            // Check for overflow before multiplication and addition. After wrapping, the value becomes a valid address
            // that cannot be detected; the interface will display it normally, and the driver will read it normally.
            if (accumulated > kMaxValue / kRadixValue)
            {
                return false;
            }
            accumulated *= kRadixValue;
            if (accumulated > kMaxValue - static_cast<std::uint64_t>(kDigit))
            {
                return false;
            }
            accumulated += static_cast<std::uint64_t>(kDigit);
        }
        valueOut = accumulated;
        return true;
    }

    // parseNumericText: parses a numeric text string according to the rules above.
    inline NumericTextParseResult parseNumericText(
        const std::string_view rawText,
        const NumericTextDefaultRadix defaultRadix)
    {
        NumericTextParseResult result;
        const std::string_view kText = numericTextTrim(rawText);
        if (kText.empty())
        {
            return result;
        }

        // Explicit prefix takes precedence over default radix: '0x' always means hexadecimal, with no exceptions.
        if (kText.size() >= 2 && kText[0] == '0' && (kText[1] == 'x' || kText[1] == 'X'))
        {
            std::uint64_t value = 0;
            if (!numericTextParseDigits(kText.substr(2), 16, value))
            {
                return result;
            }
            result.ok = true;
            result.value = value;
            result.radix = NumericTextRadix::kHexadecimal;
            result.hadHexPrefix = true;
            return result;
        }

        if (defaultRadix == NumericTextDefaultRadix::kHexadecimal)
        {
            std::uint64_t value = 0;
            if (!numericTextParseDigits(kText, 16, value))
            {
                return result;
            }
            result.ok = true;
            result.value = value;
            result.radix = NumericTextRadix::kHexadecimal;
            return result;
        }

        std::uint64_t value = 0;
        if (numericTextParseDigits(kText, 10, value))
        {
            result.ok = true;
            result.value = value;
            result.radix = NumericTextRadix::kDecimal;
            return result;
        }
        // Hexadecimal parsing is attempted only if decimal fails, preserving the input habit of 'hex without prefix'.
        if (numericTextParseDigits(kText, 16, value))
        {
            result.ok = true;
            result.value = value;
            result.radix = NumericTextRadix::kHexadecimal;
            return result;
        }
        return result;
    }
}
