#include "CliArguments.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "../../shared/driver/KswordArkCallbackIoctl.h"

#include <algorithm>
#include <cerrno>
#include <cwchar>
#include <cwctype>
#include <limits>
#include <stdexcept>

namespace ksword::cli
{
    namespace
    {
        std::uint64_t parseUnsigned(const wchar_t* token, std::uint64_t maximum, const char* name)
        {
            if (token == nullptr)
                throw std::invalid_argument(name);
            while (std::iswspace(*token)) ++token;
            if (*token == L'\0' || *token == L'-')
                throw std::invalid_argument(name);

            wchar_t* end = nullptr;
            errno = 0;
            const auto kValue = std::wcstoull(token, &end, 0);
            if (end == token || *end != L'\0')
                throw std::invalid_argument(name);
            if (errno == ERANGE || kValue > maximum)
                throw std::out_of_range(name);
            return kValue;
        }
    }
    // parseNamedArgs collects positional tokens after the command family/subcommand.
    // Inputs: argc/argv plus the start index for first option token.
    // Processing: preserves ordering for positional file/blob paths and flags.
    // Returns: NamedArgs with a positional list; option helpers scan argv directly.
    NamedArgs parseNamedArgs(int argc, wchar_t* argv[], int startIndex)
    {
        NamedArgs args{};
        for (int index = startIndex; index < argc; ++index)
        {
            if (argv[index] == nullptr || argv[index][0] == L'\0')
            {
                continue;
            }

            if (argv[index][0] == L'-')
            {
                if (index + 1 < argc && argv[index + 1] != nullptr && argv[index + 1][0] != L'-')
                {
                    args.options[argv[index]] = argv[index + 1];
                    ++index;
                }
                else
                {
                    args.options[argv[index]] = L"";
                }
                continue;
            }

            args.positionals.emplace_back(argv[index]);
        }
        return args;
    }

    // getOptionText returns a named option value from parsed args.
    // Inputs: option map and key with leading dashes.
    // Processing: caller can use fallback when the option is absent.
    // Returns: pointer to the stable internal string or nullptr.
    const std::wstring* getOptionText(const NamedArgs& args, const wchar_t* key)
    {
        const auto kIt = args.options.find(key);
        return kIt == args.options.end() ? nullptr : &kIt->second;
    }

    // getOptionU32 parses an option value as unsigned 32-bit.
    // Inputs: parsed args, key, and default value.
    // Processing: falls back to default when the switch is absent.
    // Returns: parsed or default value.
    std::uint32_t getOptionU32(const NamedArgs& args, const wchar_t* key, std::uint32_t defaultValue)
    {
        const std::wstring* value = getOptionText(args, key);
        return value == nullptr ? defaultValue : parseU32(value->c_str(), "option");
    }

    // getOptionU64 parses an option value as unsigned 64-bit.
    // Inputs: parsed args, key, and default value.
    // Processing: falls back to default when the switch is absent.
    // Returns: parsed or default value.
    std::uint64_t getOptionU64(const NamedArgs& args, const wchar_t* key, std::uint64_t defaultValue)
    {
        const std::wstring* value = getOptionText(args, key);
        return value == nullptr ? defaultValue : parseU64(value->c_str(), "option");
    }

    // getOptionBool reports whether the option is present.
    // Inputs: parsed args and key.
    // Processing: presence-only flag; no value is consumed.
    // Returns: true when present.
    bool getOptionBool(const NamedArgs& args, const wchar_t* key)
    {
        return args.options.find(key) != args.options.end();
    }

    // requireOptionText fetches a mandatory named option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent.
    // Returns: option value reference.
    const std::wstring& requireOptionText(const NamedArgs& args, const wchar_t* key)
    {
        const std::wstring* value = getOptionText(args, key);
        if (value == nullptr)
        {
            throw std::invalid_argument("missing option");
        }
        return *value;
    }

    // requireOptionU32 parses a mandatory unsigned 32-bit option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent or malformed.
    // Returns: parsed value.
    std::uint32_t requireOptionU32(const NamedArgs& args, const wchar_t* key)
    {
        return parseU32(requireOptionText(args, key).c_str(), "option");
    }

    // requireOptionU64 parses a mandatory unsigned 64-bit option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent or malformed.
    // Returns: parsed value.
    std::uint64_t requireOptionU64(const NamedArgs& args, const wchar_t* key)
    {
        return parseU64(requireOptionText(args, key).c_str(), "option");
    }

    // hasOption reports whether a named switch is present in argv.
    // Inputs: option name includes the leading dashes, for example "--pid".
    // Processing: exact case-sensitive match against the command line.
    // Returns: true when the option exists.
    bool hasOption(int argc, wchar_t* argv[], const wchar_t* option)
    {
        for (int index = 0; index < argc; ++index)
        {
            if (argv[index] != nullptr && std::wcscmp(argv[index], option) == 0)
            {
                return true;
            }
        }
        return false;
    }

    // findOptionValue returns the next token after a named switch.
    // Inputs: argv and option name; if missing, returns nullptr.
    // Processing: scans for exact option match and returns following token.
    // Returns: pointer to the following argument or nullptr.
    const wchar_t* findOptionValue(int argc, wchar_t* argv[], const wchar_t* option)
    {
        for (int index = 0; index + 1 < argc; ++index)
        {
            if (argv[index] != nullptr && std::wcscmp(argv[index], option) == 0)
            {
                return argv[index + 1];
            }
        }
        return nullptr;
    }

    // parseHexBytes accepts either 0x-prefixed numbers or raw hex byte strings.
    // Inputs: text token containing bytes like "DE AD BE EF" or "0x1234".
    // Processing: strips separators and decodes two hex digits per byte.
    // Returns: decoded bytes; throws on malformed input.
    std::vector<std::uint8_t> parseHexBytes(const std::wstring& text)
    {
        std::wstring normalized = text;
        bool hasPrefix = false;
        if (normalized.size() >= 2U && normalized[0] == L'0' && (normalized[1] == L'x' || normalized[1] == L'X'))
        {
            normalized.erase(0U, 2U);
            hasPrefix = true;
        }

        std::wstring cleaned;
        cleaned.reserve(text.size());
        for (wchar_t ch : normalized)
        {
            if (std::iswxdigit(ch))
            {
                cleaned.push_back(static_cast<wchar_t>(std::towupper(ch)));
            }
            else if (!std::iswspace(ch) && ch != L',' && ch != L':' && ch != L'-' && ch != L'_')
            {
                throw std::invalid_argument("hex bytes");
            }
        }

        if (cleaned.empty())
        {
            if (hasPrefix) throw std::invalid_argument("hex bytes");
            return {};
        }
        if ((cleaned.size() % 2U) != 0U)
        {
            throw std::invalid_argument("hex bytes");
        }

        std::vector<std::uint8_t> bytes;
        bytes.reserve(cleaned.size() / 2U);
        for (std::size_t index = 0U; index < cleaned.size(); index += 2U)
        {
            const wchar_t kHi = cleaned[index];
            const wchar_t kLo = cleaned[index + 1U];
            const auto kNibble = [](wchar_t c) -> int {
                if (c >= L'0' && c <= L'9') return static_cast<int>(c - L'0');
                if (c >= L'A' && c <= L'F') return static_cast<int>(10 + (c - L'A'));
                return -1;
            };
            const int kHiValue = kNibble(kHi);
            const int kLoValue = kNibble(kLo);
            if (kHiValue < 0 || kLoValue < 0)
            {
                throw std::invalid_argument("hex bytes");
            }
            bytes.push_back(static_cast<std::uint8_t>((kHiValue << 4) | kLoValue));
        }
        return bytes;
    }

    // parseU32 parses a decimal or 0x-prefixed unsigned 32-bit number.
    // Inputs: token is a command-line argument; name is used in error text.
    // Processing: wcstoull is used so both decimal and hex are accepted.
    // Returns: parsed value, or throws invalid_argument/out_of_range.
    std::uint32_t parseU32(const wchar_t* token, const char* name)
    {
        return static_cast<std::uint32_t>(parseUnsigned(token, std::numeric_limits<std::uint32_t>::max(), name));
    }

    // parseU64 parses a decimal or 0x-prefixed unsigned 64-bit number.
    // Inputs: token is a command-line argument; name is used in error text.
    // Processing: wcstoull is used to preserve native Windows argument encoding.
    // Returns: parsed value, or throws invalid_argument.
    std::uint64_t parseU64(const wchar_t* token, const char* name)
    {
        return parseUnsigned(token, std::numeric_limits<std::uint64_t>::max(), name);
    }

    // parsePidListText converts a delimiter-separated PID list into unique PID values.
    // Inputs: text accepts decimal or 0x-prefixed numbers separated by comma, semicolon, pipe, or whitespace.
    // Processing: PID zero is ignored and duplicates are removed while preserving first-seen order.
    // Returns: normalized PID vector; throws when a token is malformed or the protocol maximum is exceeded.
    std::vector<std::uint32_t> parsePidListText(const std::wstring& text)
    {
        std::vector<std::uint32_t> processIds;
        std::wstring token;

        const auto kFlushToken = [&]()
        {
            if (token.empty())
            {
                return;
            }

            const std::uint32_t kProcessId = parseU32(token.c_str(), "pid list");
            token.clear();
            if (kProcessId == 0U)
            {
                return;
            }
            if (std::find(processIds.begin(), processIds.end(), kProcessId) != processIds.end())
            {
                return;
            }
            if (processIds.size() >= KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT)
            {
                throw std::out_of_range("too many pids");
            }
            processIds.push_back(kProcessId);
        };

        for (const wchar_t kCh : text)
        {
            if (kCh == L',' || kCh == L';' || kCh == L'|' || std::iswspace(kCh) != 0)
            {
                kFlushToken();
                continue;
            }
            token.push_back(kCh);
        }
        kFlushToken();
        return processIds;
    }

    // containsIgnoreCase purpose: Performs wide-character substring matching in CLI text projections.
    // Input: haystack is the text to search, needle is the target substring.
    // Processing: Compare character-by-character after converting to lowercase to avoid missing reports due to case differences in R0 details.
    // Returns: true if a match is found; returns true (no filtering) if needle is empty.
    bool containsIgnoreCase(const std::wstring& haystack, const wchar_t* needle)
    {
        if (needle == nullptr || needle[0] == L'\0')
        {
            return true;
        }

        std::wstring loweredHaystack;
        loweredHaystack.reserve(haystack.size());
        for (const wchar_t kCh : haystack)
        {
            loweredHaystack.push_back(static_cast<wchar_t>(std::towlower(kCh)));
        }

        std::wstring loweredNeedle;
        for (const wchar_t* cursor = needle; *cursor != L'\0'; ++cursor)
        {
            loweredNeedle.push_back(static_cast<wchar_t>(std::towlower(*cursor)));
        }
        return loweredHaystack.find(loweredNeedle) != std::wstring::npos;
    }

    // lowerWide returns a lowercase copy for command option tokens.
    // Inputs: arbitrary wide string from argv.
    // Processing: applies towlower one code unit at a time for stable ASCII-like
    // protocol option matching.
    // Returns: lowercase text used by integrity/HWID parsers.
    std::wstring lowerWide(std::wstring text)
    {
        for (wchar_t& ch : text)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
        return text;
    }
}
