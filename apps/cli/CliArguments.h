#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ksword::cli
{
    struct ParsedOption { bool present = false; std::wstring value; };
    struct NamedArgs
    {
        std::vector<std::wstring> positionals;
        std::map<std::wstring, std::wstring> options;
    };
    NamedArgs parseNamedArgs(int argc, wchar_t* argv[], int startIndex);

    const std::wstring* getOptionText(const NamedArgs& args, const wchar_t* key);

    std::uint32_t getOptionU32(const NamedArgs& args, const wchar_t* key, std::uint32_t defaultValue);

    std::uint64_t getOptionU64(const NamedArgs& args, const wchar_t* key, std::uint64_t defaultValue);

    bool getOptionBool(const NamedArgs& args, const wchar_t* key);

    const std::wstring& requireOptionText(const NamedArgs& args, const wchar_t* key);

    std::uint32_t requireOptionU32(const NamedArgs& args, const wchar_t* key);

    std::uint64_t requireOptionU64(const NamedArgs& args, const wchar_t* key);

    bool hasOption(int argc, wchar_t* argv[], const wchar_t* option);

    const wchar_t* findOptionValue(int argc, wchar_t* argv[], const wchar_t* option);

    std::vector<std::uint8_t> parseHexBytes(const std::wstring& text);

    std::uint32_t parseU32(const wchar_t* token, const char* name);

    std::uint64_t parseU64(const wchar_t* token, const char* name);

    std::vector<std::uint32_t> parsePidListText(const std::wstring& text);

    bool containsIgnoreCase(const std::wstring& haystack, const wchar_t* needle);

    std::wstring lowerWide(std::wstring text);
}
