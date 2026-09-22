#include "../../../apps/cli/CliArguments.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace ksword::cli;

namespace
{
    void require(bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    template<class Exception, class Operation>
    void rejects(Operation operation, const char* message)
    {
        try { operation(); }
        catch (const Exception&) { return; }
        throw std::runtime_error(message);
    }

    void numericBoundaries()
    {
        require(parseU32(L"0", "test") == 0, "zero");
        require(parseU32(L"4294967295", "test") == UINT32_MAX, "u32 maximum");
        require(parseU64(L"18446744073709551615", "test") == UINT64_MAX, "u64 maximum");
        require(parseU64(L"0xffffffffffffffff", "test") == UINT64_MAX, "hex maximum");
        require(parseU32(L" +42", "test") == 42, "existing positive sign/whitespace syntax");
        require(parseU32(L"077", "test") == 63, "existing base-zero syntax");
        rejects<std::out_of_range>([] { parseU32(L"4294967296", "test"); }, "u32 overflow");
        rejects<std::out_of_range>([] { parseU64(L"18446744073709551616", "test"); }, "u64 overflow");
        rejects<std::out_of_range>([] { parseU64(L"0x10000000000000000", "test"); }, "hex overflow");
        for (const auto* input : {L"", L" ", L"-1", L" -1", L"12oops", L"0x", L"12 "})
            rejects<std::invalid_argument>([input] { parseU64(input, "test"); }, "invalid unsigned token");
        rejects<std::invalid_argument>([] { parseU64(nullptr, "test"); }, "null token");
    }

    void namedArguments()
    {
        std::vector<std::wstring> tokens{L"app", L"family", L"command", L"first", L"--pid", L"12", L"--confirm", L"--pid", L"0x2a"};
        std::vector<wchar_t*> argv;
        for (auto& token : tokens) argv.push_back(token.data());
        const auto kArgs = parseNamedArgs(static_cast<int>(argv.size()), argv.data(), 3);
        require(kArgs.positionals == std::vector<std::wstring>{L"first"}, "positionals retained");
        require(requireOptionU32(kArgs, L"--pid") == 42, "last option wins");
        require(getOptionBool(kArgs, L"--confirm"), "valueless switch");
        require(!getOptionBool(kArgs, L"--absent"), "absent switch");
        require(getOptionU64(kArgs, L"--missing", 123) == 123, "default value");
        rejects<std::invalid_argument>([&] { requireOptionU32(kArgs, L"--confirm"); }, "switch is not a number");
        rejects<std::invalid_argument>([&] { requireOptionText(kArgs, L"--missing"); }, "required option");
    }

    void bytePayloads()
    {
        const std::vector<std::uint8_t> kExpected{0xDE, 0xAD, 0xBE, 0xEF};
        require(parseHexBytes(L"0xdeadbeef") == kExpected, "prefixed hex");
        require(parseHexBytes(L"DE AD:BE-EF") == kExpected, "separators");
        require(parseHexBytes(L"DE,AD_BE EF") == kExpected, "comma and underscore");
        require(parseHexBytes(L"").empty(), "empty optional payload");
        for (const auto* input : {L"0x", L"abc", L"ZZ", L"DEZAD", L"12!34"})
            rejects<std::invalid_argument>([input] { parseHexBytes(input); }, "malformed payload cannot be silently changed");
    }

    void pidLists()
    {
        require(parsePidListText(L"0,12;0x2a|12 7") == std::vector<std::uint32_t>{12, 42, 7},
            "stable PID ordering, zero removal, deduplication");
        require(parsePidListText(L" , ; | ").empty(), "empty PID list");
        rejects<std::invalid_argument>([] { parsePidListText(L"12,bad"); }, "bad PID");
        rejects<std::out_of_range>([] { parsePidListText(L"4294967296"); }, "PID overflow");
        std::wstring oversized;
        for (unsigned i = 1; i < 10000; ++i) oversized += std::to_wstring(i) + L",";
        rejects<std::out_of_range>([&] { parsePidListText(oversized); }, "protocol PID budget");
    }
}

int main()
{
    struct Test { const char* name; void (*run)(); };
    const Test kTests[]{{"numeric boundaries", numericBoundaries}, {"named arguments", namedArguments},
        {"byte payloads", bytePayloads}, {"PID lists", pidLists}};
    int failures = 0;
    for (const auto& test : kTests)
    {
        try { test.run(); std::cout << "PASS " << test.name << '\n'; }
        catch (const std::exception& error) { ++failures; std::cerr << "FAIL " << test.name << ": " << error.what() << '\n'; }
    }
    return failures ? 1 : 0;
}
