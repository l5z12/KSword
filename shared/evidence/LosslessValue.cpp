#include "LosslessValue.h"

#include <limits>

namespace ksword::evidence {
namespace {

constexpr char kHexDigits[] = "0123456789ABCDEF";

bool hexDigitValue(char c, std::uint32_t& out) noexcept {
    if (c >= '0' && c <= '9') {
        out = static_cast<std::uint32_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        out = static_cast<std::uint32_t>(c - 'a') + 10U;
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        out = static_cast<std::uint32_t>(c - 'A') + 10U;
        return true;
    }
    return false;
}

bool parseHexBody(std::string_view text, std::uint64_t& out) noexcept {
    if (text.empty() || text.size() > 16U) {
        return false;
    }
    std::uint64_t value = 0U;
    for (const char kC : text) {
        std::uint32_t digit = 0U;
        if (!hexDigitValue(kC, digit)) {
            return false;
        }
        value = (value << 4U) | digit;
    }
    out = value;
    return true;
}

bool parseDecimalBody(std::string_view text, std::uint64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    std::uint64_t value = 0U;
    for (const char kC : text) {
        if (kC < '0' || kC > '9') {
            return false;
        }
        const std::uint64_t kDigit = static_cast<std::uint64_t>(kC - '0');
        if (value > (kMax - kDigit) / 10U) {
            return false; // Overflow: Reject, do not truncate.
        }
        value = value * 10U + kDigit;
    }
    out = value;
    return true;
}

} // namespace

std::string formatU64(std::uint64_t value, U64Format format) {
    if (format == U64Format::kHexAddress) {
        std::string text(18U, '0');
        text[0] = '0';
        text[1] = 'x';
        for (std::size_t i = 0U; i < 16U; ++i) {
            const std::uint32_t kShift = static_cast<std::uint32_t>((15U - i) * 4U);
            text[2U + i] = kHexDigits[(value >> kShift) & 0xFULL];
        }
        return text;
    }

    if (value == 0U) {
        return std::string("0");
    }
    char buffer[20];
    std::size_t length = 0U;
    while (value != 0U) {
        buffer[length++] = static_cast<char>('0' + static_cast<char>(value % 10U));
        value /= 10U;
    }
    std::string text;
    text.reserve(length);
    for (std::size_t i = length; i > 0U; --i) {
        text.push_back(buffer[i - 1U]);
    }
    return text;
}

std::string formatOptionalU64(const OptionalU64& value, U64Format format) {
    if (!value.present) {
        return std::string();
    }
    return formatU64(value.value, format);
}

bool parseU64(std::string_view text, std::uint64_t& out) noexcept {
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return parseHexBody(text.substr(2U), out);
    }
    return parseDecimalBody(text, out);
}

bool parseOptionalU64(std::string_view text, OptionalU64& out) noexcept {
    if (text.empty()) {
        out = OptionalU64::unset();
        return true;
    }
    std::uint64_t value = 0U;
    if (!parseU64(text, value)) {
        return false;
    }
    out = OptionalU64::of(value);
    return true;
}

std::string formatI64(std::int64_t value) {
    if (value < 0) {
        // Convert to unsigned first, then negate, to avoid undefined behavior when negating INT64_MIN.
        const std::uint64_t kMagnitude = ~static_cast<std::uint64_t>(value) + 1ULL;
        return std::string("-") + formatU64(kMagnitude, U64Format::kDecimal);
    }
    return formatU64(static_cast<std::uint64_t>(value), U64Format::kDecimal);
}

bool parseI64(std::string_view text, std::int64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    const bool kNegative = text[0] == '-';
    const std::string_view kBody = kNegative ? text.substr(1U) : text;
    std::uint64_t magnitude = 0U;
    if (!parseDecimalBody(kBody, magnitude)) {
        return false;
    }
    constexpr std::uint64_t kPositiveMax =
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if (kNegative) {
        if (magnitude > kPositiveMax + 1ULL) {
            return false;
        }
        if (magnitude == kPositiveMax + 1ULL) {
            out = (std::numeric_limits<std::int64_t>::min)();
            return true;
        }
        out = -static_cast<std::int64_t>(magnitude);
        return true;
    }
    if (magnitude > kPositiveMax) {
        return false;
    }
    out = static_cast<std::int64_t>(magnitude);
    return true;
}

} // namespace ksword::evidence
