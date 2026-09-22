#pragma once

// F-08: 64-bit data is lossless.
//
// Address, 64-bit ID, count, and high-precision timestamp never pass through double at this layer. During
// persistence, 64-bit values are written as formatted strings (decimal "12345" or address "0x00007FFE12340000")
// and restored bit-by-bit on read. Null is an independent state and never degenerates to 0.

#include <cstdint>
#include <string>
#include <string_view>

namespace ksword::evidence {

// OptionalU64 separates 'unknown' and 'zero' into two states. Default construction is unknown.
struct OptionalU64 final {
    bool present = false;
    std::uint64_t value = 0;

    constexpr OptionalU64() noexcept = default;

    static constexpr OptionalU64 unset() noexcept { return OptionalU64{}; }

    static constexpr OptionalU64 of(std::uint64_t v) noexcept {
        OptionalU64 result;
        result.present = true;
        result.value = v;
        return result;
    }

    // valueOr is used solely for displaying the fallback; it does not modify the underlying state, and call sites must check present first.
    constexpr std::uint64_t valueOr(std::uint64_t fallback) const noexcept {
        return present ? value : fallback;
    }

    friend constexpr bool operator==(const OptionalU64& a, const OptionalU64& b) noexcept {
        return a.present == b.present && (!a.present || a.value == b.value);
    }

    friend constexpr bool operator!=(const OptionalU64& a, const OptionalU64& b) noexcept {
        return !(a == b);
    }
};

// Persistent format marker for U64. Shared by read/write sides; must be explicitly included in exports; the reader must not guess.
enum class U64Format {
    kDecimal,     // "18446744073709551615"
    kHexAddress,  // "0x00007FFE12340000" — fixed 16-digit hexadecimal, facilitating sorting and copying by address.
};

std::string formatU64(std::uint64_t value, U64Format format);

// formatOptionalU64 returns an empty string for unknown values; call sites use this to write JSON null instead of "0".
std::string formatOptionalU64(const OptionalU64& value, U64Format format);

// ParseU64 accepts both decimal and 0x-prefixed hexadecimal formats; overflow, empty string, or trailing garbage all cause failure.
bool parseU64(std::string_view text, std::uint64_t& out) noexcept;

// parseOptionalU64: Parses empty string as "unknown" and returns true; returns false for invalid text without modifying out.
bool parseOptionalU64(std::string_view text, OptionalU64& out) noexcept;

// Signed 64-bit values (e.g., clock calibration offsets) also avoid floating-point.
std::string formatI64(std::int64_t value);
bool parseI64(std::string_view text, std::int64_t& out) noexcept;

} // namespace ksword::evidence
