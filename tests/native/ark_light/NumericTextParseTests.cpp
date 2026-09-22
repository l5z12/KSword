// Offline tests for numeric text parsing (shared/evidence/NumericTextParse.h).
//
// Why this parser deserves a full set of exhaustive assertions: it belongs to the class where calculation errors do not trigger exceptions.
// After parsing into another number, the UI still displays it and the driver still reads it, but it reads from another address.
// In a real incident: a pure numeric string entered in the address field was interpreted as decimal; `1233` became 0x4D1,
// landing in the process's null pointer guard region, ultimately manifesting as "Read failed, error code 299"—a symptom
// seemingly unrelated to parsing, leading investigators to initially suspect memory read issues rather than input parsing.
//
// Assertion principle is consistent with DdmaPlanTests.cpp:
//   * Expected values are hardcoded via manual calculation, never reverse-calculated from the function under test;
//   * Test boundaries on both sides (radix fallback boundary, uint64 overflow boundary);
//   * Rejected inputs must be explicitly rejected; do not only test the success path.
//   * Test both default bases separately — the same string must yield different results in the two modes;
//     this is the very reason this module exists. Testing only one mode is equivalent to not testing at all.

#include "TestSupport.h"

#include "../../../shared/evidence/NumericTextParse.h"

#include <cstdint>

namespace {

using ksword::evidence::NumericTextDefaultRadix;
using ksword::evidence::NumericTextRadix;
using ksword::evidence::parseNumericText;

// Address semantics: no prefix implies hexadecimal.
ksword::evidence::NumericTextParseResult addr(const char* text) {
    return parseNumericText(text, NumericTextDefaultRadix::kHexadecimal);
}

// Numeric semantics: No prefix implies decimal (used for sector LBA, byte values, and lengths).
ksword::evidence::NumericTextParseResult num(const char* text) {
    return parseNumericText(text, NumericTextDefaultRadix::kDecimal);
}

// ------------------------------------------------------------
// I. The defect itself: Pure digit strings must be distinguished under the two semantics.
// ------------------------------------------------------------
void testBareDigitsSplitBySemantics(ksword_tests::Suite& suite) {
    // The two values that actually caused the failure, hardcoded after manual calculation:
    //   0x1233 = 4659, decimal 1233 = 0x4D1;
    //   0x222222 = 2236962, decimal 222222 = 0x3640E.
    const auto kAddr1233 = addr("1233");
    suite.expect(kAddr1233.ok && kAddr1233.value == 0x1233ULL,
        L"numeric text: bare 1233 is hex 0x1233 in address semantics");
    suite.expect(kAddr1233.radix == NumericTextRadix::kHexadecimal,
        L"numeric text: address semantics reports hexadecimal for bare digits");
    suite.expect(!kAddr1233.hadHexPrefix,
        L"numeric text: bare digits are not reported as prefixed");

    const auto kNum1233 = num("1233");
    suite.expect(kNum1233.ok && kNum1233.value == 1233ULL,
        L"numeric text: bare 1233 stays decimal 1233 in quantity semantics");
    suite.expect(kNum1233.radix == NumericTextRadix::kDecimal,
        L"numeric text: quantity semantics reports decimal for bare digits");

    // The two semantics must produce different values for the same string; otherwise, this module is useless.
    suite.expect(kAddr1233.value != kNum1233.value,
        L"numeric text: the two semantics disagree on bare digits, which is the point");

    const auto kAddr222222 = addr("222222");
    suite.expect(kAddr222222.ok && kAddr222222.value == 0x222222ULL,
        L"numeric text: bare 222222 is hex 0x222222 in address semantics");
    const auto kNum222222 = num("222222");
    suite.expect(kNum222222.ok && kNum222222.value == 222222ULL,
        L"numeric text: bare 222222 stays decimal 222222 in quantity semantics");
    // Manual calculation: 222222 = 0x3640E, which is exactly the address reported in the issue.
    suite.expect(kNum222222.value == 0x3640EULL,
        L"numeric text: decimal 222222 equals 0x3640E, the address that was actually reported");
}

// ------------------------------------------------------------
// 2. The 0x prefix is always hexadecimal and takes precedence over the default radix.
// ------------------------------------------------------------
void testHexPrefixWinsOverDefault(ksword_tests::Suite& suite) {
    for (const char* text : { "0x1233", "0X1233" }) {
        const auto kAsAddress = parseNumericText(text, NumericTextDefaultRadix::kHexadecimal);
        const auto kAsQuantity = parseNumericText(text, NumericTextDefaultRadix::kDecimal);
        suite.expect(kAsAddress.ok && kAsAddress.value == 0x1233ULL,
            L"numeric text: 0x prefix parses as hex under address semantics");
        suite.expect(kAsQuantity.ok && kAsQuantity.value == 0x1233ULL,
            L"numeric text: 0x prefix parses as hex under quantity semantics too");
        suite.expect(kAsAddress.hadHexPrefix && kAsQuantity.hadHexPrefix,
            L"numeric text: the 0x prefix is reported back to the caller");
        suite.expect(kAsAddress.radix == NumericTextRadix::kHexadecimal
            && kAsQuantity.radix == NumericTextRadix::kHexadecimal,
            L"numeric text: a prefixed value reports hexadecimal in both semantics");
    }

    // Mixed-case digits are also valid.
    const auto kMixedCase = addr("0xAbCdEf");
    suite.expect(kMixedCase.ok && kMixedCase.value == 0xABCDEFULL,
        L"numeric text: hex digits are case-insensitive");

    // A prefix without digits must be rejected; it must never degrade to 0. 0 is a valid
    // address and also the MBR sector number in DDMA—the cost of degrading to it is real.
    suite.expect(!addr("0x").ok, L"numeric text: a bare 0x prefix is rejected, not treated as 0");
    suite.expect(!num("0x").ok, L"numeric text: a bare 0x prefix is rejected in quantity semantics");
    suite.expect(!addr("0X").ok, L"numeric text: a bare 0X prefix is rejected");
}

// ------------------------------------------------------------
// III. Hexadecimal fallback under decimal semantics: the boundary is precisely whether the string contains 'a'–'f'.
// ------------------------------------------------------------
void testDecimalFallbackBoundary(ksword_tests::Suite& suite) {
    // If a–f present, decimal fails -> fallback to hex.
    const auto kWithLetter = num("1a");
    suite.expect(kWithLetter.ok && kWithLetter.value == 0x1AULL,
        L"numeric text: quantity semantics falls back to hex when a digit is a-f");
    suite.expect(kWithLetter.radix == NumericTextRadix::kHexadecimal,
        L"numeric text: the fallback reports hexadecimal, not decimal");

    // Without a–f -> decimal interpretation holds -> backtracking fails. This is the root cause of the original defect; under
    // quantity semantics, this is **correct behavior** and must be preserved to prevent it from being inadvertently "fixed".
    const auto kWithoutLetter = num("19");
    suite.expect(kWithoutLetter.ok && kWithoutLetter.value == 19ULL,
        L"numeric text: quantity semantics keeps decimal when every digit is 0-9");
    suite.expect(kWithoutLetter.radix == NumericTextRadix::kDecimal,
        L"numeric text: no fallback happens when the decimal parse succeeds");

    // Address semantics have no fallback: the hexadecimal character set is a superset of decimal, so both paths are the same.
    const auto kAddrWithLetter = addr("1a");
    const auto kAddrWithoutLetter = addr("19");
    suite.expect(kAddrWithLetter.ok && kAddrWithLetter.value == 0x1AULL,
        L"numeric text: address semantics reads a-f directly");
    suite.expect(kAddrWithoutLetter.ok && kAddrWithoutLetter.value == 0x19ULL,
        L"numeric text: address semantics reads 19 as 0x19, never as decimal 19");
    suite.expect(kAddrWithoutLetter.value != 19ULL,
        L"numeric text: 0x19 and decimal 19 are different values and must not be conflated");
}

// ------------------------------------------------------------
// IV. Overflow: Must fail, never wrap.
// ------------------------------------------------------------
void testOverflowIsRejected(ksword_tests::Suite& suite) {
    // uint64 upper limit = 0xFFFFFFFFFFFFFFFF = 18446744073709551615. Test both sides.
    const auto kHexMax = addr("FFFFFFFFFFFFFFFF");
    suite.expect(kHexMax.ok && kHexMax.value == 0xFFFFFFFFFFFFFFFFULL,
        L"numeric text: the largest representable hex value is accepted");
    suite.expect(!addr("10000000000000000").ok,
        L"numeric text: one past the largest hex value is rejected, not wrapped");
    suite.expect(!addr("0x10000000000000000").ok,
        L"numeric text: a prefixed value one past the limit is rejected too");

    const auto kDecimalMax = num("18446744073709551615");
    suite.expect(kDecimalMax.ok && kDecimalMax.value == 0xFFFFFFFFFFFFFFFFULL,
        L"numeric text: the largest representable decimal value is accepted");
    suite.expect(!num("18446744073709551616").ok,
        L"numeric text: one past the largest decimal value is rejected");

    // After decimal overflow, do not allow 'falling back to hexadecimal' to rescue it: reading the same
    // digit string as hexadecimal would only yield a larger value, so any rescued number would be incorrect.
    suite.expect(!num("99999999999999999999").ok,
        L"numeric text: a decimal overflow does not get rescued by the hex fallback");

    // Leading zeros do not cause overflow.
    const auto kPadded = addr("0000000000000000000000001233");
    suite.expect(kPadded.ok && kPadded.value == 0x1233ULL,
        L"numeric text: leading zeros do not overflow");
}

// ------------------------------------------------------------
// 5. Invalid inputs must be explicitly rejected, not partially parsed.
// ------------------------------------------------------------
void testRejectedInputs(ksword_tests::Suite& suite) {
    const char* const kRejected[] = {
        "",            // Empty string
        "   ",         // All whitespace
        "g",           // Out of hexadecimal character set.
        "12g4",        // Trailing overflow
        "0x12g4",      // Out of bounds after prefix.
        "-1",          // Negative sign: addresses cannot be negative; accepting it implies accepting an overflow.
        "+1",          // Positive sign: also not accepted; better to let the user remove it.
        "12 34",       // Internal space: This is an input error, not 1234.
        "1,234",       // Thousands separator
        "1_234",       // Underscore-separated
        "0x1.8",       // Decimal point
        "1233h",       // Assembly-style suffix; this tool does not support it.
        "#1233",       // Other prefixes
    };
    for (const char* text : kRejected) {
        suite.expect(!addr(text).ok, L"numeric text: malformed input is rejected in address semantics");
        suite.expect(!num(text).ok, L"numeric text: malformed input is rejected in quantity semantics");
    }

    // On failure, output parameters must remain at a safe initial value so callers who
    // forget to check the return value do not receive stale data from a previous call.
    const auto kFailed = addr("g");
    suite.expect(kFailed.value == 0ULL, L"numeric text: a failed parse leaves the value at 0");
    suite.expect(kFailed.radix == NumericTextRadix::kNone,
        L"numeric text: a failed parse reports no radix");
    suite.expect(!kFailed.hadHexPrefix, L"numeric text: a failed parse reports no prefix");
}

// ------------------------------------------------------------
// Six: Only 0x is treated as a prefix; other strings that 'look like prefixes' are treated as ordinary digits.
// ------------------------------------------------------------
void testOnlyHexPrefixIsSpecialCased(ksword_tests::Suite& suite) {
    // `0b1010` is often mistaken for binary notation, but this tool never promised special handling for `0b`. Since
    // every character is valid in the hexadecimal set, the entire string is parsed as hexadecimal, yielding `0x0B1010`.
    // This behavior is **frozen** here because it is easily mistaken by future maintainers as a bug to be "fixed" into
    // either a rejection or binary parsing; both of those changes would alter the meaning of the `0b1010` input again.
    const auto kBinaryLooking = addr("0b1010");
    suite.expect(kBinaryLooking.ok && kBinaryLooking.value == 0x0B1010ULL,
        L"numeric text: 0b1010 is read as the hex digits 0B1010, with no binary prefix special case");
    suite.expect(!kBinaryLooking.hadHexPrefix,
        L"numeric text: 0b is not reported as a prefix");

    // Under quantity semantics, the same string follows 'decimal failure -> hex fallback', yielding the same result.
    const auto kAsQuantity = num("0b1010");
    suite.expect(kAsQuantity.ok && kAsQuantity.value == 0x0B1010ULL,
        L"numeric text: 0b1010 falls back to the same hex reading in quantity semantics");

    // A lone 0 must remain 0 and not be accidentally consumed by 'prefix detection'.
    const auto kZero = addr("0");
    suite.expect(kZero.ok && kZero.value == 0ULL,
        L"numeric text: a lone 0 parses as 0 and is not mistaken for a prefix");
    const auto kZeroQuantity = num("0");
    suite.expect(kZeroQuantity.ok && kZeroQuantity.value == 0ULL,
        L"numeric text: a lone 0 parses as 0 in quantity semantics");
}

} // namespace

int runNumericTextParseTests() {
    ksword_tests::Suite suite(L"ADDR numeric text");
    testBareDigitsSplitBySemantics(suite);
    testHexPrefixWinsOverDefault(suite);
    testDecimalFallbackBoundary(suite);
    testOverflowIsRejected(suite);
    testRejectedInputs(suite);
    testOnlyHexPrefixIsSpecialCased(suite);
    suite.report();
    return suite.failures();
}
