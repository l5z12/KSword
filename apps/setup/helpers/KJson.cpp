#include "KJson.h"

#include <cmath>
#include <cctype>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace {

// Parser and writer constants stay local to this translation unit.
const int kPrettyIndentSpaces = 4;
const int kMaxJsonDepth = 256;

// appendIndent writes depth * kPrettyIndentSpaces spaces into output and returns
// no value. The writer uses it only for pretty formatting.
void appendIndent(std::string& output, int depth) {
    output.append(static_cast<std::size_t>(depth * kPrettyIndentSpaces), ' ');
}

// appendHex4 writes a four-digit uppercase JSON \\u escape code and returns no
// value. It is used for control characters that do not have short escapes.
void appendHex4(std::string& output, unsigned int codePoint) {
    static const char kHex[] = "0123456789ABCDEF";
    output.push_back('\\');
    output.push_back('u');
    output.push_back(kHex[(codePoint >> 12) & 0x0F]);
    output.push_back(kHex[(codePoint >> 8) & 0x0F]);
    output.push_back(kHex[(codePoint >> 4) & 0x0F]);
    output.push_back(kHex[codePoint & 0x0F]);
}

// appendUtf8 encodes one Unicode code point as UTF-8 bytes. Input is assumed to
// be a valid scalar value; invalid callers receive no appended bytes.
void appendUtf8(std::string& output, unsigned int codePoint) {
    if (codePoint <= 0x7F) {
        output.push_back(static_cast<char>(codePoint));
    } else if (codePoint <= 0x7FF) {
        output.push_back(static_cast<char>(0xC0 | ((codePoint >> 6) & 0x1F)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    } else if (codePoint <= 0xFFFF) {
        output.push_back(static_cast<char>(0xE0 | ((codePoint >> 12) & 0x0F)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    } else if (codePoint <= 0x10FFFF) {
        output.push_back(static_cast<char>(0xF0 | ((codePoint >> 18) & 0x07)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    }
}

// decodeUtf8At validates and decodes one UTF-8 sequence at index. It returns
// false for malformed, overlong, surrogate, or out-of-range sequences.
bool decodeUtf8At(const std::string& input, std::size_t index, std::size_t& bytesRead, unsigned int& codePoint) {
    bytesRead = 0;
    codePoint = 0;

    if (index >= input.size()) {
        return false;
    }

    const unsigned char kFirst = static_cast<unsigned char>(input[index]);
    if (kFirst <= 0x7F) {
        bytesRead = 1;
        codePoint = kFirst;
        return true;
    }

    std::size_t expected = 0;
    unsigned int minimum = 0;
    if ((kFirst & 0xE0) == 0xC0) {
        expected = 2;
        codePoint = kFirst & 0x1F;
        minimum = 0x80;
    } else if ((kFirst & 0xF0) == 0xE0) {
        expected = 3;
        codePoint = kFirst & 0x0F;
        minimum = 0x800;
    } else if ((kFirst & 0xF8) == 0xF0) {
        expected = 4;
        codePoint = kFirst & 0x07;
        minimum = 0x10000;
    } else {
        return false;
    }

    if (index + expected > input.size()) {
        return false;
    }

    for (std::size_t i = 1; i < expected; ++i) {
        const unsigned char kNext = static_cast<unsigned char>(input[index + i]);
        if ((kNext & 0xC0) != 0x80) {
            return false;
        }
        codePoint = (codePoint << 6) | (kNext & 0x3F);
    }

    if (codePoint < minimum || codePoint > 0x10FFFF) {
        return false;
    }
    if (codePoint >= 0xD800 && codePoint <= 0xDFFF) {
        return false;
    }

    bytesRead = expected;
    return true;
}

// escapeString writes a JSON string literal, including surrounding quotes. It
// preserves valid UTF-8 bytes and escapes JSON control characters.
void escapeString(std::string& output, const std::string& value) {
    output.push_back('"');
    for (std::size_t i = 0; i < value.size(); ++i) {
        const unsigned char kCh = static_cast<unsigned char>(value[i]);
        switch (kCh) {
        case '"':
            output += "\\\"";
            break;
        case '\\':
            output += "\\\\";
            break;
        case '\b':
            output += "\\b";
            break;
        case '\f':
            output += "\\f";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            if (kCh < 0x20) {
                appendHex4(output, kCh);
            } else {
                output.push_back(static_cast<char>(kCh));
            }
            break;
        }
    }
    output.push_back('"');
}

void serializeValue(const KJsonValue& value, KJsonFormat format, int depth, std::string& output);

// serializeArray writes one array recursively. It returns no value and delegates
// scalar/container details back to serializeValue().
void serializeArray(const KJsonArray& arrayValue, KJsonFormat format, int depth, std::string& output) {
    if (arrayValue.isEmpty()) {
        output += "[]";
        return;
    }

    const bool kPretty = format == KJsonFormat::kPretty;
    output.push_back('[');
    if (kPretty) {
        output.push_back('\n');
    }

    for (std::size_t i = 0; i < arrayValue.size(); ++i) {
        if (kPretty) {
            appendIndent(output, depth + 1);
        }
        serializeValue(arrayValue.at(i), format, depth + 1, output);
        if (i + 1 < arrayValue.size()) {
            output.push_back(',');
        }
        if (kPretty) {
            output.push_back('\n');
        }
    }

    if (kPretty) {
        appendIndent(output, depth);
    }
    output.push_back(']');
}

// serializeObject writes one object recursively. std::map iteration gives stable
// key order, so the same object serializes to the same bytes every time.
void serializeObject(const KJsonObject& objectValue, KJsonFormat format, int depth, std::string& output) {
    if (objectValue.isEmpty()) {
        output += "{}";
        return;
    }

    const bool kPretty = format == KJsonFormat::kPretty;
    output.push_back('{');
    if (kPretty) {
        output.push_back('\n');
    }

    std::size_t index = 0;
    const std::size_t kMemberCount = objectValue.size();
    for (KJsonObject::ConstIterator it = objectValue.begin(); it != objectValue.end(); ++it, ++index) {
        if (kPretty) {
            appendIndent(output, depth + 1);
        }
        escapeString(output, it->first);
        output.push_back(':');
        if (kPretty) {
            output.push_back(' ');
        }
        serializeValue(it->second, format, depth + 1, output);
        if (index + 1 < kMemberCount) {
            output.push_back(',');
        }
        if (kPretty) {
            output.push_back('\n');
        }
    }

    if (kPretty) {
        appendIndent(output, depth);
    }
    output.push_back('}');
}

// serializeValue writes one JSON node and returns no value. Non-finite doubles
// are emitted as null because JSON has no NaN or infinity tokens.
void serializeValue(const KJsonValue& value, KJsonFormat format, int depth, std::string& output) {
    switch (value.type()) {
    case KJsonValue::kNull:
        output += "null";
        break;
    case KJsonValue::kBool:
        output += value.toBool() ? "true" : "false";
        break;
    case KJsonValue::kInt64: {
        std::ostringstream stream;
        stream.imbue(std::locale::classic());
        stream << value.toInt();
        output += stream.str();
        break;
    }
    case KJsonValue::kDouble: {
        const double kDoubleValue = value.toDouble();
        if (!std::isfinite(kDoubleValue)) {
            output += "null";
            break;
        }
        std::ostringstream stream;
        stream.imbue(std::locale::classic());
        stream << std::setprecision(std::numeric_limits<double>::max_digits10) << kDoubleValue;
        output += stream.str();
        break;
    }
    case KJsonValue::kString:
        escapeString(output, value.toString());
        break;
    case KJsonValue::kArray:
        serializeArray(value.toArray(), format, depth, output);
        break;
    case KJsonValue::kObject:
        serializeObject(value.toObject(), format, depth, output);
        break;
    }
}

// HexValue converts an ASCII hex digit to its numeric value. It returns -1 for
// any non-hex byte so callers can report a JSON escape error.
int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

// KJsonParser implements a recursive descent parser over UTF-8 bytes. It owns
// no output memory beyond temporary values and records only the first error.
class KJsonParser {
public:
    // The constructor receives the immutable input buffer and optional error sink.
    KJsonParser(const std::string& input, KJsonParseError* parseError)
        : input_(input),
          error_(parseError),
          index_(0),
          line_(1),
          column_(1),
          failed_(false) {
        if (error_) {
            error_->clear();
        }
    }

    // parseDocument parses one complete JSON value and rejects trailing garbage.
    KJsonDocument parseDocument() {
        KJsonValue root;
        skipWhitespace();
        if (!parseValue(root, 0)) {
            return KJsonDocument();
        }
        skipWhitespace();
        if (!atEnd()) {
            fail(KJsonParseError::kGarbageAtEnd, "Unexpected bytes after the JSON value");
            return KJsonDocument();
        }
        if (error_) {
            error_->clear();
        }
        return KJsonDocument(root);
    }

private:
    // atEnd returns true when all bytes have been consumed.
    bool atEnd() const {
        return index_ >= input_.size();
    }

    // peek returns the current byte or NUL at end of input.
    char peek() const {
        return atEnd() ? '\0' : input_[index_];
    }

    // advance consumes one byte and updates one-based line/column counters.
    char advance() {
        if (atEnd()) {
            return '\0';
        }
        const char kCh = input_[index_++];
        if (kCh == '\n') {
            ++line_;
            column_ = 1;
        } else {
            ++column_;
        }
        return kCh;
    }

    // consume advances one byte when it matches expected and returns success.
    bool consume(char expected) {
        if (peek() != expected) {
            return false;
        }
        advance();
        return true;
    }

    // skipWhitespace consumes the four whitespace bytes allowed by JSON.
    void skipWhitespace() {
        while (!atEnd()) {
            const char kCh = peek();
            if (kCh == ' ' || kCh == '\t' || kCh == '\r' || kCh == '\n') {
                advance();
            } else {
                break;
            }
        }
    }

    // fail records the first error and returns false for convenient parser code.
    bool fail(KJsonParseError::ParseError error, const std::string& message) {
        if (!failed_ && error_) {
            error_->error = error;
            error_->offset = static_cast<int>(index_);
            error_->line = line_;
            error_->column = column_;
            error_->message = message;
        }
        failed_ = true;
        return false;
    }

    // parseValue dispatches to the correct grammar production based on the next byte.
    bool parseValue(KJsonValue& output, int depth) {
        if (depth > kMaxJsonDepth) {
            return fail(KJsonParseError::kDeepNesting, "JSON nesting depth limit exceeded");
        }

        skipWhitespace();
        if (atEnd()) {
            return fail(KJsonParseError::kIllegalValue, "Expected a JSON value");
        }

        const char kCh = peek();
        if (kCh == 'n') {
            return parseLiteral("null", KJsonValue(), output);
        }
        if (kCh == 't') {
            return parseLiteral("true", KJsonValue(true), output);
        }
        if (kCh == 'f') {
            return parseLiteral("false", KJsonValue(false), output);
        }
        if (kCh == '"') {
            std::string stringValue;
            if (!parseString(stringValue)) {
                return false;
            }
            output = KJsonValue(stringValue);
            return true;
        }
        if (kCh == '[') {
            KJsonArray arrayValue;
            if (!parseArray(arrayValue, depth + 1)) {
                return false;
            }
            output = KJsonValue(arrayValue);
            return true;
        }
        if (kCh == '{') {
            KJsonObject objectValue;
            if (!parseObject(objectValue, depth + 1)) {
                return false;
            }
            output = KJsonValue(objectValue);
            return true;
        }
        if (kCh == '-' || (kCh >= '0' && kCh <= '9')) {
            return parseNumber(output);
        }

        return fail(KJsonParseError::kIllegalValue, "Unexpected byte while reading JSON value");
    }

    // parseLiteral consumes a fixed token such as true, false, or null.
    bool parseLiteral(const char* literal, const KJsonValue& value, KJsonValue& output) {
        for (const char* cursor = literal; *cursor != '\0'; ++cursor) {
            if (peek() != *cursor) {
                return fail(KJsonParseError::kIllegalValue, std::string("Expected '") + literal + "'");
            }
            advance();
        }
        output = value;
        return true;
    }

    // parseString consumes a JSON string, decodes escapes, validates UTF-8, and
    // writes the unescaped UTF-8 bytes into output.
    bool parseString(std::string& output) {
        if (!consume('"')) {
            return fail(KJsonParseError::kUnterminatedString, "Expected string opening quote");
        }

        while (!atEnd()) {
            const unsigned char kCh = static_cast<unsigned char>(peek());
            if (kCh == '"') {
                advance();
                return true;
            }
            if (kCh == '\\') {
                advance();
                if (!parseEscape(output)) {
                    return false;
                }
                continue;
            }
            if (kCh < 0x20) {
                return fail(KJsonParseError::kUnterminatedString, "Unescaped control character in string");
            }
            if (kCh < 0x80) {
                output.push_back(advance());
                continue;
            }

            std::size_t bytesRead = 0;
            unsigned int codePoint = 0;
            if (!decodeUtf8At(input_, index_, bytesRead, codePoint)) {
                return fail(KJsonParseError::kIllegalUtF8String, "Invalid UTF-8 sequence in string");
            }
            for (std::size_t i = 0; i < bytesRead; ++i) {
                output.push_back(advance());
            }
        }

        return fail(KJsonParseError::kUnterminatedString, "Missing string closing quote");
    }

    // parseEscape consumes the byte after a backslash and appends its decoded
    // value to output. Unicode surrogate pairs are combined into UTF-8.
    bool parseEscape(std::string& output) {
        if (atEnd()) {
            return fail(KJsonParseError::kUnterminatedString, "String ends inside an escape sequence");
        }

        const char kEscapeCode = advance();
        switch (kEscapeCode) {
        case '"':
            output.push_back('"');
            return true;
        case '\\':
            output.push_back('\\');
            return true;
        case '/':
            output.push_back('/');
            return true;
        case 'b':
            output.push_back('\b');
            return true;
        case 'f':
            output.push_back('\f');
            return true;
        case 'n':
            output.push_back('\n');
            return true;
        case 'r':
            output.push_back('\r');
            return true;
        case 't':
            output.push_back('\t');
            return true;
        case 'u':
            return parseUnicodeEscape(output);
        default:
            return fail(KJsonParseError::kIllegalEscapeSequence, "Unsupported string escape sequence");
        }
    }

    // parseUnicodeEscape decodes four hex digits after \\u. If it sees a high
    // surrogate, it requires and combines a following low-surrogate escape.
    bool parseUnicodeEscape(std::string& output) {
        unsigned int codeUnit = 0;
        if (!parseHex4(codeUnit)) {
            return false;
        }

        if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF) {
            if (!consume('\\') || !consume('u')) {
                return fail(KJsonParseError::kIllegalEscapeSequence, "Expected low surrogate after high surrogate");
            }
            unsigned int lowSurrogate = 0;
            if (!parseHex4(lowSurrogate)) {
                return false;
            }
            if (lowSurrogate < 0xDC00 || lowSurrogate > 0xDFFF) {
                return fail(KJsonParseError::kIllegalEscapeSequence, "Invalid low surrogate in Unicode escape");
            }
            const unsigned int kHighTenBits = codeUnit - 0xD800;
            const unsigned int kLowTenBits = lowSurrogate - 0xDC00;
            const unsigned int kCodePoint = 0x10000 + ((kHighTenBits << 10) | kLowTenBits);
            appendUtf8(output, kCodePoint);
            return true;
        }

        if (codeUnit >= 0xDC00 && codeUnit <= 0xDFFF) {
            return fail(KJsonParseError::kIllegalEscapeSequence, "Low surrogate without preceding high surrogate");
        }

        appendUtf8(output, codeUnit);
        return true;
    }

    // parseHex4 consumes exactly four ASCII hex digits and writes the numeric
    // value into output.
    bool parseHex4(unsigned int& output) {
        output = 0;
        for (int i = 0; i < 4; ++i) {
            if (atEnd()) {
                return fail(KJsonParseError::kIllegalEscapeSequence, "Unicode escape ended early");
            }
            const int kValue = hexValue(peek());
            if (kValue < 0) {
                return fail(KJsonParseError::kIllegalEscapeSequence, "Unicode escape contains a non-hex digit");
            }
            output = (output << 4) | static_cast<unsigned int>(kValue);
            advance();
        }
        return true;
    }

    // parseNumber consumes the JSON number grammar and stores either Int64 or
    // Double depending on fractional/exponent notation.
    bool parseNumber(KJsonValue& output) {
        const std::size_t kStart = index_;
        bool floatingPoint = false;

        if (peek() == '-') {
            advance();
        }

        if (atEnd()) {
            return fail(KJsonParseError::kIllegalNumber, "Number ended after sign");
        }

        if (peek() == '0') {
            advance();
            if (!atEnd() && std::isdigit(static_cast<unsigned char>(peek()))) {
                return fail(KJsonParseError::kIllegalNumber, "Leading zero is not allowed in JSON numbers");
            }
        } else if (peek() >= '1' && peek() <= '9') {
            while (!atEnd() && std::isdigit(static_cast<unsigned char>(peek()))) {
                advance();
            }
        } else {
            return fail(KJsonParseError::kIllegalNumber, "Expected digit in JSON number");
        }

        if (!atEnd() && peek() == '.') {
            floatingPoint = true;
            advance();
            if (atEnd() || !std::isdigit(static_cast<unsigned char>(peek()))) {
                return fail(KJsonParseError::kIllegalNumber, "Expected digit after decimal point");
            }
            while (!atEnd() && std::isdigit(static_cast<unsigned char>(peek()))) {
                advance();
            }
        }

        if (!atEnd() && (peek() == 'e' || peek() == 'E')) {
            floatingPoint = true;
            advance();
            if (!atEnd() && (peek() == '+' || peek() == '-')) {
                advance();
            }
            if (atEnd() || !std::isdigit(static_cast<unsigned char>(peek()))) {
                return fail(KJsonParseError::kIllegalNumber, "Expected exponent digits");
            }
            while (!atEnd() && std::isdigit(static_cast<unsigned char>(peek()))) {
                advance();
            }
        }

        const std::string kNumberText = input_.substr(kStart, index_ - kStart);
        if (floatingPoint) {
            double doubleValue = 0.0;
            std::istringstream stream(kNumberText);
            stream.imbue(std::locale::classic());
            stream >> doubleValue;
            if (stream.fail() || !stream.eof() || !std::isfinite(doubleValue)) {
                return fail(KJsonParseError::kIllegalNumber, "Floating-point number is out of range");
            }
            output = KJsonValue(doubleValue);
            return true;
        }

        try {
            std::size_t parsed = 0;
            const long long kIntValue = std::stoll(kNumberText, &parsed, 10);
            if (parsed != kNumberText.size()) {
                return fail(KJsonParseError::kIllegalNumber, "Integer contains invalid bytes");
            }
            output = KJsonValue(kIntValue);
            return true;
        } catch (const std::exception&) {
            return fail(KJsonParseError::kIllegalNumber, "Integer is out of 64-bit range");
        }
    }

    // parseArray consumes '[' elements ']' and fills output in input order.
    bool parseArray(KJsonArray& output, int depth) {
        if (!consume('[')) {
            return fail(KJsonParseError::kIllegalValue, "Expected array opening bracket");
        }

        skipWhitespace();
        if (consume(']')) {
            return true;
        }

        while (!atEnd()) {
            KJsonValue item;
            if (!parseValue(item, depth)) {
                return false;
            }
            output.append(item);
            skipWhitespace();
            if (consume(',')) {
                skipWhitespace();
                continue;
            }
            if (consume(']')) {
                return true;
            }
            return fail(KJsonParseError::kMissingValueSeparator, "Expected ',' or ']' after array value");
        }

        return fail(KJsonParseError::kMissingValueSeparator, "Array ended before closing bracket");
    }

    // parseObject consumes '{' members '}' and fills output by key. Duplicate
    // keys intentionally keep the last value, matching many JSON object maps.
    bool parseObject(KJsonObject& output, int depth) {
        if (!consume('{')) {
            return fail(KJsonParseError::kIllegalValue, "Expected object opening brace");
        }

        skipWhitespace();
        if (consume('}')) {
            return true;
        }

        while (!atEnd()) {
            if (peek() != '"') {
                return fail(KJsonParseError::kIllegalValue, "Expected object member name");
            }
            std::string key;
            if (!parseString(key)) {
                return false;
            }
            skipWhitespace();
            if (!consume(':')) {
                return fail(KJsonParseError::kMissingNameSeparator, "Expected ':' after object member name");
            }
            KJsonValue memberValue;
            if (!parseValue(memberValue, depth)) {
                return false;
            }
            output.insert(key, memberValue);
            skipWhitespace();
            if (consume(',')) {
                skipWhitespace();
                continue;
            }
            if (consume('}')) {
                return true;
            }
            return fail(KJsonParseError::kMissingValueSeparator, "Expected ',' or '}' after object member");
        }

        return fail(KJsonParseError::kMissingValueSeparator, "Object ended before closing brace");
    }

    // Input and mutable parser state are deliberately simple byte indexes.
    const std::string& input_;
    KJsonParseError* error_;
    std::size_t index_;
    int line_;
    int column_;
    bool failed_;
};

} // namespace

KJsonParseError::KJsonParseError()
    : error(kNoError), offset(0), line(1), column(1), message() {
}

void KJsonParseError::clear() {
    error = kNoError;
    offset = 0;
    line = 1;
    column = 1;
    message.clear();
}

bool KJsonParseError::hasError() const {
    return error != kNoError;
}

std::string KJsonParseError::errorString() const {
    if (!hasError()) {
        return "No error";
    }

    std::ostringstream stream;
    stream << (message.empty() ? "JSON parse error" : message)
           << " at line " << line
           << ", column " << column
           << " (offset " << offset << ")";
    return stream.str();
}

KJsonValue::KJsonValue()
    : type_(kNull),
      boolValue_(false),
      intValue_(0),
      doubleValue_(0.0),
      stringValue_(),
      arrayValue_(),
      objectValue_() {
}

KJsonValue::KJsonValue(std::nullptr_t)
    : KJsonValue() {
}

KJsonValue::KJsonValue(bool value)
    : KJsonValue() {
    reset(kBool);
    boolValue_ = value;
}

KJsonValue::KJsonValue(int value)
    : KJsonValue(static_cast<long long>(value)) {
}

KJsonValue::KJsonValue(long long value)
    : KJsonValue() {
    reset(kInt64);
    intValue_ = value;
}

KJsonValue::KJsonValue(double value)
    : KJsonValue() {
    reset(kDouble);
    doubleValue_ = value;
}

KJsonValue::KJsonValue(const char* value)
    : KJsonValue() {
    if (value) {
        reset(kString);
        stringValue_ = value;
    }
}

KJsonValue::KJsonValue(const std::string& value)
    : KJsonValue() {
    reset(kString);
    stringValue_ = value;
}

KJsonValue::KJsonValue(const KJsonArray& value)
    : KJsonValue() {
    reset(kArray);
    arrayValue_.reset(new KJsonArray(value));
}

KJsonValue::KJsonValue(const KJsonObject& value)
    : KJsonValue() {
    reset(kObject);
    objectValue_.reset(new KJsonObject(value));
}

KJsonValue::~KJsonValue() {
}

KJsonValue::Type KJsonValue::type() const {
    return type_;
}

bool KJsonValue::isNull() const {
    return type_ == kNull;
}

bool KJsonValue::isBool() const {
    return type_ == kBool;
}

bool KJsonValue::isInt() const {
    return type_ == kInt64;
}

bool KJsonValue::isDouble() const {
    return type_ == kDouble;
}

bool KJsonValue::isNumber() const {
    return type_ == kInt64 || type_ == kDouble;
}

bool KJsonValue::isString() const {
    return type_ == kString;
}

bool KJsonValue::isArray() const {
    return type_ == kArray;
}

bool KJsonValue::isObject() const {
    return type_ == kObject;
}

bool KJsonValue::toBool(bool defaultValue) const {
    return type_ == kBool ? boolValue_ : defaultValue;
}

long long KJsonValue::toInt(long long defaultValue) const {
    return type_ == kInt64 ? intValue_ : defaultValue;
}

double KJsonValue::toDouble(double defaultValue) const {
    if (type_ == kDouble) {
        return doubleValue_;
    }
    if (type_ == kInt64) {
        return static_cast<double>(intValue_);
    }
    return defaultValue;
}

std::string KJsonValue::toString(const std::string& defaultValue) const {
    return type_ == kString ? stringValue_ : defaultValue;
}

KJsonArray KJsonValue::toArray() const {
    if (type_ == kArray && arrayValue_) {
        return *arrayValue_;
    }
    return KJsonArray();
}

KJsonObject KJsonValue::toObject() const {
    if (type_ == kObject && objectValue_) {
        return *objectValue_;
    }
    return KJsonObject();
}

std::string KJsonValue::toJson(KJsonFormat format) const {
    std::string output;
    serializeValue(*this, format, 0, output);
    return output;
}

void KJsonValue::reset(Type nextType) {
    type_ = nextType;
    boolValue_ = false;
    intValue_ = 0;
    doubleValue_ = 0.0;
    stringValue_.clear();
    arrayValue_.reset();
    objectValue_.reset();
}

KJsonArray::KJsonArray()
    : values_() {
}

KJsonArray::KJsonArray(const std::vector<KJsonValue>& values)
    : values_(values) {
}

void KJsonArray::append(const KJsonValue& value) {
    values_.push_back(value);
}

void KJsonArray::clear() {
    values_.clear();
}

KJsonValue KJsonArray::value(std::size_t index, const KJsonValue& defaultValue) const {
    if (index >= values_.size()) {
        return defaultValue;
    }
    return values_[index];
}

const KJsonValue& KJsonArray::at(std::size_t index) const {
    return values_.at(index);
}

KJsonValue& KJsonArray::operator[](std::size_t index) {
    return values_[index];
}

const KJsonValue& KJsonArray::operator[](std::size_t index) const {
    return values_[index];
}

std::size_t KJsonArray::size() const {
    return values_.size();
}

bool KJsonArray::isEmpty() const {
    return values_.empty();
}

KJsonArray::Iterator KJsonArray::begin() {
    return values_.begin();
}

KJsonArray::Iterator KJsonArray::end() {
    return values_.end();
}

KJsonArray::ConstIterator KJsonArray::begin() const {
    return values_.begin();
}

KJsonArray::ConstIterator KJsonArray::end() const {
    return values_.end();
}

std::vector<KJsonValue> KJsonArray::values() const {
    return values_;
}

std::string KJsonArray::toJson(KJsonFormat format) const {
    std::string output;
    serializeArray(*this, format, 0, output);
    return output;
}

KJsonObject::KJsonObject()
    : values_() {
}

void KJsonObject::insert(const std::string& key, const KJsonValue& value) {
    values_[key] = value;
}

bool KJsonObject::remove(const std::string& key) {
    return values_.erase(key) > 0;
}

void KJsonObject::clear() {
    values_.clear();
}

bool KJsonObject::contains(const std::string& key) const {
    return values_.find(key) != values_.end();
}

KJsonValue KJsonObject::value(const std::string& key, const KJsonValue& defaultValue) const {
    ConstIterator it = values_.find(key);
    if (it == values_.end()) {
        return defaultValue;
    }
    return it->second;
}

KJsonValue& KJsonObject::operator[](const std::string& key) {
    return values_[key];
}

std::size_t KJsonObject::size() const {
    return values_.size();
}

bool KJsonObject::isEmpty() const {
    return values_.empty();
}

std::vector<std::string> KJsonObject::keys() const {
    std::vector<std::string> result;
    result.reserve(values_.size());
    for (ConstIterator it = values_.begin(); it != values_.end(); ++it) {
        result.push_back(it->first);
    }
    return result;
}

KJsonObject::Iterator KJsonObject::begin() {
    return values_.begin();
}

KJsonObject::Iterator KJsonObject::end() {
    return values_.end();
}

KJsonObject::ConstIterator KJsonObject::begin() const {
    return values_.begin();
}

KJsonObject::ConstIterator KJsonObject::end() const {
    return values_.end();
}

std::string KJsonObject::toJson(KJsonFormat format) const {
    std::string output;
    serializeObject(*this, format, 0, output);
    return output;
}

KJsonDocument::KJsonDocument()
    : value_() {
}

KJsonDocument::KJsonDocument(const KJsonValue& value)
    : value_(value) {
}

KJsonDocument::KJsonDocument(const KJsonObject& object)
    : value_(object) {
}

KJsonDocument::KJsonDocument(const KJsonArray& array)
    : value_(array) {
}

KJsonDocument KJsonDocument::fromJson(const std::string& json, KJsonParseError* parseError) {
    KJsonParser parser(json, parseError);
    return parser.parseDocument();
}

std::string KJsonDocument::toJson(KJsonFormat format) const {
    return value_.toJson(format);
}

bool KJsonDocument::isNull() const {
    return value_.isNull();
}

bool KJsonDocument::isArray() const {
    return value_.isArray();
}

bool KJsonDocument::isObject() const {
    return value_.isObject();
}

KJsonValue KJsonDocument::value() const {
    return value_;
}

KJsonArray KJsonDocument::array() const {
    return value_.toArray();
}

KJsonObject KJsonDocument::object() const {
    return value_.toObject();
}

void KJsonDocument::setValue(const KJsonValue& value) {
    value_ = value;
}
