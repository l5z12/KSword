#include "EvidenceJson.h"

#include <limits>
#include <unordered_set>

namespace ksword::evidence {
namespace {

constexpr char kHexDigitsLower[] = "0123456789abcdef";

void appendEscapedString(std::string& out, const std::string& text) {
    out.push_back('"');
    for (const char kRaw : text) {
        const unsigned char kC = static_cast<unsigned char>(kRaw);
        switch (kC) {
        case '"':  out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\b': out.append("\\b"); break;
        case '\f': out.append("\\f"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
            if (kC < 0x20U) {
                // Q-12: All control characters must be escaped; no raw control codes should remain in the report.
                out.append("\\u00");
                out.push_back(kHexDigitsLower[(kC >> 4U) & 0xFU]);
                out.push_back(kHexDigitsLower[kC & 0xFU]);
            } else {
                out.push_back(kRaw);
            }
            break;
        }
    }
    out.push_back('"');
}

void appendIndent(std::string& out, unsigned indent, unsigned depth) {
    if (indent == 0U) {
        return;
    }
    out.push_back('\n');
    out.append(static_cast<std::size_t>(indent) * depth, ' ');
}

void writeValue(std::string& out, const JsonValue& value, unsigned indent, unsigned depth);

void writeContainer(std::string& out,
                    const JsonValue& value,
                    unsigned indent,
                    unsigned depth) {
    if (const JsonArray* array = value.asArray()) {
        if (array->empty()) {
            out.append("[]");
            return;
        }
        out.push_back('[');
        bool first = true;
        for (const JsonValue& item : *array) {
            if (!first) {
                out.push_back(',');
            }
            first = false;
            appendIndent(out, indent, depth + 1U);
            writeValue(out, item, indent, depth + 1U);
        }
        appendIndent(out, indent, depth);
        out.push_back(']');
        return;
    }

    const JsonObject* object = value.asObject();
    if (object == nullptr || object->empty()) {
        out.append("{}");
        return;
    }
    out.push_back('{');
    bool first = true;
    for (const auto& member : *object) {
        if (!first) {
            out.push_back(',');
        }
        first = false;
        appendIndent(out, indent, depth + 1U);
        appendEscapedString(out, member.first);
        out.push_back(':');
        if (indent != 0U) {
            out.push_back(' ');
        }
        writeValue(out, member.second, indent, depth + 1U);
    }
    appendIndent(out, indent, depth);
    out.push_back('}');
}

void writeValue(std::string& out, const JsonValue& value, unsigned indent, unsigned depth) {
    switch (value.type()) {
    case JsonType::kNull:
        out.append("null");
        break;
    case JsonType::kBool: {
        bool flag = false;
        (void)value.tryGetBool(flag);
        out.append(flag ? "true" : "false");
        break;
    }
    case JsonType::kUInt: {
        std::uint64_t number = 0U;
        (void)value.tryGetU64(number);
        out.append(formatU64(number, U64Format::kDecimal));
        break;
    }
    case JsonType::kInt: {
        std::int64_t number = 0;
        (void)value.tryGetI64(number);
        out.append(formatI64(number));
        break;
    }
    case JsonType::kString: {
        std::string text;
        (void)value.tryGetString(text);
        appendEscapedString(out, text);
        break;
    }
    case JsonType::kArray:
    case JsonType::kObject:
        writeContainer(out, value, indent, depth);
        break;
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
class Parser final {
public:
    Parser(std::string_view text, const JsonLimits& limits) noexcept
        : text_(text), limits_(limits) {}

    JsonParseResult run() {
        skipWhitespace();
        if (pos_ >= text_.size()) {
            return fail(JsonParseStatus::kEmpty);
        }
        JsonValue value;
        if (!parseValue(value, 0U)) {
            return fail(status_);
        }
        skipWhitespace();
        if (pos_ != text_.size()) {
            return fail(JsonParseStatus::kTrailingData);
        }
        JsonParseResult result;
        result.status = JsonParseStatus::kOk;
        result.value = std::move(value);
        return result;
    }

private:
    JsonParseResult fail(JsonParseStatus status) const {
        JsonParseResult result;
        result.status = status == JsonParseStatus::kOk ? JsonParseStatus::kSyntax : status;
        result.errorOffset = pos_;
        return result;
    }

    void skipWhitespace() noexcept {
        while (pos_ < text_.size()) {
            const char kC = text_[pos_];
            if (kC == ' ' || kC == '\t' || kC == '\n' || kC == '\r') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    bool consume(char expected) noexcept {
        if (pos_ < text_.size() && text_[pos_] == expected) {
            ++pos_;
            return true;
        }
        status_ = JsonParseStatus::kSyntax;
        return false;
    }

    bool literal(std::string_view word) noexcept {
        if (text_.size() - pos_ < word.size() || text_.compare(pos_, word.size(), word) != 0) {
            status_ = JsonParseStatus::kSyntax;
            return false;
        }
        pos_ += word.size();
        return true;
    }

    bool countNode() noexcept {
        if (++nodes_ > limits_.maxTotalNodes) {
            status_ = JsonParseStatus::kNodeLimit;
            return false;
        }
        // F-07 / Q-12: Limiting node count alone does not bound memory amplification. Four arrays of one million elements each use only
        // 7.6 MB of input but expand to hundreds of MB based on sizeof(JsonValue). Apply a separate limit to the estimated byte size.
        // Use division instead of multiplication to avoid overflow of nodes_ * sizeof before the operation.
        if (limits_.maxEstimatedNodeBytes != 0U &&
            nodes_ > limits_.maxEstimatedNodeBytes / sizeof(JsonValue)) {
            status_ = JsonParseStatus::kSizeLimit;
            return false;
        }
        return true;
    }

    bool parseValue(JsonValue& out, std::size_t depth) {
        if (depth > limits_.maxDepth) {
            status_ = JsonParseStatus::kDepthLimit;
            return false;
        }
        if (!countNode()) {
            return false;
        }
        skipWhitespace();
        if (pos_ >= text_.size()) {
            status_ = JsonParseStatus::kSyntax;
            return false;
        }
        switch (text_[pos_]) {
        case 'n':
            if (!literal("null")) {
                return false;
            }
            out = JsonValue::makeNull();
            return true;
        case 't':
            if (!literal("true")) {
                return false;
            }
            out = JsonValue::makeBool(true);
            return true;
        case 'f':
            if (!literal("false")) {
                return false;
            }
            out = JsonValue::makeBool(false);
            return true;
        case '"': {
            std::string text;
            if (!parseString(text)) {
                return false;
            }
            out = JsonValue::makeString(std::move(text));
            return true;
        }
        case '[':
            return parseArray(out, depth);
        case '{':
            return parseObject(out, depth);
        default:
            return parseNumber(out);
        }
    }

    bool parseArray(JsonValue& out, std::size_t depth) {
        if (!consume('[')) {
            return false;
        }
        JsonArray items;
        skipWhitespace();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            ++pos_;
            out = JsonValue::makeArray(std::move(items));
            return true;
        }
        for (;;) {
            if (items.size() >= limits_.maxContainerItems) {
                status_ = JsonParseStatus::kSizeLimit;
                return false;
            }
            JsonValue item;
            if (!parseValue(item, depth + 1U)) {
                return false;
            }
            items.push_back(std::move(item));
            skipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            break;
        }
        if (!consume(']')) {
            return false;
        }
        out = JsonValue::makeArray(std::move(items));
        return true;
    }

    bool parseObject(JsonValue& out, std::size_t depth) {
        if (!consume('{')) {
            return false;
        }
        JsonObject members;
        // Q-12: Duplicate key detection must be amortized O(1). Previously, using any_of to linearly scan collected members
        // created an O(n²) DoS vector on the import side: 128,000 members (1.4 MB) took 15 seconds in practice; extrapolating
        // to the default member limit yields ~17 minutes, yet status=Ok throughout, making the UI appear frozen.
        std::unordered_set<std::string> seenNames;
        skipWhitespace();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            ++pos_;
            out = JsonValue::makeObject(std::move(members));
            return true;
        }
        for (;;) {
            if (members.size() >= limits_.maxContainerItems) {
                status_ = JsonParseStatus::kSizeLimit;
                return false;
            }
            skipWhitespace();
            std::string name;
            if (!parseString(name)) {
                return false;
            }
            // Q-12: Duplicate IDs or duplicate keys must be rejected; later writes must not silently overwrite earlier ones.
            if (!seenNames.insert(name).second) {
                status_ = JsonParseStatus::kDuplicateKey;
                return false;
            }
            skipWhitespace();
            if (!consume(':')) {
                return false;
            }
            JsonValue value;
            if (!parseValue(value, depth + 1U)) {
                return false;
            }
            members.emplace_back(std::move(name), std::move(value));
            skipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            break;
        }
        if (!consume('}')) {
            return false;
        }
        out = JsonValue::makeObject(std::move(members));
        return true;
    }

    bool appendUtf8(std::string& out, std::uint32_t codepoint) {
        if (codepoint < 0x80U) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint < 0x800U) {
            out.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else if (codepoint < 0x10000U) {
            out.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else if (codepoint <= 0x10FFFFU) {
            out.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else {
            status_ = JsonParseStatus::kSyntax;
            return false;
        }
        return true;
    }

    bool parseHex4(std::uint32_t& out) noexcept {
        if (text_.size() - pos_ < 4U) {
            status_ = JsonParseStatus::kSyntax;
            return false;
        }
        std::uint32_t value = 0U;
        for (std::size_t i = 0U; i < 4U; ++i) {
            const char kC = text_[pos_ + i];
            std::uint32_t digit = 0U;
            if (kC >= '0' && kC <= '9') {
                digit = static_cast<std::uint32_t>(kC - '0');
            } else if (kC >= 'a' && kC <= 'f') {
                digit = static_cast<std::uint32_t>(kC - 'a') + 10U;
            } else if (kC >= 'A' && kC <= 'F') {
                digit = static_cast<std::uint32_t>(kC - 'A') + 10U;
            } else {
                status_ = JsonParseStatus::kSyntax;
                return false;
            }
            value = (value << 4U) | digit;
        }
        pos_ += 4U;
        out = value;
        return true;
    }

    bool parseString(std::string& out) {
        if (!consume('"')) {
            return false;
        }
        out.clear();
        for (;;) {
            if (pos_ >= text_.size()) {
                status_ = JsonParseStatus::kSyntax;
                return false;
            }
            if (out.size() > limits_.maxStringBytes) {
                status_ = JsonParseStatus::kSizeLimit;
                return false;
            }
            const char kC = text_[pos_];
            if (kC == '"') {
                ++pos_;
                return true;
            }
            if (kC == '\\') {
                ++pos_;
                if (pos_ >= text_.size()) {
                    status_ = JsonParseStatus::kSyntax;
                    return false;
                }
                const char kEsc = text_[pos_++];
                switch (kEsc) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t code = 0U;
                    if (!parseHex4(code)) {
                        return false;
                    }
                    if (code >= 0xD800U && code <= 0xDBFFU) {
                        // High proxy must immediately follow low proxy; otherwise, it is invalid data.
                        if (text_.size() - pos_ < 6U || text_[pos_] != '\\' || text_[pos_ + 1U] != 'u') {
                            status_ = JsonParseStatus::kSyntax;
                            return false;
                        }
                        pos_ += 2U;
                        std::uint32_t low = 0U;
                        if (!parseHex4(low)) {
                            return false;
                        }
                        if (low < 0xDC00U || low > 0xDFFFU) {
                            status_ = JsonParseStatus::kSyntax;
                            return false;
                        }
                        code = 0x10000U + ((code - 0xD800U) << 10U) + (low - 0xDC00U);
                    } else if (code >= 0xDC00U && code <= 0xDFFFU) {
                        status_ = JsonParseStatus::kSyntax;
                        return false;
                    }
                    if (!appendUtf8(out, code)) {
                        return false;
                    }
                    break;
                }
                default:
                    status_ = JsonParseStatus::kSyntax;
                    return false;
                }
                continue;
            }
            if (static_cast<unsigned char>(kC) < 0x20U) {
                status_ = JsonParseStatus::kSyntax;  // Raw control characters are invalid
                return false;
            }
            out.push_back(kC);
            ++pos_;
        }
    }

    bool parseNumber(JsonValue& out) {
        const std::size_t kStart = pos_;
        const bool kNegative = pos_ < text_.size() && text_[pos_] == '-';
        if (kNegative) {
            ++pos_;
        }
        const std::size_t kDigitStart = pos_;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            ++pos_;
        }
        if (pos_ == kDigitStart) {
            status_ = JsonParseStatus::kSyntax;
            pos_ = kStart;
            return false;
        }
        // F-08: This reader does not accept floating-point numbers. Decimal points and exponents are rejected outright, not downgraded in precision.
        if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
            status_ = JsonParseStatus::kFloatingPointRejected;
            return false;
        }
        const std::string_view kDigits = text_.substr(kDigitStart, pos_ - kDigitStart);
        std::uint64_t magnitude = 0U;
        if (!parseU64(kDigits, magnitude)) {
            status_ = JsonParseStatus::kIntegerOverflow;
            return false;
        }
        if (!kNegative) {
            out = JsonValue::makeUInt(magnitude);
            return true;
        }
        constexpr std::uint64_t kPositiveMax =
            static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        if (magnitude > kPositiveMax + 1ULL) {
            status_ = JsonParseStatus::kIntegerOverflow;
            return false;
        }
        if (magnitude == kPositiveMax + 1ULL) {
            out = JsonValue::makeInt((std::numeric_limits<std::int64_t>::min)());
            return true;
        }
        out = JsonValue::makeInt(-static_cast<std::int64_t>(magnitude));
        return true;
    }

    std::string_view text_;
    JsonLimits limits_;
    std::size_t pos_ = 0;
    std::size_t nodes_ = 0;
    JsonParseStatus status_ = JsonParseStatus::kSyntax;
};

} // namespace

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------
JsonValue JsonValue::makeNull() {
    JsonValue value;
    value.type_ = JsonType::kNull;
    return value;
}

JsonValue JsonValue::makeBool(bool flag) {
    JsonValue value;
    value.type_ = JsonType::kBool;
    value.bool_ = flag;
    return value;
}

JsonValue JsonValue::makeUInt(std::uint64_t number) {
    JsonValue value;
    value.type_ = JsonType::kUInt;
    value.uint_ = number;
    return value;
}

JsonValue JsonValue::makeInt(std::int64_t number) {
    JsonValue value;
    value.type_ = JsonType::kInt;
    value.int_ = number;
    return value;
}

JsonValue JsonValue::makeString(std::string text) {
    JsonValue value;
    value.type_ = JsonType::kString;
    value.string_ = std::move(text);
    return value;
}

JsonValue JsonValue::makeArray(JsonArray items) {
    JsonValue value;
    value.type_ = JsonType::kArray;
    value.array_ = std::make_shared<JsonArray>(std::move(items));
    return value;
}

JsonValue JsonValue::makeObject(JsonObject members) {
    JsonValue value;
    value.type_ = JsonType::kObject;
    value.object_ = std::make_shared<JsonObject>(std::move(members));
    return value;
}

JsonValue JsonValue::makeU64Text(std::uint64_t number, U64Format format) {
    return makeString(formatU64(number, format));
}

JsonValue JsonValue::makeOptionalU64Text(const OptionalU64& number, U64Format format) {
    if (!number.present) {
        return makeNull();  // F-08: Writing null results in null on read; it does not become 0.
    }
    return makeString(formatU64(number.value, format));
}

bool JsonValue::tryGetBool(bool& out) const noexcept {
    if (type_ != JsonType::kBool) {
        return false;
    }
    out = bool_;
    return true;
}

bool JsonValue::tryGetU64(std::uint64_t& out) const noexcept {
    if (type_ == JsonType::kUInt) {
        out = uint_;
        return true;
    }
    if (type_ == JsonType::kInt) {
        if (int_ < 0) {
            return false;
        }
        out = static_cast<std::uint64_t>(int_);
        return true;
    }
    if (type_ == JsonType::kString) {
        return parseU64(string_, out);
    }
    return false;
}

bool JsonValue::tryGetI64(std::int64_t& out) const noexcept {
    if (type_ == JsonType::kInt) {
        out = int_;
        return true;
    }
    if (type_ == JsonType::kUInt) {
        constexpr std::uint64_t kMax =
            static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        if (uint_ > kMax) {
            return false;
        }
        out = static_cast<std::int64_t>(uint_);
        return true;
    }
    if (type_ == JsonType::kString) {
        return parseI64(string_, out);
    }
    return false;
}

bool JsonValue::tryGetString(std::string& out) const {
    if (type_ != JsonType::kString) {
        return false;
    }
    out = string_;
    return true;
}

bool JsonValue::tryGetOptionalU64(OptionalU64& out) const noexcept {
    if (type_ == JsonType::kNull) {
        out = OptionalU64::unset();
        return true;
    }
    std::uint64_t number = 0U;
    if (!tryGetU64(number)) {
        return false;
    }
    out = OptionalU64::of(number);
    return true;
}

const JsonArray* JsonValue::asArray() const noexcept {
    return (type_ == JsonType::kArray && array_) ? array_.get() : nullptr;
}

const JsonObject* JsonValue::asObject() const noexcept {
    return (type_ == JsonType::kObject && object_) ? object_.get() : nullptr;
}

const JsonValue* JsonValue::find(std::string_view name) const noexcept {
    const JsonObject* members = asObject();
    if (members == nullptr) {
        return nullptr;
    }
    for (const auto& member : *members) {
        if (member.first == name) {
            return &member.second;
        }
    }
    return nullptr;
}

std::string writeJson(const JsonValue& value, unsigned indent) {
    std::string out;
    writeValue(out, value, indent, 0U);
    return out;
}

const char* jsonParseStatusName(JsonParseStatus status) noexcept {
    switch (status) {
    case JsonParseStatus::kOk:                    return "Ok";
    case JsonParseStatus::kEmpty:                 return "Empty";
    case JsonParseStatus::kSyntax:                return "Syntax";
    case JsonParseStatus::kDepthLimit:            return "DepthLimit";
    case JsonParseStatus::kSizeLimit:             return "SizeLimit";
    case JsonParseStatus::kNodeLimit:             return "NodeLimit";
    case JsonParseStatus::kFloatingPointRejected: return "FloatingPointRejected";
    case JsonParseStatus::kIntegerOverflow:       return "IntegerOverflow";
    case JsonParseStatus::kTrailingData:          return "TrailingData";
    case JsonParseStatus::kDuplicateKey:          return "DuplicateKey";
    }
    return "Syntax";
}

JsonParseResult parseJson(std::string_view text, const JsonLimits& limits) {
    // Q-12: Session/report import involves untrusted input. Enforce total byte limits
    // first before parsing; otherwise, an 11 MB file can deadlock the import thread.
    if (limits.maxTotalBytes != 0U && text.size() > limits.maxTotalBytes) {
        JsonParseResult result;
        result.status = JsonParseStatus::kSizeLimit;
        result.errorOffset = limits.maxTotalBytes;
        return result;
    }
    Parser parser(text, limits);
    return parser.run();
}

} // namespace ksword::evidence
