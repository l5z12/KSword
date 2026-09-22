#pragma once

// Lossless JSON encoding/decoding — F-08, reused by session persistence in T-09 / D-06 / Q-12.
//
// Key constraint:
//   * This reader/writer **has no floating-point type**. JSON numbers are parsed only as int64/uint64; numbers with a decimal
//     point or exponent are immediately treated as parse failures to avoid silent precision loss for values above 2^53.
//   * 64-bit addresses/IDs/counts are always written as formatted strings (see LosslessValue.h).
//   * null, 0, and empty string are three distinct values; they are not merged upon read-back.
//   * The parser enforces hard limits on depth, length, and member count (Q-12: untrusted input).

#include "LosslessValue.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ksword::evidence {

enum class JsonType {
    kNull,
    kBool,
    kUInt,
    kInt,
    kString,
    kArray,
    kObject,
};

class JsonValue;

using JsonArray = std::vector<JsonValue>;
using JsonObject = std::vector<std::pair<std::string, JsonValue>>;  // Preserve order for exportable verification.

class JsonValue final {
public:
    JsonValue() = default;

    static JsonValue makeNull();
    static JsonValue makeBool(bool value);
    static JsonValue makeUInt(std::uint64_t value);
    static JsonValue makeInt(std::int64_t value);
    static JsonValue makeString(std::string value);
    static JsonValue makeArray(JsonArray value);
    static JsonValue makeObject(JsonObject value);

    // Standard pattern for lossless address/count fields: store as string, read back using tryGetU64.
    static JsonValue makeU64Text(std::uint64_t value, U64Format format);
    static JsonValue makeOptionalU64Text(const OptionalU64& value, U64Format format);

    JsonType type() const noexcept { return type_; }
    bool isNull() const noexcept { return type_ == JsonType::kNull; }

    bool tryGetBool(bool& out) const noexcept;
    bool tryGetU64(std::uint64_t& out) const noexcept;      // Accepts UInt or a parseable String
    bool tryGetI64(std::int64_t& out) const noexcept;
    bool tryGetString(std::string& out) const;
    // null -> unset and returns true; invalid content returns false.
    bool tryGetOptionalU64(OptionalU64& out) const noexcept;

    const JsonArray* asArray() const noexcept;
    const JsonObject* asObject() const noexcept;

    // Search only on Object; return nullptr if not found (do not insert).
    const JsonValue* find(std::string_view name) const noexcept;

private:
    JsonType type_ = JsonType::kNull;
    bool bool_ = false;
    std::uint64_t uint_ = 0;
    std::int64_t int_ = 0;
    std::string string_;
    std::shared_ptr<JsonArray> array_;
    std::shared_ptr<JsonObject> object_;
};

// Serialization. indent=0 outputs compact single line.
std::string writeJson(const JsonValue& value, unsigned indent = 0);

struct JsonLimits final {
    std::size_t maxDepth = 64;
    std::size_t maxStringBytes = 1u << 20;      // 1 MiB
    std::size_t maxContainerItems = 1u << 20;   // Maximum limit for a single array/object member.
    // Q-12: Limiting nodes by count alone cannot control memory usage—each JsonValue has a fixed overhead of dozens of bytes, so a few MB of
    // input can expand to hundreds of MB of resident memory. Three limits must be applied together: input bytes, node count, and node bytes.
    std::size_t maxTotalNodes = 1u << 19;             // 524,288 nodes
    std::size_t maxTotalBytes = 32u * 1024u * 1024u;  // 32 MiB input limit; 0 means unlimited.
    // Budget for nodes * sizeof(JsonValue); 0 means unlimited. Callers needing more must explicitly raise this limit.
    std::size_t maxEstimatedNodeBytes = 64u * 1024u * 1024u;
};

enum class JsonParseStatus {
    kOk,
    kEmpty,
    kSyntax,
    kDepthLimit,
    kSizeLimit,
    kNodeLimit,
    kFloatingPointRejected,   // Explicitly reject floating point, rather than silently downgrading precision.
    kIntegerOverflow,
    kTrailingData,
    kDuplicateKey,
};

const char* jsonParseStatusName(JsonParseStatus status) noexcept;

struct JsonParseResult final {
    JsonParseStatus status = JsonParseStatus::kEmpty;
    JsonValue value;
    std::size_t errorOffset = 0;

    bool ok() const noexcept { return status == JsonParseStatus::kOk; }
};

JsonParseResult parseJson(std::string_view text, const JsonLimits& limits = JsonLimits{});

} // namespace ksword::evidence
