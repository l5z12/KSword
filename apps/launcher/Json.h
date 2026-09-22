#pragma once

#include <map>
#include <string>
#include <vector>

namespace launcher {

// JsonValue is the minimal JSON DOM used by Launcher to avoid introducing Qt or other runtime dependencies.
class JsonValue {
public:
    enum class Type { kNull, kBoolean, kNumber, kString, kArray, kObject };

    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;

    JsonValue();
    explicit JsonValue(bool value);
    explicit JsonValue(double value);
    explicit JsonValue(std::string value);
    explicit JsonValue(Array value);
    explicit JsonValue(Object value);

    Type type() const { return type_; }
    bool isObject() const { return type_ == Type::kObject; }
    bool isArray() const { return type_ == Type::kArray; }
    bool isString() const { return type_ == Type::kString; }
    bool isNumber() const { return type_ == Type::kNumber; }
    bool isBoolean() const { return type_ == Type::kBoolean; }
    const Object& object() const { return object_; }
    const Array& array() const { return array_; }
    const std::string& string() const { return string_; }
    double number() const { return number_; }
    bool boolean() const { return boolean_; }

    const JsonValue* get(const char* name) const;
    std::string stringOr(const char* name, const std::string& fallback) const;
    double numberOr(const char* name, double fallback) const;
    bool booleanOr(const char* name, bool fallback) const;

private:
    Type type_ = Type::kNull;
    bool boolean_ = false;
    double number_ = 0.0;
    std::string string_;
    Array array_;
    Object object_;
};

// parseJson parses UTF-8 JSON text into a DOM; returns false on failure and fills the error description.
bool parseJson(const std::string& text, JsonValue* value, std::string* error);

// jsonEscape converts a UTF-8 string into a string literal content embeddable in JSON.
std::string jsonEscape(const std::string& text);

}
