#include "KVariant.h"

#include "KString.h"

#include <algorithm>
#include <cctype>

namespace {

// toLowerAscii creates a lowercase copy for simple boolean text parsing.
std::string toLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    });
    return value;
}

} // namespace

KVariant::KVariant()
    : type_(kInvalid),
      boolValue_(false),
      intValue_(0),
      doubleValue_(0.0),
      stringValue_(),
      objectValue_(),
      arrayValue_() {
}

KVariant::KVariant(std::nullptr_t)
    : KVariant() {
}

KVariant::KVariant(bool value)
    : KVariant() {
    reset(kBool);
    boolValue_ = value;
}

KVariant::KVariant(int value)
    : KVariant(static_cast<long long>(value)) {
}

KVariant::KVariant(long long value)
    : KVariant() {
    reset(kInt64);
    intValue_ = value;
}

KVariant::KVariant(double value)
    : KVariant() {
    reset(kDouble);
    doubleValue_ = value;
}

KVariant::KVariant(const char* value)
    : KVariant() {
    if (value) {
        reset(kString);
        stringValue_ = value;
    }
}

KVariant::KVariant(const std::string& value)
    : KVariant() {
    reset(kString);
    stringValue_ = value;
}

KVariant::KVariant(const KJsonObject& value)
    : KVariant() {
    reset(kJsonObject);
    objectValue_.reset(new KJsonObject(value));
}

KVariant::KVariant(const KJsonArray& value)
    : KVariant() {
    reset(kJsonArray);
    arrayValue_.reset(new KJsonArray(value));
}

KVariant::~KVariant() {
}

KVariant::Type KVariant::type() const {
    return type_;
}

std::string KVariant::typeName() const {
    switch (type_) {
    case kInvalid:
        return "Invalid";
    case kBool:
        return "Bool";
    case kInt64:
        return "Int64";
    case kDouble:
        return "Double";
    case kString:
        return "String";
    case kJsonObject:
        return "JsonObject";
    case kJsonArray:
        return "JsonArray";
    }
    return "Unknown";
}

void KVariant::clear() {
    reset(kInvalid);
}

bool KVariant::isValid() const {
    return type_ != kInvalid;
}

bool KVariant::isNull() const {
    return type_ == kInvalid;
}

bool KVariant::isBool() const {
    return type_ == kBool;
}

bool KVariant::isInt() const {
    return type_ == kInt64;
}

bool KVariant::isDouble() const {
    return type_ == kDouble;
}

bool KVariant::isNumber() const {
    return type_ == kInt64 || type_ == kDouble;
}

bool KVariant::isString() const {
    return type_ == kString;
}

bool KVariant::isJsonObject() const {
    return type_ == kJsonObject;
}

bool KVariant::isJsonArray() const {
    return type_ == kJsonArray;
}

bool KVariant::toBool(bool defaultValue) const {
    if (type_ == kBool) {
        return boolValue_;
    }
    if (type_ == kInt64) {
        return intValue_ != 0;
    }
    if (type_ == kDouble) {
        return doubleValue_ != 0.0;
    }
    if (type_ == kString) {
        const std::string kText = toLowerAscii(KString(stringValue_).trim().stdString());
        if (kText == "true" || kText == "1" || kText == "yes" || kText == "on") {
            return true;
        }
        if (kText == "false" || kText == "0" || kText == "no" || kText == "off") {
            return false;
        }
    }
    return defaultValue;
}

long long KVariant::toInt(long long defaultValue) const {
    if (type_ == kInt64) {
        return intValue_;
    }
    if (type_ == kBool) {
        return boolValue_ ? 1 : 0;
    }
    if (type_ == kDouble) {
        return static_cast<long long>(doubleValue_);
    }
    if (type_ == kString) {
        bool ok = false;
        const long long kValue = KString(stringValue_).toInt64(&ok, 10, defaultValue);
        return ok ? kValue : defaultValue;
    }
    return defaultValue;
}

double KVariant::toDouble(double defaultValue) const {
    if (type_ == kDouble) {
        return doubleValue_;
    }
    if (type_ == kInt64) {
        return static_cast<double>(intValue_);
    }
    if (type_ == kBool) {
        return boolValue_ ? 1.0 : 0.0;
    }
    if (type_ == kString) {
        bool ok = false;
        const double kValue = KString(stringValue_).toDouble(&ok, defaultValue);
        return ok ? kValue : defaultValue;
    }
    return defaultValue;
}

std::string KVariant::toString(const std::string& defaultValue) const {
    if (type_ == kString) {
        return stringValue_;
    }
    if (type_ == kBool) {
        return boolValue_ ? "true" : "false";
    }
    if (type_ == kInt64) {
        return KString::fromNumber(intValue_).stdString();
    }
    if (type_ == kDouble) {
        return KString::fromNumber(doubleValue_).stdString();
    }
    if (type_ == kJsonObject && objectValue_) {
        return objectValue_->toJson(KJsonFormat::kCompact);
    }
    if (type_ == kJsonArray && arrayValue_) {
        return arrayValue_->toJson(KJsonFormat::kCompact);
    }
    return defaultValue;
}

KJsonObject KVariant::toJsonObject() const {
    if (type_ == kJsonObject && objectValue_) {
        return *objectValue_;
    }
    return KJsonObject();
}

KJsonArray KVariant::toJsonArray() const {
    if (type_ == kJsonArray && arrayValue_) {
        return *arrayValue_;
    }
    return KJsonArray();
}

KJsonValue KVariant::toJsonValue() const {
    switch (type_) {
    case kBool:
        return KJsonValue(boolValue_);
    case kInt64:
        return KJsonValue(intValue_);
    case kDouble:
        return KJsonValue(doubleValue_);
    case kString:
        return KJsonValue(stringValue_);
    case kJsonObject:
        return objectValue_ ? KJsonValue(*objectValue_) : KJsonValue(KJsonObject());
    case kJsonArray:
        return arrayValue_ ? KJsonValue(*arrayValue_) : KJsonValue(KJsonArray());
    case kInvalid:
    default:
        return KJsonValue();
    }
}

KVariant KVariant::fromJsonValue(const KJsonValue& value) {
    if (value.isBool()) {
        return KVariant(value.toBool());
    }
    if (value.isInt()) {
        return KVariant(value.toInt());
    }
    if (value.isDouble()) {
        return KVariant(value.toDouble());
    }
    if (value.isString()) {
        return KVariant(value.toString());
    }
    if (value.isObject()) {
        return KVariant(value.toObject());
    }
    if (value.isArray()) {
        return KVariant(value.toArray());
    }
    return KVariant();
}

void KVariant::reset(Type nextType) {
    type_ = nextType;
    boolValue_ = false;
    intValue_ = 0;
    doubleValue_ = 0.0;
    stringValue_.clear();
    objectValue_.reset();
    arrayValue_.reset();
}
