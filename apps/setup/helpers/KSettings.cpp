#include "KSettings.h"

#include <fstream>
#include <sstream>
#include <vector>

namespace {

// SplitKey converts slash-separated setting names into path segments. Empty
// segments are ignored so callers can pass either "a/b" or "/a/b/".
std::vector<std::string> splitKey(const std::string& key) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= key.size()) {
        const std::size_t kPos = key.find('/', start);
        const std::size_t kEnd = (kPos == std::string::npos) ? key.size() : kPos;
        if (kEnd > start) {
            parts.push_back(key.substr(start, kEnd - start));
        }
        if (kPos == std::string::npos) {
            break;
        }
        start = kPos + 1;
    }
    return parts;
}

// FindPath resolves a key path inside object. It returns false when any segment
// is missing or when an intermediate value is not a JSON object.
bool findPath(const KJsonObject& object, const std::vector<std::string>& parts, KJsonValue& output) {
    if (parts.empty()) {
        return false;
    }

    KJsonObject current = object;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (!current.contains(parts[i])) {
            return false;
        }
        const KJsonValue kValue = current.value(parts[i]);
        if (i + 1 == parts.size()) {
            output = kValue;
            return true;
        }
        if (!kValue.isObject()) {
            return false;
        }
        current = kValue.toObject();
    }
    return false;
}

// SetPath writes value into object by recursive copy/update. It creates missing
// intermediate objects and overwrites non-object intermediates with objects.
void setPath(KJsonObject& object, const std::vector<std::string>& parts, std::size_t index, const KJsonValue& value) {
    if (index >= parts.size()) {
        return;
    }

    if (index + 1 == parts.size()) {
        object.insert(parts[index], value);
        return;
    }

    KJsonObject child;
    const KJsonValue kExisting = object.value(parts[index]);
    if (kExisting.isObject()) {
        child = kExisting.toObject();
    }
    setPath(child, parts, index + 1, value);
    object.insert(parts[index], KJsonValue(child));
}

// markLoadError writes a synthetic parse error for file and root-contract errors.
void markLoadError(KJsonParseError& error, const std::string& message) {
    error.error = KJsonParseError::kIllegalValue;
    error.offset = 0;
    error.line = 1;
    error.column = 1;
    error.message = message;
}

} // namespace

KSettings::KSettings()
    : filePath_(), root_(), lastParseError_() {
}

KSettings::KSettings(const std::string& filePath)
    : filePath_(filePath), root_(), lastParseError_() {
}

void KSettings::setFileName(const std::string& filePath) {
    filePath_ = filePath;
}

std::string KSettings::fileName() const {
    return filePath_;
}

bool KSettings::load() {
    if (filePath_.empty()) {
        markLoadError(lastParseError_, "Settings file path is empty");
        return false;
    }
    return load(filePath_);
}

bool KSettings::load(const std::string& filePath) {
    filePath_ = filePath;
    lastParseError_.clear();

    std::ifstream input(filePath.c_str(), std::ios::in | std::ios::binary);
    if (!input) {
        markLoadError(lastParseError_, "Unable to open settings file for reading");
        return false;
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string kBytes = buffer.str();

    KJsonParseError parseError;
    const KJsonDocument kDocument = KJsonDocument::fromJson(kBytes, &parseError);
    if (parseError.hasError()) {
        lastParseError_ = parseError;
        return false;
    }
    if (!kDocument.isObject()) {
        markLoadError(lastParseError_, "Settings root must be a JSON object");
        return false;
    }

    root_ = kDocument.object();
    lastParseError_.clear();
    return true;
}

bool KSettings::save() const {
    if (filePath_.empty()) {
        return false;
    }
    return save(filePath_);
}

bool KSettings::save(const std::string& filePath) const {
    std::ofstream output(filePath.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    const KJsonDocument kDocument(root_);
    output << kDocument.toJson(KJsonFormat::kPretty);
    output << '\n';
    return output.good();
}

KVariant KSettings::value(const std::string& key, const KVariant& defaultValue) const {
    KJsonValue jsonValue;
    if (!findPath(root_, splitKey(key), jsonValue)) {
        return defaultValue;
    }
    return KVariant::fromJsonValue(jsonValue);
}

void KSettings::setValue(const std::string& key, const KVariant& value) {
    const std::vector<std::string> kParts = splitKey(key);
    if (kParts.empty()) {
        return;
    }
    setPath(root_, kParts, 0, value.toJsonValue());
}

bool KSettings::contains(const std::string& key) const {
    KJsonValue ignored;
    return findPath(root_, splitKey(key), ignored);
}

void KSettings::clear() {
    root_.clear();
    lastParseError_.clear();
}

KJsonObject KSettings::object() const {
    return root_;
}

void KSettings::setObject(const KJsonObject& object) {
    root_ = object;
}

KJsonParseError KSettings::lastParseError() const {
    return lastParseError_;
}

std::string KSettings::lastErrorString() const {
    return lastParseError_.errorString();
}
