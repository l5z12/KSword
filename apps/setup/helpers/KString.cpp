#include "KString.h"

#include <cctype>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace {

// isAsciiSpace returns true for whitespace recognized by common text formats.
bool isAsciiSpace(char ch) {
    return std::isspace(static_cast<unsigned char>(ch)) != 0;
}

// SetOk writes parse status only when the caller provided an output pointer.
void setOk(bool* ok, bool value) {
    if (ok) {
        *ok = value;
    }
}

} // namespace

KString::KString()
    : value_() {
}

KString::KString(const char* value)
    : value_(value ? value : "") {
}

KString::KString(const std::string& value)
    : value_(value) {
}

std::string KString::stdString() const {
    return value_;
}

const char* KString::cStr() const {
    return value_.c_str();
}

std::size_t KString::size() const {
    return value_.size();
}

bool KString::isEmpty() const {
    return value_.empty();
}

KString KString::trim() const {
    std::size_t begin = 0;
    while (begin < value_.size() && isAsciiSpace(value_[begin])) {
        ++begin;
    }

    std::size_t end = value_.size();
    while (end > begin && isAsciiSpace(value_[end - 1])) {
        --end;
    }

    return KString(value_.substr(begin, end - begin));
}

std::vector<KString> KString::split(const KString& separator, bool keepEmptyParts) const {
    std::vector<KString> result;
    const std::string kSep = separator.stdString();
    if (kSep.empty()) {
        result.push_back(*this);
        return result;
    }

    std::size_t start = 0;
    while (start <= value_.size()) {
        const std::size_t kPos = value_.find(kSep, start);
        const std::size_t kEnd = (kPos == std::string::npos) ? value_.size() : kPos;
        if (keepEmptyParts || kEnd > start) {
            result.push_back(KString(value_.substr(start, kEnd - start)));
        }
        if (kPos == std::string::npos) {
            break;
        }
        start = kPos + kSep.size();
    }

    return result;
}

KString KString::join(const std::vector<KString>& parts, const KString& separator) {
    std::string result;
    const std::string kSep = separator.stdString();
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            result += kSep;
        }
        result += parts[i].stdString();
    }
    return KString(result);
}

KString KString::replace(const KString& before, const KString& after) const {
    const std::string kFrom = before.stdString();
    if (kFrom.empty()) {
        return *this;
    }

    const std::string kTo = after.stdString();
    std::string result;
    std::size_t start = 0;
    while (start < value_.size()) {
        const std::size_t kPos = value_.find(kFrom, start);
        if (kPos == std::string::npos) {
            result += value_.substr(start);
            break;
        }
        result += value_.substr(start, kPos - start);
        result += kTo;
        start = kPos + kFrom.size();
    }
    if (value_.empty()) {
        return KString();
    }
    return KString(result);
}

bool KString::startsWith(const KString& prefix) const {
    const std::string kPrefixBytes = prefix.stdString();
    if (kPrefixBytes.size() > value_.size()) {
        return false;
    }
    return value_.compare(0, kPrefixBytes.size(), kPrefixBytes) == 0;
}

bool KString::endsWith(const KString& suffix) const {
    const std::string kSuffixBytes = suffix.stdString();
    if (kSuffixBytes.size() > value_.size()) {
        return false;
    }
    return value_.compare(value_.size() - kSuffixBytes.size(), kSuffixBytes.size(), kSuffixBytes) == 0;
}

int KString::toInt(bool* ok, int base, int defaultValue) const {
    bool parsedOk = false;
    const long long kValue = toInt64(&parsedOk, base, defaultValue);
    if (!parsedOk || kValue < std::numeric_limits<int>::min() || kValue > std::numeric_limits<int>::max()) {
        setOk(ok, false);
        return defaultValue;
    }
    setOk(ok, true);
    return static_cast<int>(kValue);
}

long long KString::toInt64(bool* ok, int base, long long defaultValue) const {
    const std::string kText = trim().stdString();
    if (kText.empty()) {
        setOk(ok, false);
        return defaultValue;
    }

    try {
        std::size_t parsed = 0;
        const long long kValue = std::stoll(kText, &parsed, base);
        if (parsed != kText.size()) {
            setOk(ok, false);
            return defaultValue;
        }
        setOk(ok, true);
        return kValue;
    } catch (const std::exception&) {
        setOk(ok, false);
        return defaultValue;
    }
}

double KString::toDouble(bool* ok, double defaultValue) const {
    const std::string kText = trim().stdString();
    if (kText.empty()) {
        setOk(ok, false);
        return defaultValue;
    }

    double value = 0.0;
    std::istringstream stream(kText);
    stream.imbue(std::locale::classic());
    stream >> value;
    if (stream.fail() || !stream.eof()) {
        setOk(ok, false);
        return defaultValue;
    }

    setOk(ok, true);
    return value;
}

KString KString::fromNumber(int value) {
    return fromNumber(static_cast<long long>(value));
}

KString KString::fromNumber(long long value) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << value;
    return KString(stream.str());
}

KString KString::fromNumber(double value, int precision) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << std::setprecision(precision) << value;
    return KString(stream.str());
}

KString& KString::operator=(const std::string& value) {
    value_ = value;
    return *this;
}

KString& KString::operator+=(const KString& other) {
    value_ += other.value_;
    return *this;
}

KString KString::operator+(const KString& other) const {
    return KString(value_ + other.value_);
}

bool KString::operator==(const KString& other) const {
    return value_ == other.value_;
}

bool KString::operator!=(const KString& other) const {
    return value_ != other.value_;
}

bool KString::operator<(const KString& other) const {
    return value_ < other.value_;
}

KString::operator std::string() const {
    return value_;
}
