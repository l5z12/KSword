#include "DriverModel.h"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>

namespace ksword::features::driver {
namespace {

// toLowerWstring converts text to lowercase for case-insensitive filters. Input
// is arbitrary Unicode text; processing applies towlower to each character;
// output is a best-effort lowercase copy for comparisons.
std::wstring toLowerWstring(const std::wstring& text) {
    std::wstring lowered;
    lowered.reserve(text.size());
    for (wchar_t ch : text) {
        lowered.push_back(static_cast<wchar_t>(std::towlower(ch)));
    }
    return lowered;
}

// joinUniqueText collects unique strings into a sorted vector. Input is a
// sequence of candidate labels; processing trims, deduplicates and sorts;
// output is a stable filter list without empty entries.
std::vector<std::wstring> joinUniqueText(std::vector<std::wstring> values) {
    values.erase(std::remove_if(values.begin(), values.end(), [](const std::wstring& value) {
        return value.empty();
    }), values.end());

    std::sort(values.begin(), values.end(), [](const std::wstring& left, const std::wstring& right) {
        return toLowerWstring(left) < toLowerWstring(right);
    });
    values.erase(std::unique(values.begin(), values.end(), [](const std::wstring& left, const std::wstring& right) {
        return toLowerWstring(left) == toLowerWstring(right);
    }), values.end());
    return values;
}

} // namespace

void DriverModel::setOverviewRows(std::vector<DriverOverviewRow> rows) {
    overviewRows_ = std::move(rows);
}

void DriverModel::setObjectRows(std::vector<DriverObjectRow> rows) {
    objectRows_ = std::move(rows);
}

const std::vector<DriverOverviewRow>& DriverModel::overviewRows() const {
    return overviewRows_;
}

const std::vector<DriverObjectRow>& DriverModel::objectRows() const {
    return objectRows_;
}

std::vector<DriverOverviewRow> DriverModel::filterOverviewRows(const std::wstring& keywordText) const {
    const std::wstring kKeyword = trimCopy(keywordText);
    if (kKeyword.empty()) {
        return overviewRows_;
    }

    std::vector<DriverOverviewRow> filtered;
    for (const DriverOverviewRow& row : overviewRows_) {
        if (containsIgnoreCase(row.driverName, kKeyword)
            || containsIgnoreCase(row.baseAddressText, kKeyword)
            || containsIgnoreCase(row.memoryRangeText, kKeyword)
            || containsIgnoreCase(row.sizeText, kKeyword)
            || containsIgnoreCase(row.pathText, kKeyword)
            || containsIgnoreCase(row.signatureText, kKeyword)
            || containsIgnoreCase(row.statusText, kKeyword)
            || containsIgnoreCase(row.anomalyText, kKeyword)
            || containsIgnoreCase(row.capabilityHint, kKeyword)) {
            filtered.push_back(row);
        }
    }
    return filtered;
}

std::vector<DriverObjectRow> DriverModel::filterObjectRows(
    const std::wstring& directoryFilterText,
    const std::wstring& typeFilterText,
    const std::wstring& keywordText) const {
    const std::wstring kDirectoryFilter = trimCopy(directoryFilterText);
    const std::wstring kTypeFilter = trimCopy(typeFilterText);
    const std::wstring kKeyword = trimCopy(keywordText);

    std::vector<DriverObjectRow> filtered;
    for (const DriverObjectRow& row : objectRows_) {
        if (!kDirectoryFilter.empty() && !containsIgnoreCase(row.directoryPathText, kDirectoryFilter)) {
            continue;
        }
        if (!kTypeFilter.empty() && !containsIgnoreCase(row.objectTypeText, kTypeFilter)) {
            continue;
        }
        if (!kKeyword.empty()
            && !containsIgnoreCase(row.directoryPathText, kKeyword)
            && !containsIgnoreCase(row.objectNameText, kKeyword)
            && !containsIgnoreCase(row.objectTypeText, kKeyword)
            && !containsIgnoreCase(row.referenceCountText, kKeyword)
            && !containsIgnoreCase(row.handleCountText, kKeyword)
            && !containsIgnoreCase(row.fullPathText, kKeyword)
            && !containsIgnoreCase(row.targetPathText, kKeyword)
            && !containsIgnoreCase(row.statusText, kKeyword)
            && !containsIgnoreCase(row.capabilityHint, kKeyword)) {
            continue;
        }
        filtered.push_back(row);
    }
    return filtered;
}

std::wstring DriverModel::overviewSummaryText(const std::wstring& keywordText) const {
    const std::vector<DriverOverviewRow> kFiltered = filterOverviewRows(keywordText);
    std::wstring text = L"状态：驱动概览 ";
    text += std::to_wstring(kFiltered.size());
    text += L" 项";
    if (!trimCopy(keywordText).empty()) {
        text += L"，关键字筛选中";
    }
    return text;
}

std::wstring DriverModel::objectSummaryText(
    const std::wstring& directoryFilterText,
    const std::wstring& typeFilterText,
    const std::wstring& keywordText) const {
    const std::vector<DriverObjectRow> kFiltered = filterObjectRows(directoryFilterText, typeFilterText, keywordText);
    std::wstring text = L"状态：对象信息 ";
    text += std::to_wstring(kFiltered.size());
    text += L" 项";
    if (!trimCopy(directoryFilterText).empty() || !trimCopy(typeFilterText).empty() || !trimCopy(keywordText).empty()) {
        text += L"，已启用筛选";
    }
    return text;
}

std::vector<std::wstring> DriverModel::overviewDriverNames() const {
    std::vector<std::wstring> values;
    values.reserve(overviewRows_.size());
    for (const DriverOverviewRow& row : overviewRows_) {
        values.push_back(trimCopy(row.driverName));
    }
    return joinUniqueText(std::move(values));
}

std::vector<std::wstring> DriverModel::objectDirectories() const {
    std::vector<std::wstring> values;
    values.reserve(objectRows_.size());
    for (const DriverObjectRow& row : objectRows_) {
        values.push_back(trimCopy(row.directoryPathText));
    }
    return joinUniqueText(std::move(values));
}

std::vector<std::wstring> DriverModel::objectTypes() const {
    std::vector<std::wstring> values;
    values.reserve(objectRows_.size());
    for (const DriverObjectRow& row : objectRows_) {
        values.push_back(trimCopy(row.objectTypeText));
    }
    return joinUniqueText(std::move(values));
}

std::wstring DriverModel::sanitizeTsvCell(const std::wstring& text) {
    std::wstring sanitized = text;
    for (wchar_t& ch : sanitized) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return sanitized;
}

bool DriverModel::containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) {
        return true;
    }
    return toLowerWstring(haystack).find(toLowerWstring(needle)) != std::wstring::npos;
}

std::wstring DriverModel::trimCopy(const std::wstring& text) {
    const auto kFirst = std::find_if_not(text.begin(), text.end(), [](wchar_t ch) {
        return std::iswspace(ch) != 0;
    });
    const auto kLast = std::find_if_not(text.rbegin(), text.rend(), [](wchar_t ch) {
        return std::iswspace(ch) != 0;
    }).base();
    if (kFirst >= kLast) {
        return {};
    }
    return std::wstring(kFirst, kLast);
}

std::wstring DriverModel::toLowerCopy(const std::wstring& text) {
    return toLowerWstring(text);
}

std::wstring formatHexAddress(const std::uint64_t value, const std::size_t width) {
    std::wostringstream out;
    out << L"0x" << std::uppercase << std::hex << std::setw(static_cast<int>(width)) << std::setfill(L'0') << value;
    return out.str();
}

std::wstring formatByteSize(const std::uint64_t bytes) {
    constexpr std::uint64_t kKiB = 1024ULL;
    constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
    constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;

    std::wostringstream out;
    out << std::fixed << std::setprecision(1);
    if (bytes >= kGiB) {
        out << (static_cast<long double>(bytes) / kGiB) << L" GiB";
    } else if (bytes >= kMiB) {
        out << (static_cast<long double>(bytes) / kMiB) << L" MiB";
    } else if (bytes >= kKiB) {
        out << (static_cast<long double>(bytes) / kKiB) << L" KiB";
    } else {
        out.unsetf(std::ios::floatfield);
        out << bytes << L" B";
    }
    return out.str();
}

} // namespace Ksword::Features::Driver
