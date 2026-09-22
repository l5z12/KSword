#include "HardwareStatsModel.h"

#include <cmath>
#include <cstdio>

namespace ksword::features::hardware_stats {
namespace {

constexpr double kKibi = 1024.0;

// IsUsable rejects the values PDH produces for a counter that has not settled.
// A NaN or infinity rendered through swprintf_s becomes "nan"/"inf" in the
// table, which reads like a real measurement instead of a missing one.
bool isUsable(double value) {
    return std::isfinite(value);
}

} // namespace

std::wstring formatByteSize(const double bytes) {
    if (!isUsable(bytes)) {
        return L"—";
    }
    const double kMagnitude = bytes < 0.0 ? -bytes : bytes;
    const wchar_t* unit = L"B";
    double scaled = bytes;
    if (kMagnitude >= kKibi * kKibi * kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi * kKibi * kKibi);
        unit = L"TiB";
    } else if (kMagnitude >= kKibi * kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi * kKibi);
        unit = L"GiB";
    } else if (kMagnitude >= kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi);
        unit = L"MiB";
    } else if (kMagnitude >= kKibi) {
        scaled = bytes / kKibi;
        unit = L"KiB";
    } else {
        wchar_t whole[64] = {};
        swprintf_s(whole, L"%.0f B", bytes);
        return std::wstring(whole);
    }

    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f %s", scaled, unit);
    return std::wstring(buffer);
}

std::wstring formatByteRate(const double bytesPerSecond) {
    if (!isUsable(bytesPerSecond)) {
        return L"—";
    }
    return formatByteSize(bytesPerSecond) + L"/s";
}

std::wstring formatPercent(const double value) {
    if (!isUsable(value)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.1f %%", value);
    return std::wstring(buffer);
}

std::wstring formatRate(const double perSecond) {
    if (!isUsable(perSecond)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.1f /s", perSecond);
    return std::wstring(buffer);
}

std::wstring formatCount(const double value) {
    if (!isUsable(value)) {
        return L"—";
    }

    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.0f", value);
    std::wstring digits(buffer);
    const bool kNegative = !digits.empty() && digits.front() == L'-';
    if (kNegative) {
        digits.erase(digits.begin());
    }

    std::wstring grouped;
    grouped.reserve(digits.size() + digits.size() / 3 + 1);
    // The first group is whatever is left over above a multiple of three, and a
    // separator is only due once that group has been emitted. The index >= leading
    // guard is what keeps the unsigned subtraction from wrapping on short numbers,
    // which would otherwise put a separator inside a two-digit value.
    const std::size_t kLeading = digits.size() % 3 == 0 ? 3 : digits.size() % 3;
    for (std::size_t index = 0; index < digits.size(); ++index) {
        if (index >= kLeading && (index - kLeading) % 3 == 0) {
            grouped += L',';
        }
        grouped += digits[index];
    }
    return kNegative ? L"-" + grouped : grouped;
}

std::wstring formatDecimal(const double value) {
    if (!isUsable(value)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f", value);
    return std::wstring(buffer);
}

std::wstring formatLatency(const double seconds) {
    if (!isUsable(seconds)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f ms", seconds * 1000.0);
    return std::wstring(buffer);
}

std::wstring formatUpTime(const double seconds) {
    if (!isUsable(seconds) || seconds < 0.0) {
        return L"—";
    }
    const unsigned long long kTotal = static_cast<unsigned long long>(seconds);
    const unsigned long long kDays = kTotal / 86400ULL;
    const unsigned long long kHours = (kTotal % 86400ULL) / 3600ULL;
    const unsigned long long kMinutes = (kTotal % 3600ULL) / 60ULL;
    const unsigned long long kRemainder = kTotal % 60ULL;

    wchar_t buffer[96] = {};
    if (kDays > 0) {
        swprintf_s(buffer, L"%llu 天 %llu 小时 %llu 分", kDays, kHours, kMinutes);
    } else if (kHours > 0) {
        swprintf_s(buffer, L"%llu 小时 %llu 分 %llu 秒", kHours, kMinutes, kRemainder);
    } else {
        swprintf_s(buffer, L"%llu 分 %llu 秒", kMinutes, kRemainder);
    }
    return std::wstring(buffer);
}

std::wstring usbNodeKindText(const UsbNodeKind kind) {
    switch (kind) {
    case UsbNodeKind::kHostController:
        return L"主控制器";
    case UsbNodeKind::kHub:
        return L"集线器";
    case UsbNodeKind::kDevice:
    default:
        return L"设备";
    }
}

std::wstring indentedName(const std::wstring& name, const int depth) {
    // The indent is capped because a malformed parent chain would otherwise push
    // the name off the right edge of the column and hide it entirely.
    const int kLevels = depth < 0 ? 0 : (depth > 16 ? 16 : depth);
    if (kLevels == 0) {
        return name;
    }
    std::wstring prefix;
    prefix.reserve(static_cast<std::size_t>(kLevels) * 4);
    for (int level = 0; level < kLevels - 1; ++level) {
        prefix += L"    ";
    }
    prefix += L"└─ ";
    return prefix + name;
}

} // namespace Ksword::Features::hardware_stats
