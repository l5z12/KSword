#include "SystemTimeInfo.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace ksword::features::sys_tools {
namespace {

constexpr wchar_t kW32TimeParametersKey[] = L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters";

std::wstring formatSystemTime(const SYSTEMTIME& time, const bool withMilliseconds) {
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear << L'-' << std::setw(2) << time.wMonth << L'-' << std::setw(2) << time.wDay
        << L' ' << std::setw(2) << time.wHour << L':' << std::setw(2) << time.wMinute
        << L':' << std::setw(2) << time.wSecond;
    if (withMilliseconds) {
        stream << L'.' << std::setw(3) << time.wMilliseconds;
    }
    return stream.str();
}

// formatBias renders a UTC offset the way a user reads it. Windows stores the
// bias as "minutes to add to local time to get UTC", which is the opposite sign
// of the UTC+08:00 notation everyone expects, so the sign is flipped here.
std::wstring formatBias(const LONG biasMinutes) {
    const LONG kOffset = -biasMinutes;
    const wchar_t kSign = kOffset < 0 ? L'-' : L'+';
    const LONG kMagnitude = kOffset < 0 ? -kOffset : kOffset;
    std::wostringstream stream;
    stream << L"UTC" << kSign << std::setfill(L'0') << std::setw(2) << (kMagnitude / 60)
        << L':' << std::setw(2) << (kMagnitude % 60)
        << L"（Bias=" << biasMinutes << L" 分钟）";
    return stream.str();
}

std::wstring formatUptime(const ULONGLONG milliseconds) {
    const ULONGLONG kTotalSeconds = milliseconds / 1000ULL;
    const ULONGLONG kDays = kTotalSeconds / 86400ULL;
    const ULONGLONG kHours = (kTotalSeconds % 86400ULL) / 3600ULL;
    const ULONGLONG kMinutes = (kTotalSeconds % 3600ULL) / 60ULL;
    const ULONGLONG kSeconds = kTotalSeconds % 60ULL;
    std::wostringstream stream;
    stream << kDays << L" 天 " << std::setfill(L'0') << std::setw(2) << kHours << L':'
        << std::setw(2) << kMinutes << L':' << std::setw(2) << kSeconds;
    return stream.str();
}

// estimateBootTime derives the boot moment from the tick counter. It is an
// estimate on purpose: GetTickCount64 excludes time spent in sleep on some
// configurations, so the value is labelled as derived rather than presented as
// an authoritative boot timestamp.
std::wstring estimateBootTime(const ULONGLONG uptimeMs) {
    FILETIME nowFileTime{};
    ::GetSystemTimeAsFileTime(&nowFileTime);
    ULARGE_INTEGER now{};
    now.LowPart = nowFileTime.dwLowDateTime;
    now.HighPart = nowFileTime.dwHighDateTime;
    const ULONGLONG kUptime100ns = uptimeMs * 10000ULL;
    if (now.QuadPart <= kUptime100ns) {
        return L"—";
    }
    ULARGE_INTEGER boot{};
    boot.QuadPart = now.QuadPart - kUptime100ns;
    FILETIME bootFileTime{};
    bootFileTime.dwLowDateTime = boot.LowPart;
    bootFileTime.dwHighDateTime = boot.HighPart;
    FILETIME localFileTime{};
    SYSTEMTIME localTime{};
    if (!::FileTimeToLocalFileTime(&bootFileTime, &localFileTime) ||
        !::FileTimeToSystemTime(&localFileTime, &localTime)) {
        return L"—";
    }
    return formatSystemTime(localTime, false);
}

std::wstring timeZoneIdText(const DWORD timeZoneId) {
    switch (timeZoneId) {
    case TIME_ZONE_ID_STANDARD:
        return L"标准时间";
    case TIME_ZONE_ID_DAYLIGHT:
        return L"夏令时";
    case TIME_ZONE_ID_UNKNOWN:
        return L"未定义夏令时规则";
    default:
        return L"查询失败";
    }
}

std::wstring formatBinaryPreview(const std::vector<BYTE>& data) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    const std::size_t kShown = (std::min)(data.size(), static_cast<std::size_t>(32));
    for (std::size_t index = 0; index < kShown; ++index) {
        if (index != 0) {
            stream << L' ';
        }
        stream << std::setw(2) << static_cast<unsigned>(data[index]);
    }
    if (kShown < data.size()) {
        stream << L" …（共 " << std::dec << data.size() << L" 字节）";
    }
    return stream.str();
}

std::wstring formatRegistryValue(const DWORD type, const std::vector<BYTE>& data) {
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        if (data.size() < sizeof(wchar_t)) {
            return {};
        }
        const auto* text = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t kMaxChars = data.size() / sizeof(wchar_t);
        return std::wstring(text, ::wcsnlen(text, kMaxChars));
    }
    case REG_MULTI_SZ: {
        std::wstring joined;
        const auto* cursor = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t kMaxChars = data.size() / sizeof(wchar_t);
        std::size_t offset = 0;
        while (offset < kMaxChars && cursor[offset] != L'\0') {
            const std::size_t kLength = ::wcsnlen(cursor + offset, kMaxChars - offset);
            if (!joined.empty()) {
                joined += L" | ";
            }
            joined.append(cursor + offset, kLength);
            offset += kLength + 1;
        }
        return joined;
    }
    case REG_DWORD: {
        if (data.size() < sizeof(DWORD)) {
            return {};
        }
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        std::wostringstream stream;
        stream << value << L" (0x" << std::uppercase << std::hex << value << L")";
        return stream.str();
    }
    case REG_QWORD: {
        if (data.size() < sizeof(ULONGLONG)) {
            return {};
        }
        ULONGLONG value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        std::wostringstream stream;
        stream << value << L" (0x" << std::uppercase << std::hex << value << L")";
        return stream.str();
    }
    default:
        return formatBinaryPreview(data);
    }
}

// readW32TimeParameters enumerates every value rather than reading a hardcoded
// list. The interesting names differ between a domain member, a workgroup
// machine and a Hyper-V guest, and a fixed list would quietly omit exactly the
// setting that explains a wrong clock.
SystemTimeInfoSection readW32TimeParameters() {
    SystemTimeInfoSection section{};
    section.title = L"NTP / W32Time 配置（HKLM\\" + std::wstring(kW32TimeParametersKey) + L"）";

    HKEY key = nullptr;
    const LSTATUS kStatus = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kW32TimeParametersKey, 0, KEY_READ, &key);
    if (kStatus != ERROR_SUCCESS) {
        section.properties.push_back({ L"读取状态",
            L"无法打开注册表键，错误码 " + std::to_wstring(kStatus) + L"。W32Time 可能未安装。" });
        return section;
    }

    wchar_t name[512] = {};
    std::vector<BYTE> data(4096);
    for (DWORD index = 0;; ++index) {
        DWORD nameLength = static_cast<DWORD>(std::size(name));
        DWORD type = 0;
        DWORD dataSize = static_cast<DWORD>(data.size());
        LSTATUS enumStatus = ::RegEnumValueW(key, index, name, &nameLength, nullptr, &type, data.data(), &dataSize);
        if (enumStatus == ERROR_MORE_DATA) {
            data.resize(dataSize);
            nameLength = static_cast<DWORD>(std::size(name));
            dataSize = static_cast<DWORD>(data.size());
            enumStatus = ::RegEnumValueW(key, index, name, &nameLength, nullptr, &type, data.data(), &dataSize);
        }
        if (enumStatus != ERROR_SUCCESS) {
            break;
        }
        std::vector<BYTE> value(data.begin(), data.begin() + dataSize);
        const std::wstring kValueName = nameLength > 0 ? std::wstring(name, nameLength) : std::wstring(L"(默认)");
        section.properties.push_back({ kValueName, formatRegistryValue(type, value) });
    }
    ::RegCloseKey(key);

    if (section.properties.empty()) {
        section.properties.push_back({ L"读取状态", L"该键下没有任何值。" });
    }
    return section;
}

} // namespace

SystemTimeInfoSnapshot collectSystemTimeInfo() {
    SystemTimeInfoSnapshot snapshot{};

    SYSTEMTIME localTime{};
    SYSTEMTIME utcTime{};
    ::GetLocalTime(&localTime);
    ::GetSystemTime(&utcTime);

    TIME_ZONE_INFORMATION zone{};
    const DWORD kZoneId = ::GetTimeZoneInformation(&zone);
    const LONG kEffectiveBias = zone.Bias +
        (kZoneId == TIME_ZONE_ID_DAYLIGHT ? zone.DaylightBias
            : kZoneId == TIME_ZONE_ID_STANDARD ? zone.StandardBias : 0);

    const ULONGLONG kUptimeMs = ::GetTickCount64();

    SystemTimeInfoSection clock{};
    clock.title = L"系统时间";
    clock.properties.push_back({ L"本地时间", formatSystemTime(localTime, true) });
    clock.properties.push_back({ L"UTC 时间", formatSystemTime(utcTime, true) });
    clock.properties.push_back({ L"当前有效偏移", formatBias(kEffectiveBias) });
    snapshot.sections.push_back(std::move(clock));

    SystemTimeInfoSection timeZone{};
    timeZone.title = L"时区";
    timeZone.properties.push_back({ L"当前状态", timeZoneIdText(kZoneId) });
    timeZone.properties.push_back({ L"标准时间名称", zone.StandardName });
    timeZone.properties.push_back({ L"夏令时名称", zone.DaylightName });
    timeZone.properties.push_back({ L"基准偏移", formatBias(zone.Bias) });
    timeZone.properties.push_back({ L"标准时间附加偏移", std::to_wstring(zone.StandardBias) + L" 分钟" });
    timeZone.properties.push_back({ L"夏令时附加偏移", std::to_wstring(zone.DaylightBias) + L" 分钟" });

    DYNAMIC_TIME_ZONE_INFORMATION dynamicZone{};
    if (::GetDynamicTimeZoneInformation(&dynamicZone) != TIME_ZONE_ID_INVALID) {
        timeZone.properties.push_back({ L"时区注册表键", dynamicZone.TimeZoneKeyName });
        timeZone.properties.push_back({ L"动态夏令时",
            dynamicZone.DynamicDaylightTimeDisabled ? L"已禁用" : L"启用" });
    }
    snapshot.sections.push_back(std::move(timeZone));

    SystemTimeInfoSection uptime{};
    uptime.title = L"运行时长";
    uptime.properties.push_back({ L"开机时长", formatUptime(kUptimeMs) });
    uptime.properties.push_back({ L"GetTickCount64", std::to_wstring(kUptimeMs) + L" ms" });
    uptime.properties.push_back({ L"推算开机时间", estimateBootTime(kUptimeMs) });
    snapshot.sections.push_back(std::move(uptime));

    snapshot.sections.push_back(readW32TimeParameters());
    snapshot.success = true;
    return snapshot;
}

std::wstring formatLiveClockLine() {
    SYSTEMTIME localTime{};
    SYSTEMTIME utcTime{};
    ::GetLocalTime(&localTime);
    ::GetSystemTime(&utcTime);
    return L"本地 " + formatSystemTime(localTime, false) +
        L"    UTC " + formatSystemTime(utcTime, false) +
        L"    已运行 " + formatUptime(::GetTickCount64());
}

std::wstring renderSystemTimeReport(const SystemTimeInfoSnapshot& snapshot) {
    if (!snapshot.success) {
        return snapshot.diagnosticText.empty() ? L"系统时间信息收集失败。" : snapshot.diagnosticText;
    }
    std::wstring text;
    for (const SystemTimeInfoSection& section : snapshot.sections) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        text += L"【" + section.title + L"】\r\n";
        for (const SystemTimeProperty& property : section.properties) {
            text += L"  " + property.name + L"：" + property.value + L"\r\n";
        }
    }
    if (!snapshot.diagnosticText.empty()) {
        text += L"\r\n" + snapshot.diagnosticText + L"\r\n";
    }
    return text;
}

} // namespace Ksword::Features::SysTools
