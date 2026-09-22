#include "EntityRef.h"

#include <algorithm>
#include <cwctype>
#include <limits>

namespace ksword::core {
namespace {

std::wstring trim(std::wstring value) {
    while (!value.empty() && std::iswspace(value.back())) {
        value.pop_back();
    }
    std::size_t first = 0;
    while (first < value.size() && std::iswspace(value[first])) {
        ++first;
    }
    if (first != 0) {
        value.erase(0, first);
    }
    return value;
}

std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool parseUnsigned(const std::wstring& text, std::uint64_t& value) {
    const std::wstring kTrimmed = trim(text);
    if (kTrimmed.empty()) {
        return false;
    }
    int base = 10;
    std::size_t first = 0;
    if (kTrimmed.size() > 2U && kTrimmed[0] == L'0' && (kTrimmed[1] == L'x' || kTrimmed[1] == L'X')) {
        base = 16;
        first = 2;
    }
    if (first >= kTrimmed.size()) {
        return false;
    }
    std::uint64_t parsed = 0;
    for (std::size_t index = first; index < kTrimmed.size(); ++index) {
        const wchar_t kCh = kTrimmed[index];
        unsigned digit = 0;
        if (kCh >= L'0' && kCh <= L'9') {
            digit = static_cast<unsigned>(kCh - L'0');
        } else if (base == 16 && kCh >= L'a' && kCh <= L'f') {
            digit = static_cast<unsigned>(kCh - L'a' + 10);
        } else if (base == 16 && kCh >= L'A' && kCh <= L'F') {
            digit = static_cast<unsigned>(kCh - L'A' + 10);
        } else {
            return false;
        }
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / static_cast<unsigned>(base)) {
            return false;
        }
        parsed = parsed * static_cast<unsigned>(base) + digit;
    }
    value = parsed;
    return true;
}

CommandInputResult numericRequest(
    const std::wstring& argument,
    const EntityKind kind,
    const NavigationTarget target,
    const wchar_t* label) {
    CommandInputResult result{};
    std::uint64_t id = 0;
    if (!parseUnsigned(argument, id) || id == 0) {
        result.error = std::wstring(label) + L" 必须是非零十进制或 0x 十六进制数字。";
        return result;
    }
    if (kind != EntityKind::kWindow && id > (std::numeric_limits<std::uint32_t>::max)()) {
        result.error = std::wstring(label) + L" 超出 Windows 32 位标识符范围。";
        return result;
    }
    result.kind = CommandInputKind::kNavigation;
    result.navigation.target = target;
    result.navigation.entity.kind = kind;
    result.navigation.entity.id = id;
    return result;
}

const wchar_t* moduleTitleForBareVerb(const std::wstring& verb) {
    if (verb == L"process" || verb == L"进程") { return L"进程"; }
    if (verb == L"memory" || verb == L"内存") { return L"内存"; }
    if (verb == L"window" || verb == L"窗口") { return L"窗口"; }
    if (verb == L"network" || verb == L"网络") { return L"网络"; }
    if (verb == L"handle" || verb == L"handles" || verb == L"句柄") { return L"句柄"; }
    if (verb == L"monitor" || verb == L"监控") { return L"监控"; }
    if (verb == L"file" || verb == L"文件") { return L"文件"; }
    if (verb == L"reg" || verb == L"registry" || verb == L"注册表") { return L"注册表"; }
    if (verb == L"driver" || verb == L"驱动") { return L"驱动"; }
    if (verb == L"kernel" || verb == L"内核") { return L"内核"; }
    if (verb == L"hardware" || verb == L"硬件") { return L"硬件"; }
    if (verb == L"startup" || verb == L"启动项") { return L"启动项"; }
    if (verb == L"service" || verb == L"services" || verb == L"服务") { return L"服务"; }
    if (verb == L"privilege" || verb == L"权限") { return L"权限"; }
    if (verb == L"systools" || verb == L"系统工具") { return L"系统工具"; }
    if (verb == L"misc" || verb == L"杂项安全") { return L"杂项安全"; }
    return nullptr;
}

} // namespace

CommandInputResult parseCommandInput(const std::wstring& input) {
    const std::wstring kTrimmed = trim(input);
    CommandInputResult result{};
    if (kTrimmed.empty()) {
        result.error = L"请输入模块名或导航命令。";
        return result;
    }
    if (kTrimmed.front() == L'!') {
        result.shellCommand = trim(kTrimmed.substr(1));
        if (result.shellCommand.empty()) {
            result.error = L"! 后需要提供要执行的命令。";
            return result;
        }
        result.kind = CommandInputKind::kShell;
        return result;
    }

    const std::size_t kSeparator = kTrimmed.find_first_of(L" \t");
    const std::wstring kVerb = lower(kTrimmed.substr(0, kSeparator));
    const std::wstring kArgument = kSeparator == std::wstring::npos ? std::wstring{} : trim(kTrimmed.substr(kSeparator + 1));

    if (kArgument.empty() && moduleTitleForBareVerb(kVerb) != nullptr) {
        result.kind = CommandInputKind::kNavigation;
        result.navigation.entity.kind = EntityKind::kModule;
        result.navigation.entity.text = moduleTitleForBareVerb(kVerb);
        return result;
    }

    if (kVerb == L"pid" || kVerb == L"process" || kVerb == L"进程") {
        return numericRequest(kArgument, EntityKind::kProcess, NavigationTarget::kProcessDetails, L"PID");
    }
    if (kVerb == L"tid" || kVerb == L"thread" || kVerb == L"线程") {
        return numericRequest(kArgument, EntityKind::kThread, NavigationTarget::kProcessDetails, L"TID");
    }
    if (kVerb == L"mem" || kVerb == L"memory" || kVerb == L"内存") {
        return numericRequest(kArgument, EntityKind::kProcess, NavigationTarget::kMemoryOperations, L"PID");
    }
    if (kVerb == L"hwnd" || kVerb == L"window" || kVerb == L"窗口") {
        return numericRequest(kArgument, EntityKind::kWindow, NavigationTarget::kWindowManager, L"HWND");
    }
    if (kVerb == L"net" || kVerb == L"network" || kVerb == L"网络") {
        return numericRequest(kArgument, EntityKind::kProcess, NavigationTarget::kNetworkConnections, L"PID");
    }
    if (kVerb == L"handle" || kVerb == L"handles" || kVerb == L"句柄") {
        return numericRequest(kArgument, EntityKind::kProcess, NavigationTarget::kHandleTable, L"PID");
    }
    if (kVerb == L"etw" || kVerb == L"monitor" || kVerb == L"监控") {
        return numericRequest(kArgument, EntityKind::kProcess, NavigationTarget::kEtwMonitor, L"PID");
    }
    if (kVerb == L"file" || kVerb == L"文件") {
        if (kArgument.empty()) {
            result.error = L"file 后需要提供路径。";
            return result;
        }
        result.kind = CommandInputKind::kNavigation;
        result.navigation.target = NavigationTarget::kFileBrowser;
        result.navigation.entity.kind = EntityKind::kFile;
        result.navigation.entity.text = kArgument;
        return result;
    }
    if (kVerb == L"reg" || kVerb == L"registry" || kVerb == L"注册表") {
        if (kArgument.empty()) {
            result.error = L"reg 后需要提供注册表路径。";
            return result;
        }
        result.kind = CommandInputKind::kNavigation;
        result.navigation.target = NavigationTarget::kRegistryBrowser;
        result.navigation.entity.kind = EntityKind::kRegistryKey;
        result.navigation.entity.text = kArgument;
        return result;
    }
    if (kVerb == L"module" || kVerb == L"模块") {
        if (kArgument.empty()) {
            result.error = L"module 后需要提供模块名称。";
            return result;
        }
        result.kind = CommandInputKind::kNavigation;
        result.navigation.entity.kind = EntityKind::kModule;
        result.navigation.entity.text = kArgument;
        return result;
    }

    result.kind = CommandInputKind::kNavigation;
    result.navigation.entity.kind = EntityKind::kModule;
    result.navigation.entity.text = kTrimmed;
    return result;
}

} // namespace Ksword::Core
