#include "StartupActions.h"

#include "../../core/Common.h"

#include <algorithm>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <objbase.h>
#include <oleauto.h>
#include <sstream>
#include <shlobj.h>
#include <shellapi.h>
#include <taskschd.h>
#include <utility>
#include <vector>
#include <winsvc.h>

namespace ksword::features::startup {
namespace {
constexpr wchar_t kServiceDisabledStore[] = L"Software\\KswordARKLight\\DisabledStartup\\Services";
constexpr wchar_t kDisabledStartupFolderBase[] = L"KswordARKLight\\DisabledStartup\\StartupFolder";

// isReadOnlyServiceObservation identifies service records that Startup may show
// for investigation but must never mutate or open through a management surface.
// Input is a startup kind; output is true only for the two read-only sources.
bool isReadOnlyServiceObservation(StartupEntryKind kind) {
    return kind == StartupEntryKind::kDriverService || kind == StartupEntryKind::kRegistryOnlyService;
}

// rejectReadOnlyServiceAction preserves the read-only boundary for SCM driver
// observations and registry/SCM source mismatches. Input is the selected entry;
// output never opens SCM with write access or launches an external management
// surface.
StartupActionResult rejectReadOnlyServiceAction(const StartupEntry& entry) {
    if (entry.kind == StartupEntryKind::kRegistryOnlyService) {
        return { false, L"Registry-observed service entries are read-only in Lite; enable, disable, delete, and open are unavailable." };
    }
    return { false, L"Driver startup entries are read-only in Lite; enable, disable, delete, and open are unavailable." };
}

// RegKey owns an HKEY for StartupActions mutations. Inputs are handles returned
// by registry APIs; processing closes the key at scope exit; get returns the raw
// handle without transferring ownership.
class RegKey final {
public:
    RegKey() : key_(nullptr) {}
    explicit RegKey(HKEY key) : key_(key) {}
    ~RegKey() { reset(); }

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;

    void reset(HKEY key = nullptr) {
        if (key_) {
            ::RegCloseKey(key_);
        }
        key_ = key;
    }

    HKEY get() const { return key_; }
    bool valid() const { return key_ != nullptr; }

private:
    HKEY key_;
};

// ServiceHandle owns an SC_HANDLE. Inputs are SCM/service handles; processing
// closes them at scope exit; get returns the raw handle for SCM calls.
class ServiceHandle final {
public:
    ServiceHandle() : handle_(nullptr) {}
    explicit ServiceHandle(SC_HANDLE handle) : handle_(handle) {}
    ~ServiceHandle() { reset(); }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    void reset(SC_HANDLE handle = nullptr) {
        if (handle_) {
            ::CloseServiceHandle(handle_);
        }
        handle_ = handle;
    }

    SC_HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != nullptr; }

private:
    SC_HANDLE handle_;
};

// ComPtr owns one COM interface pointer. Inputs are raw COM interface pointers
// returned by CoCreateInstance or QueryInterface-style APIs; processing releases
// the pointer at scope exit; get/put expose the pointer for Windows APIs without
// transferring ownership.
template <typename T>
class ComPtr final {
public:
    ComPtr() : pointer_(nullptr) {}
    explicit ComPtr(T* pointer) : pointer_(pointer) {}
    ~ComPtr() { reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : pointer_(other.pointer_) {
        other.pointer_ = nullptr;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset();
            pointer_ = other.pointer_;
            other.pointer_ = nullptr;
        }
        return *this;
    }

    void reset(T* pointer = nullptr) {
        if (pointer_) {
            pointer_->Release();
        }
        pointer_ = pointer;
    }

    T* get() const { return pointer_; }
    T** put() {
        reset();
        return &pointer_;
    }
    T* operator->() const { return pointer_; }
    explicit operator bool() const { return pointer_ != nullptr; }

private:
    T* pointer_;
};

// BStr owns a COM BSTR value. Input is UTF-16 task text; processing allocates
// with SysAllocStringLen and frees with SysFreeString; get returns a borrowed
// BSTR for Task Scheduler methods.
class BStr final {
public:
    explicit BStr(const std::wstring& text)
        : value_(::SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {}
    ~BStr() {
        if (value_) {
            ::SysFreeString(value_);
        }
    }

    BStr(const BStr&) = delete;
    BStr& operator=(const BStr&) = delete;

    BSTR get() const { return value_; }
    bool valid() const { return value_ != nullptr; }

private:
    BSTR value_;
};

// ComApartment initializes COM for the current action callback. There is no
// input; processing accepts both MTA and already-initialized STA threads; ok
// reports whether COM calls can proceed and the destructor balances only the
// successful initialization owned by this object.
class ComApartment final {
public:
    ComApartment()
        : hr_(::CoInitializeEx(nullptr, COINIT_MULTITHREADED)),
          uninitialize_(hr_ == S_OK || hr_ == S_FALSE) {}

    ~ComApartment() {
        if (uninitialize_) {
            ::CoUninitialize();
        }
    }

    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

    ComApartment(ComApartment&& other) noexcept
        : hr_(other.hr_),
          uninitialize_(other.uninitialize_) {
        other.uninitialize_ = false;
    }

    ComApartment& operator=(ComApartment&& other) noexcept {
        if (this != &other) {
            if (uninitialize_) {
                ::CoUninitialize();
            }
            hr_ = other.hr_;
            uninitialize_ = other.uninitialize_;
            other.uninitialize_ = false;
        }
        return *this;
    }

    bool ok() const { return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE; }
    HRESULT result() const { return hr_; }

private:
    HRESULT hr_;
    bool uninitialize_;
};

// TaskPathParts is the normalized split form of a scheduled task path. Inputs
// are produced from StartupEntry::taskPath; consumers pass folderPath and taskName
// to ITaskService/ITaskFolder.
struct TaskPathParts {
    std::wstring fullPath;
    std::wstring folderPath;
    std::wstring taskName;
};

// ScheduledTaskConnection keeps Task Scheduler COM objects alive for one action.
// Inputs are assigned by openScheduledTask; processing in callers uses folder
// for deletion and task for enable/disable; success is false when any COM stage
// failed and message contains a displayable diagnostic.
struct ScheduledTaskConnection {
    bool success = false;
    std::wstring message;
    TaskPathParts parts;
    ComApartment apartment;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> folder;
    ComPtr<IRegisteredTask> task;
};

// hResultText formats HRESULT values for status messages. Input is an HRESULT;
// output contains the hexadecimal value and a system message when available.
std::wstring hResultText(HRESULT hr) {
    wchar_t message[512]{};
    const DWORD kChars = ::FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(hr),
        0,
        message,
        static_cast<DWORD>(std::size(message)),
        nullptr);
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr);
    if (kChars > 0) {
        std::wstring text(message, message + kChars);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'\t')) {
            text.pop_back();
        }
        if (!text.empty()) {
            stream << L" (" << text << L")";
        }
    }
    return stream.str();
}

// ensureComSecurity initializes process COM security once when possible. There
// is no input; processing tolerates RPC_E_TOO_LATE because another component may
// already have initialized security; no value is returned.
void ensureComSecurity() {
    static bool attempted = false;
    if (attempted) {
        return;
    }
    attempted = true;
    const HRESULT kHr = ::CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr);
    (void)kHr;
}

// normalizeTaskPath prepares a task path for Task Scheduler COM. Input is a
// StartupEntry from the scheduler facade; output starts with backslash, uses
// backslashes only, and omits trailing slashes except for the root.
std::wstring normalizeTaskPath(const StartupEntry& entry) {
    std::wstring path = entry.taskPath.empty() ? entry.name : entry.taskPath;
    for (wchar_t& ch : path) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    while (!path.empty() && (path.front() == L' ' || path.front() == L'\t')) {
        path.erase(path.begin());
    }
    while (!path.empty() && (path.back() == L' ' || path.back() == L'\t' || path.back() == L'\r' || path.back() == L'\n')) {
        path.pop_back();
    }
    if (path.empty()) {
        return {};
    }
    if (path.front() != L'\\') {
        path.insert(path.begin(), L'\\');
    }
    while (path.size() > 1 && path.back() == L'\\') {
        path.pop_back();
    }
    return path;
}

// splitTaskPath separates a full task path into folder and leaf task name.
// Input is a normalized scheduler path such as "\Vendor\Task"; output is false
// when the path has no task leaf.
bool splitTaskPath(const std::wstring& fullPath, TaskPathParts* parts) {
    if (!parts || fullPath.empty() || fullPath == L"\\") {
        return false;
    }
    const std::size_t kSlash = fullPath.find_last_of(L'\\');
    if (kSlash == std::wstring::npos || kSlash + 1 >= fullPath.size()) {
        return false;
    }
    parts->fullPath = fullPath;
    parts->folderPath = kSlash == 0 ? L"\\" : fullPath.substr(0, kSlash);
    parts->taskName = fullPath.substr(kSlash + 1);
    return !parts->taskName.empty();
}

// openScheduledTask connects to Task Scheduler and resolves one registered task.
// Input is a StartupEntry with taskPath/name filled by StartupEnumerator; output
// owns the COM service, folder and task pointers or carries a precise failure.
ScheduledTaskConnection openScheduledTask(const StartupEntry& entry) {
    ScheduledTaskConnection connection;
    const std::wstring kFullPath = normalizeTaskPath(entry);
    if (!splitTaskPath(kFullPath, &connection.parts)) {
        connection.message = L"计划任务路径无效。";
        return connection;
    }

    if (!connection.apartment.ok()) {
        connection.message = L"CoInitializeEx failed: " + hResultText(connection.apartment.result());
        return connection;
    }
    ensureComSecurity();

    HRESULT hr = ::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(connection.service.put()));
    if (FAILED(hr) || !connection.service) {
        connection.message = L"创建 Task Scheduler 服务失败: " + hResultText(hr);
        return connection;
    }

    VARIANT empty;
    ::VariantInit(&empty);
    hr = connection.service->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        connection.message = L"连接 Task Scheduler 失败: " + hResultText(hr);
        return connection;
    }

    const BStr kFolderPath(connection.parts.folderPath);
    if (!kFolderPath.valid()) {
        connection.message = L"分配计划任务文件夹路径失败。";
        return connection;
    }
    hr = connection.service->GetFolder(kFolderPath.get(), connection.folder.put());
    if (FAILED(hr) || !connection.folder) {
        connection.message = L"打开计划任务文件夹失败: " + connection.parts.folderPath + L" | " + hResultText(hr);
        return connection;
    }

    const BStr kTaskName(connection.parts.taskName);
    if (!kTaskName.valid()) {
        connection.message = L"分配计划任务名称失败。";
        return connection;
    }
    hr = connection.folder->GetTask(kTaskName.get(), connection.task.put());
    if (FAILED(hr) || !connection.task) {
        connection.message = L"打开计划任务失败: " + connection.parts.fullPath + L" | " + hResultText(hr);
        return connection;
    }

    connection.success = true;
    return connection;
}

// setScheduledTaskEnabled applies the enabled flag through IRegisteredTask.
// Inputs are a startup entry and target enabled state; output reports the COM
// mutation result and never leaves a silent failure.
StartupActionResult setScheduledTaskEnabled(const StartupEntry& entry, bool enabled) {
    ScheduledTaskConnection connection = openScheduledTask(entry);
    if (!connection.success) {
        return { false, connection.message };
    }
    const HRESULT kHr = connection.task->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(kHr)) {
        return { false, std::wstring(enabled ? L"启用计划任务失败: " : L"禁用计划任务失败: ") + hResultText(kHr) };
    }
    return { true, std::wstring(enabled ? L"计划任务已启用: " : L"计划任务已禁用: ") + connection.parts.fullPath };
}

// deleteScheduledTask removes one registered task from its parent folder. Input
// is a startup entry; processing resolves the COM folder/task first so stale file
// facade rows report a clear error; output reports deletion status.
StartupActionResult deleteScheduledTask(const StartupEntry& entry) {
    ScheduledTaskConnection connection = openScheduledTask(entry);
    if (!connection.success) {
        return { false, connection.message };
    }
    const BStr kTaskName(connection.parts.taskName);
    if (!kTaskName.valid()) {
        return { false, L"分配计划任务名称失败。" };
    }
    const HRESULT kHr = connection.folder->DeleteTask(kTaskName.get(), 0);
    if (FAILED(kHr)) {
        return { false, L"删除计划任务失败: " + hResultText(kHr) };
    }
    return { true, L"计划任务已删除: " + connection.parts.fullPath };
}

// folderPath returns a CSIDL folder path. Input is a CSIDL value; output is empty
// when Shell32 cannot resolve the folder.
std::wstring folderPath(int csidl) {
    wchar_t path[MAX_PATH]{};
    if (FAILED(::SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, path))) {
        return {};
    }
    return std::wstring(path);
}

// JoinPath combines two Win32 path segments. Inputs are base and leaf; output has
// exactly one slash between non-empty parts.
std::wstring joinPath(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty()) {
        return leaf;
    }
    if (leaf.empty()) {
        return base;
    }
    if (base.back() == L'\\' || base.back() == L'/') {
        return base + leaf;
    }
    return base + L"\\" + leaf;
}

// parentPath returns the containing directory for a path. Input is a Win32 path;
// output is empty when no directory separator exists.
std::wstring parentPath(const std::wstring& path) {
    const std::size_t kPos = path.find_last_of(L"\\/");
    if (kPos == std::wstring::npos) {
        return {};
    }
    return path.substr(0, kPos);
}

// ensureDirectoryRecursive creates a directory tree. Input is an absolute or
// relative path; processing creates missing parents recursively; output is true
// when the directory exists by the end of the call.
bool ensureDirectoryRecursive(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    DWORD attrs = ::GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    const std::wstring kParent = parentPath(path);
    if (!kParent.empty() && kParent != path && !ensureDirectoryRecursive(kParent)) {
        return false;
    }
    if (::CreateDirectoryW(path.c_str(), nullptr)) {
        return true;
    }
    return ::GetLastError() == ERROR_ALREADY_EXISTS;
}

// disabledStartupFolder returns this module's file parking folder for a startup
// folder scope. Input is entry scope; output is empty when LocalAppData is not
// available.
std::wstring disabledStartupFolder(StartupEntryScope scope) {
    const std::wstring kLocalAppData = folderPath(CSIDL_LOCAL_APPDATA);
    if (kLocalAppData.empty()) {
        return {};
    }
    const wchar_t* scopeName = scope == StartupEntryScope::kAllUsers ? L"AllUsers" : L"CurrentUser";
    return joinPath(joinPath(kLocalAppData, kDisabledStartupFolderBase), scopeName);
}

// openRegistryKey opens or creates a key for registry actions. Inputs are root,
// subkey, access, view, and creation mode; output is an owning key or empty key.
RegKey openRegistryKey(HKEY root, const std::wstring& subKey, REGSAM access, DWORD view, bool create) {
    HKEY raw = nullptr;
    if (create) {
        if (::RegCreateKeyExW(root, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                access | view, nullptr, &raw, nullptr) != ERROR_SUCCESS) {
            return RegKey();
        }
    } else if (::RegOpenKeyExW(root, subKey.c_str(), 0, access | view, &raw) != ERROR_SUCCESS) {
        return RegKey();
    }
    return RegKey(raw);
}

// readRegistryString reads one string-like registry value. Inputs are key and
// value name; output is empty when the value is missing or not string-like.
std::wstring readRegistryString(HKEY key, const std::wstring& valueName) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (::RegQueryValueExW(key, valueName.empty() ? nullptr : valueName.c_str(), nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS) {
        return {};
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return {};
    }
    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2, L'\0');
    if (::RegQueryValueExW(key, valueName.empty() ? nullptr : valueName.c_str(), nullptr, &type,
            reinterpret_cast<LPBYTE>(buffer.data()), &bytes) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// writeRegistryString writes one REG_SZ value. Inputs are key, value name and
// text; output is true when RegSetValueExW succeeds.
bool writeRegistryString(HKEY key, const std::wstring& valueName, const std::wstring& text) {
    const DWORD kBytes = static_cast<DWORD>((text.size() + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(key, valueName.empty() ? nullptr : valueName.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(text.c_str()), kBytes) == ERROR_SUCCESS;
}

// deleteRegistryValue removes one value from a key. Inputs are key and value
// name; output is true when deletion succeeds or the value is already absent.
bool deleteRegistryValue(HKEY key, const std::wstring& valueName) {
    const LSTATUS kStatus = ::RegDeleteValueW(key, valueName.empty() ? nullptr : valueName.c_str());
    return kStatus == ERROR_SUCCESS || kStatus == ERROR_FILE_NOT_FOUND;
}

// moveRegistryValue copies a string value between keys and deletes the source.
// Inputs are source/destination metadata and value name; output reports success.
StartupActionResult moveRegistryValue(HKEY sourceRoot, DWORD sourceView, const std::wstring& sourceSubKey,
    HKEY destRoot, DWORD destView, const std::wstring& destSubKey, const std::wstring& valueName) {
    RegKey source = openRegistryKey(sourceRoot, sourceSubKey, KEY_QUERY_VALUE | KEY_SET_VALUE, sourceView, false);
    if (!source.valid()) {
        return { false, L"Source registry key is not available: " + sourceSubKey };
    }
    RegKey dest = openRegistryKey(destRoot, destSubKey, KEY_SET_VALUE, destView, true);
    if (!dest.valid()) {
        return { false, L"Destination registry key is not available: " + destSubKey };
    }
    const std::wstring kCommand = readRegistryString(source.get(), valueName);
    if (kCommand.empty()) {
        return { false, L"Registry value is missing or not string-like." };
    }
    if (!writeRegistryString(dest.get(), valueName, kCommand)) {
        return { false, L"Failed to write destination registry value: " + ksword::core::lastErrorMessage() };
    }
    if (!deleteRegistryValue(source.get(), valueName)) {
        return { false, L"Failed to delete source registry value: " + ksword::core::lastErrorMessage() };
    }
    return { true, L"Registry startup entry moved." };
}

// moveFileEntry moves a Startup-folder item between active and disabled folders.
// Inputs are source and destination paths; processing creates destination parent;
// output reports the MoveFileExW result.
StartupActionResult moveFileEntry(const std::wstring& source, const std::wstring& dest) {
    if (source.empty() || dest.empty()) {
        return { false, L"Startup file source or destination is empty." };
    }
    if (!ensureDirectoryRecursive(parentPath(dest))) {
        return { false, L"Failed to create destination folder." };
    }
    if (!::MoveFileExW(source.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        return { false, L"MoveFileExW failed: " + ksword::core::lastErrorMessage() };
    }
    return { true, L"Startup folder entry moved." };
}

// openServiceForChange opens SCM and one service for configuration changes.
// Inputs are service name and desired access; output is an owning ServiceHandle
// while outScm keeps the SCM handle alive.
ServiceHandle openServiceForChange(const std::wstring& serviceName, DWORD access, ServiceHandle& outScm) {
    outScm.reset(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!outScm.valid()) {
        return ServiceHandle();
    }
    return ServiceHandle(::OpenServiceW(outScm.get(), serviceName.c_str(), access));
}

// serviceStoreSubKey returns the HKCU location used to preserve service start
// type before disabling. Input is a service name; output is the registry path.
std::wstring serviceStoreSubKey(const std::wstring& serviceName) {
    return std::wstring(kServiceDisabledStore) + L"\\" + serviceName;
}

// storeServiceStartType writes the previous start type before disabling a
// service. Inputs are service name and start type; output reports persistence.
bool storeServiceStartType(const std::wstring& serviceName, DWORD startType) {
    RegKey key = openRegistryKey(HKEY_CURRENT_USER, serviceStoreSubKey(serviceName), KEY_SET_VALUE, 0, true);
    if (!key.valid()) {
        return false;
    }
    return ::RegSetValueExW(key.get(), L"StartType", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&startType), sizeof(startType)) == ERROR_SUCCESS;
}

// loadServiceStartType reads a preserved service start type. Inputs are service
// name and fallback; output is the preserved value or fallback.
DWORD loadServiceStartType(const std::wstring& serviceName, DWORD fallback) {
    RegKey key = openRegistryKey(HKEY_CURRENT_USER, serviceStoreSubKey(serviceName), KEY_QUERY_VALUE, 0, false);
    if (!key.valid()) {
        return fallback;
    }
    DWORD type = 0;
    DWORD value = fallback;
    DWORD bytes = sizeof(value);
    if (::RegQueryValueExW(key.get(), L"StartType", nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes) != ERROR_SUCCESS ||
        type != REG_DWORD) {
        return fallback;
    }
    return value;
}

// changeServiceStartType applies one service startup type. Inputs are entry and
// target start type; processing uses ChangeServiceConfigW; output reports status.
StartupActionResult changeServiceStartType(const StartupEntry& entry, DWORD startType) {
    if (entry.serviceName.empty()) {
        return { false, L"Service name is empty." };
    }
    ServiceHandle scm;
    ServiceHandle service = openServiceForChange(entry.serviceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG, scm);
    if (!service.valid()) {
        return { false, L"OpenServiceW failed: " + ksword::core::lastErrorMessage() };
    }
    if (!::ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
        return { false, L"ChangeServiceConfigW failed: " + ksword::core::lastErrorMessage() };
    }
    return { true, L"Service startup type changed." };
}

// registryLocationForRegedit formats a regedit path. Input is a startup entry;
// output is empty when the entry is not registry-backed.
std::wstring registryLocationForRegedit(const StartupEntry& entry) {
    if (entry.registrySubKey.empty()) {
        return {};
    }
    const wchar_t* root = entry.registryRoot == HKEY_LOCAL_MACHINE ? L"HKEY_LOCAL_MACHINE" : L"HKEY_CURRENT_USER";
    return std::wstring(root) + L"\\" + entry.registrySubKey;
}

// shellOpen launches a path or verb target. Inputs are target and optional params;
// output reports whether ShellExecuteW returned a success code.
StartupActionResult shellOpen(const std::wstring& target, const std::wstring& params = {}) {
    HINSTANCE result = ::ShellExecuteW(nullptr, L"open", target.c_str(), params.empty() ? nullptr : params.c_str(), nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        return { false, L"ShellExecuteW failed." };
    }
    return { true, L"Open request issued." };
}

} // namespace

StartupActionResult enableStartupEntry(const StartupEntry& entry) {
    if (isReadOnlyServiceObservation(entry.kind)) {
        return rejectReadOnlyServiceAction(entry);
    }
    if (entry.kind == StartupEntryKind::kScheduledTaskFacade) {
        return setScheduledTaskEnabled(entry, true);
    }
    if (entry.state != StartupEntryState::kDisabled) {
        return { false, L"Entry is not disabled." };
    }
    if (entry.kind == StartupEntryKind::kRegistryRun || entry.kind == StartupEntryKind::kRegistryRunOnce) {
        return moveRegistryValue(HKEY_CURRENT_USER, 0, entry.disabledRegistrySubKey,
            entry.registryRoot, entry.registryView, entry.registrySubKey, entry.registryValueName);
    }
    if (entry.kind == StartupEntryKind::kStartupFolder) {
        return moveFileEntry(entry.disabledFilePath, entry.filePath);
    }
    if (entry.kind == StartupEntryKind::kService) {
        const DWORD kTargetStart = loadServiceStartType(entry.serviceName, SERVICE_AUTO_START);
        return changeServiceStartType(entry, kTargetStart == SERVICE_DISABLED ? SERVICE_AUTO_START : kTargetStart);
    }
    return { false, L"Unsupported startup entry kind." };
}

StartupActionResult disableStartupEntry(const StartupEntry& entry) {
    if (isReadOnlyServiceObservation(entry.kind)) {
        return rejectReadOnlyServiceAction(entry);
    }
    if (entry.state == StartupEntryState::kDisabled) {
        return { false, L"Entry is already disabled." };
    }
    if (entry.kind == StartupEntryKind::kRegistryRun || entry.kind == StartupEntryKind::kRegistryRunOnce) {
        return moveRegistryValue(entry.registryRoot, entry.registryView, entry.registrySubKey,
            HKEY_CURRENT_USER, 0, entry.disabledRegistrySubKey, entry.registryValueName);
    }
    if (entry.kind == StartupEntryKind::kStartupFolder) {
        std::wstring disabledPath = entry.disabledFilePath;
        if (disabledPath.empty()) {
            disabledPath = joinPath(disabledStartupFolder(entry.scope), entry.name);
        }
        return moveFileEntry(entry.filePath, disabledPath);
    }
    if (entry.kind == StartupEntryKind::kService) {
        storeServiceStartType(entry.serviceName, entry.serviceStartType);
        return changeServiceStartType(entry, SERVICE_DISABLED);
    }
    if (entry.kind == StartupEntryKind::kScheduledTaskFacade) {
        return setScheduledTaskEnabled(entry, false);
    }
    return { false, L"Unsupported startup entry kind." };
}

StartupActionResult deleteStartupEntry(const StartupEntry& entry) {
    if (isReadOnlyServiceObservation(entry.kind)) {
        return rejectReadOnlyServiceAction(entry);
    }
    if (entry.kind == StartupEntryKind::kRegistryRun || entry.kind == StartupEntryKind::kRegistryRunOnce) {
        const bool kDisabled = entry.state == StartupEntryState::kDisabled;
        RegKey key = openRegistryKey(kDisabled ? HKEY_CURRENT_USER : entry.registryRoot,
            kDisabled ? entry.disabledRegistrySubKey : entry.registrySubKey,
            KEY_SET_VALUE, kDisabled ? 0 : entry.registryView, false);
        if (!key.valid()) {
            return { false, L"Registry key is not available." };
        }
        if (!deleteRegistryValue(key.get(), entry.registryValueName)) {
            return { false, L"RegDeleteValueW failed: " + ksword::core::lastErrorMessage() };
        }
        return { true, L"Registry startup entry deleted." };
    }
    if (entry.kind == StartupEntryKind::kStartupFolder) {
        const std::wstring kPath = entry.state == StartupEntryState::kDisabled ? entry.disabledFilePath : entry.filePath;
        if (kPath.empty()) {
            return { false, L"Startup file path is empty." };
        }
        if (!::DeleteFileW(kPath.c_str())) {
            return { false, L"DeleteFileW failed: " + ksword::core::lastErrorMessage() };
        }
        return { true, L"Startup folder entry deleted." };
    }
    if (entry.kind == StartupEntryKind::kService) {
        ServiceHandle scm;
        ServiceHandle service = openServiceForChange(entry.serviceName, DELETE, scm);
        if (!service.valid()) {
            return { false, L"OpenServiceW failed: " + ksword::core::lastErrorMessage() };
        }
        if (!::DeleteService(service.get())) {
            return { false, L"DeleteService failed: " + ksword::core::lastErrorMessage() };
        }
        return { true, L"Service delete requested." };
    }
    if (entry.kind == StartupEntryKind::kScheduledTaskFacade) {
        return deleteScheduledTask(entry);
    }
    return { false, L"Unsupported startup entry kind." };
}

StartupActionResult openStartupEntryLocation(const StartupEntry& entry) {
    if (isReadOnlyServiceObservation(entry.kind)) {
        return rejectReadOnlyServiceAction(entry);
    }
    if (entry.kind == StartupEntryKind::kRegistryRun || entry.kind == StartupEntryKind::kRegistryRunOnce) {
        const std::wstring kLocation = registryLocationForRegedit(entry);
        if (kLocation.empty()) {
            return { false, L"Registry location is empty." };
        }
        RegKey regedit = openRegistryKey(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", KEY_SET_VALUE, 0, true);
        if (regedit.valid()) {
            writeRegistryString(regedit.get(), L"LastKey", kLocation);
        }
        return shellOpen(L"regedit.exe");
    }
    if (entry.kind == StartupEntryKind::kStartupFolder) {
        const std::wstring kPath = entry.state == StartupEntryState::kDisabled ? entry.disabledFilePath : entry.filePath;
        if (!kPath.empty()) {
            return shellOpen(L"explorer.exe", L"/select,\"" + kPath + L"\"");
        }
        return shellOpen(entry.location);
    }
    if (entry.kind == StartupEntryKind::kService) {
        return shellOpen(L"services.msc");
    }
    if (entry.kind == StartupEntryKind::kScheduledTaskFacade) {
        if (!entry.location.empty()) {
            return shellOpen(L"explorer.exe", L"/select,\"" + entry.location + L"\"");
        }
        return shellOpen(L"taskschd.msc");
    }
    return { false, L"Unsupported startup entry kind." };
}

} // namespace Ksword::Features::Startup
