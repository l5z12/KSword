#include "HardwareEnumerator.h"

#include "../../core/Common.h"

#include <algorithm>
#include <cfgmgr32.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <setupapi.h>
#include <vector>

#ifndef DN_PHANTOM
#define DN_PHANTOM 0x00004000
#endif

namespace ksword::features::hardware {
namespace {

// DevInfoSet owns a SetupAPI HDEVINFO handle. Inputs are handles from
// SetupDiGetClassDevsW or SetupDiCreateDeviceInfoList; processing releases the
// handle at scope exit; get() returns the raw handle without transferring it.
class DevInfoSet final {
public:
    explicit DevInfoSet(HDEVINFO handle) : handle_(handle) {}
    ~DevInfoSet() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            ::SetupDiDestroyDeviceInfoList(handle_);
        }
    }

    DevInfoSet(const DevInfoSet&) = delete;
    DevInfoSet& operator=(const DevInfoSet&) = delete;

    HDEVINFO get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HDEVINFO handle_;
};

// joinMultiSz converts a REG_MULTI_SZ buffer into a semicolon-separated string.
// Input is the raw UTF-16 buffer returned by SetupAPI; output is compact display
// text and is empty when the buffer has no strings.
std::wstring joinMultiSz(const std::vector<wchar_t>& buffer) {
    std::wstring out;
    const wchar_t* cursor = buffer.data();
    const wchar_t* end = buffer.data() + buffer.size();
    while (cursor < end && *cursor) {
        const std::wstring kPart(cursor);
        if (!out.empty()) {
            out += L"; ";
        }
        out += kPart;
        cursor += kPart.size() + 1;
    }
    return out;
}

// registryTypeToString formats non-string registry data. Inputs are registry type
// and raw bytes; processing keeps display deterministic; output is readable text.
std::wstring registryTypeToString(DWORD type, const std::vector<BYTE>& data) {
    if ((type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) && data.size() >= sizeof(DWORD)) {
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        return L"0x" + std::to_wstring(value);
    }
    if (type == REG_QWORD && data.size() >= sizeof(ULONGLONG)) {
        ULONGLONG value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        return std::to_wstring(value);
    }
    return L"(" + std::to_wstring(data.size()) + L" bytes)";
}

// queryDeviceRegistryProperty reads one SPDRP_* value as display text. Inputs are
// the device set, device info record and property identifier; processing handles
// REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ and numeric fallbacks; output is empty on
// missing or unsupported values.
std::wstring queryDeviceRegistryProperty(HDEVINFO set, SP_DEVINFO_DATA& data, DWORD property) {
    DWORD type = 0;
    DWORD needed = 0;
    ::SetupDiGetDeviceRegistryPropertyW(set, &data, property, &type, nullptr, 0, &needed);
    if (needed == 0) {
        return {};
    }

    std::vector<BYTE> bytes(needed + sizeof(wchar_t) * 2, 0);
    if (!::SetupDiGetDeviceRegistryPropertyW(set, &data, property, &type, bytes.data(), needed, nullptr)) {
        return {};
    }

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(bytes.data());
        return text ? std::wstring(text) : std::wstring();
    }
    if (type == REG_MULTI_SZ) {
        const auto* first = reinterpret_cast<const wchar_t*>(bytes.data());
        const std::size_t kCount = bytes.size() / sizeof(wchar_t);
        return joinMultiSz(std::vector<wchar_t>(first, first + kCount));
    }
    return registryTypeToString(type, bytes);
}

// guidToString converts a device setup class GUID to display text. Input is a
// GUID supplied by SetupAPI; processing formats locally to avoid adding a new
// link-time dependency; output is empty only if formatting fails.
std::wstring guidToString(const GUID& guid) {
    wchar_t buffer[64] = {};
    const int kWritten = swprintf_s(buffer,
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        static_cast<unsigned long>(guid.Data1),
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
    if (kWritten <= 0) {
        return {};
    }
    return std::wstring(buffer);
}

// queryDeviceRegistryMultiSz reads REG_MULTI_SZ values from a device registry
// key. Inputs are an HDEVINFO, device info, property scope and value name;
// processing opens the requested key read-only; output is semicolon-separated
// text or empty when the value/key is absent.
std::wstring queryDeviceRegistryMultiSz(HDEVINFO set,
    SP_DEVINFO_DATA& data,
    DWORD scope,
    DWORD hardwareProfile,
    const wchar_t* valueName) {
    HKEY key = ::SetupDiOpenDevRegKey(set, &data, scope, hardwareProfile, DIREG_DEV, KEY_QUERY_VALUE);
    if (key == INVALID_HANDLE_VALUE) {
        return {};
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = ::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || bytes == 0) {
        ::RegCloseKey(key);
        return {};
    }

    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2, L'\0');
    status = ::RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_MULTI_SZ) {
        return {};
    }
    return joinMultiSz(buffer);
}

// queryClassRegistryMultiSz reads REG_MULTI_SZ class filter values. Inputs are a
// setup class GUID and value name; processing opens the class registry key
// read-only; output is semicolon-separated text or empty when absent.
std::wstring queryClassRegistryMultiSz(const GUID& classGuid, const wchar_t* valueName) {
    HKEY key = ::SetupDiOpenClassRegKeyExW(&classGuid, KEY_QUERY_VALUE, DIOCR_INSTALLER, nullptr, nullptr);
    if (key == INVALID_HANDLE_VALUE) {
        return {};
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = ::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || bytes == 0) {
        ::RegCloseKey(key);
        return {};
    }

    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2, L'\0');
    status = ::RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_MULTI_SZ) {
        return {};
    }
    return joinMultiSz(buffer);
}

// devInstToInstanceId returns the stable PnP instance ID for one devnode. Input
// is a DEVINST from SetupAPI/CM; processing uses CM_Get_Device_IDW; output is
// empty when the devnode is invalid or was removed while enumerating.
std::wstring devInstToInstanceId(DEVINST devInst) {
    ULONG length = 0;
    if (::CM_Get_Device_ID_Size(&length, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1, L'\0');
    if (::CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// queryParentInstanceId reads the parent devnode ID through Configuration
// Manager. Input is a child DEVINST; output is empty for root devices or failed
// parent lookups.
std::wstring queryParentInstanceId(DEVINST devInst) {
    DEVINST parent = 0;
    if (::CM_Get_Parent(&parent, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    return devInstToInstanceId(parent);
}

// stateFromStatus converts CM status/problem values to a small UI enum. Inputs
// are raw status flags and problem code; output is a HardwareDeviceState used by
// model and view formatting.
HardwareDeviceState stateFromStatus(ULONG status, ULONG problem) {
    if ((status & DN_HAS_PROBLEM) != 0) {
        if (problem == CM_PROB_DISABLED) {
            return HardwareDeviceState::kDisabled;
        }
        return HardwareDeviceState::kProblem;
    }
    if ((status & DN_STARTED) != 0) {
        return HardwareDeviceState::kStarted;
    }
    if ((status & DN_PHANTOM) != 0) {
        return HardwareDeviceState::kPhantom;
    }
    if (status != 0) {
        return HardwareDeviceState::kStopped;
    }
    return HardwareDeviceState::kUnknown;
}

// queryStatus fills status flags and problem code for one device. Input is a
// DEVINST; processing uses CM_Get_DevNode_Status; output is the derived state.
HardwareDeviceState queryStatus(DEVINST devInst, ULONG& status, ULONG& problem) {
    status = 0;
    problem = 0;
    if (::CM_Get_DevNode_Status(&status, &problem, devInst, 0) != CR_SUCCESS) {
        return HardwareDeviceState::kUnknown;
    }
    return stateFromStatus(status, problem);
}

// appendProperty adds a live detail row when a value exists. Inputs are mutable
// detail, label and value; processing filters empty values; no return.
void appendProperty(HardwareDeviceDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// populateNodeFromDevInfo converts one SP_DEVINFO_DATA into the module model.
// Inputs are a SetupAPI set, info data and index; processing queries SetupAPI and
// CM fields; output is one HardwareDeviceNode with no child links yet.
HardwareDeviceNode populateNodeFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info, int index) {
    HardwareDeviceNode node;
    node.index = index;
    node.devInst = info.DevInst;
    node.instanceId = devInstToInstanceId(info.DevInst);
    node.parentInstanceId = queryParentInstanceId(info.DevInst);
    node.classGuid = guidToString(info.ClassGuid);
    node.displayName = queryDeviceRegistryProperty(set, info, SPDRP_FRIENDLYNAME);
    if (node.displayName.empty()) {
        node.displayName = queryDeviceRegistryProperty(set, info, SPDRP_DEVICEDESC);
    }
    node.className = queryDeviceRegistryProperty(set, info, SPDRP_CLASS);
    node.manufacturer = queryDeviceRegistryProperty(set, info, SPDRP_MFG);
    node.serviceName = queryDeviceRegistryProperty(set, info, SPDRP_SERVICE);
    node.driverKey = queryDeviceRegistryProperty(set, info, SPDRP_DRIVER);
    node.location = queryDeviceRegistryProperty(set, info, SPDRP_LOCATION_INFORMATION);
    node.locationPaths = queryDeviceRegistryProperty(set, info, SPDRP_LOCATION_PATHS);
    node.hardwareIds = queryDeviceRegistryProperty(set, info, SPDRP_HARDWAREID);
    node.compatibleIds = queryDeviceRegistryProperty(set, info, SPDRP_COMPATIBLEIDS);
    node.upperFilters = queryDeviceRegistryMultiSz(set, info, DICS_FLAG_GLOBAL, 0, L"UpperFilters");
    node.lowerFilters = queryDeviceRegistryMultiSz(set, info, DICS_FLAG_GLOBAL, 0, L"LowerFilters");
    node.classUpperFilters = queryClassRegistryMultiSz(info.ClassGuid, L"UpperFilters");
    node.classLowerFilters = queryClassRegistryMultiSz(info.ClassGuid, L"LowerFilters");
    node.state = queryStatus(info.DevInst, node.statusFlags, node.problemCode);
    return node;
}

// rebuildHierarchy links device nodes using parent instance IDs. Input is a flat
// device vector; processing fills parentIndex, depth, and childIndices fields; no
// value is returned.
void rebuildHierarchy(std::vector<HardwareDeviceNode>& devices) {
    std::map<std::wstring, int> byInstance;
    for (HardwareDeviceNode& node : devices) {
        node.parentIndex = -1;
        node.depth = 0;
        node.childIndices.clear();
        if (!node.instanceId.empty()) {
            byInstance[node.instanceId] = node.index;
        }
    }

    for (HardwareDeviceNode& node : devices) {
        if (node.parentInstanceId.empty()) {
            continue;
        }
        const auto kFound = byInstance.find(node.parentInstanceId);
        if (kFound != byInstance.end() && kFound->second != node.index) {
            node.parentIndex = kFound->second;
            devices[kFound->second].childIndices.push_back(node.index);
        }
    }

    for (HardwareDeviceNode& node : devices) {
        int depth = 0;
        int parent = node.parentIndex;
        while (parent >= 0 && parent < static_cast<int>(devices.size()) && depth < 64) {
            ++depth;
            parent = devices[parent].parentIndex;
        }
        node.depth = depth;
    }

    for (HardwareDeviceNode& node : devices) {
        std::sort(node.childIndices.begin(), node.childIndices.end(), [&devices](int left, int right) {
            return compactDeviceName(devices[left]) < compactDeviceName(devices[right]);
        });
    }
}

// findDeviceByInstanceId opens a specific devnode into an existing read-only
// enumeration set. Inputs are an HDEVINFO and instance ID; processing calls
// SetupDiOpenDeviceInfoW only to address the devnode for property queries; output
// is true when infoData has been initialized for the matching device.
bool findDeviceByInstanceId(HDEVINFO set, const std::wstring& instanceId, SP_DEVINFO_DATA& infoData) {
    infoData = {};
    infoData.cbSize = sizeof(infoData);
    return ::SetupDiOpenDeviceInfoW(set, instanceId.c_str(), nullptr, 0, &infoData) == TRUE;
}

} // namespace

HardwareEnumerationResult enumerateDeviceManagerTree() {
    HardwareEnumerationResult result;
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
    if (!set.valid()) {
        result.success = false;
        result.diagnosticText = L"SetupDiGetClassDevsW failed: " + ksword::core::lastErrorMessage();
        return result;
    }

    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            const DWORD kError = ::GetLastError();
            if (kError == ERROR_NO_MORE_ITEMS) {
                break;
            }
            result.success = false;
            result.diagnosticText = L"SetupDiEnumDeviceInfo failed: " + ksword::core::lastErrorMessage(kError);
            return result;
        }
        result.devices.push_back(populateNodeFromDevInfo(set.get(), info, static_cast<int>(result.devices.size())));
    }

    rebuildHierarchy(result.devices);
    std::sort(result.devices.begin(), result.devices.end(), [](const HardwareDeviceNode& left, const HardwareDeviceNode& right) {
        if (left.parentIndex != right.parentIndex) {
            return left.parentIndex < right.parentIndex;
        }
        return compactDeviceName(left) < compactDeviceName(right);
    });
    for (int i = 0; i < static_cast<int>(result.devices.size()); ++i) {
        result.devices[i].index = i;
    }
    rebuildHierarchy(result.devices);

    result.success = true;
    result.diagnosticText = L"OK";
    return result;
}

HardwareDeviceDetail queryDeviceManagerDetails(const std::wstring& instanceId) {
    HardwareDeviceDetail detail;
    detail.instanceId = instanceId;
    if (instanceId.empty()) {
        return detail;
    }

    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
    if (!set.valid()) {
        return detail;
    }

    SP_DEVINFO_DATA info{};
    if (!findDeviceByInstanceId(set.get(), instanceId, info)) {
        return detail;
    }

    HardwareDeviceNode node = populateNodeFromDevInfo(set.get(), info, 0);
    detail.found = true;
    detail.title = compactDeviceName(node);
    detail.instanceId = node.instanceId;
    appendProperty(detail, L"Display name", compactDeviceName(node));
    appendProperty(detail, L"Instance ID", node.instanceId);
    appendProperty(detail, L"Parent instance ID", node.parentInstanceId);
    appendProperty(detail, L"Class", node.className);
    appendProperty(detail, L"Class GUID", node.classGuid);
    appendProperty(detail, L"Manufacturer", node.manufacturer);
    appendProperty(detail, L"Service", node.serviceName);
    appendProperty(detail, L"Driver key", node.driverKey);
    appendProperty(detail, L"Location", node.location);
    appendProperty(detail, L"Location paths", node.locationPaths);
    appendProperty(detail, L"Hardware IDs", node.hardwareIds);
    appendProperty(detail, L"Compatible IDs", node.compatibleIds);
    appendProperty(detail, L"Device UpperFilters", node.upperFilters);
    appendProperty(detail, L"Device LowerFilters", node.lowerFilters);
    appendProperty(detail, L"Class UpperFilters", node.classUpperFilters);
    appendProperty(detail, L"Class LowerFilters", node.classLowerFilters);
    appendProperty(detail, L"State", deviceStateText(node.state, node.problemCode));
    appendProperty(detail, L"Status flags", L"0x" + std::to_wstring(node.statusFlags));
    appendProperty(detail, L"Problem code", std::to_wstring(node.problemCode));
    return detail;
}

} // namespace Ksword::Features::Hardware
