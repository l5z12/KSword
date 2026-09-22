#include "HardwareModel.h"

#include <algorithm>
#include <cwctype>
#include <initializer_list>
#include <utility>

namespace ksword::features::hardware {
namespace {

// addProperty appends a detail row only when the value exists. Inputs are target
// detail, label and value; processing keeps the detail pane compact; no return.
void addProperty(HardwareDeviceDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// ToLower returns a case-folded copy for simple substring classification. Input
// is a display or instance string; processing lowercases ASCII/Unicode wchar_t
// values through towlower; output preserves the original string length.
std::wstring toLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

// containsAny checks whether a haystack contains one of the supplied markers.
// Inputs are already-normalized text and marker literals; output is true on the
// first substring match.
bool containsAny(const std::wstring& haystack, const std::initializer_list<const wchar_t*> markers) {
    for (const wchar_t* marker : markers) {
        if (haystack.find(marker) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

// nodeSearchText builds a normalized evidence string from stable devnode fields.
// Input is a HardwareDeviceNode; processing concatenates class, service,
// instance, hardware and compatible IDs; output is used only for classification.
std::wstring nodeSearchText(const HardwareDeviceNode& node) {
    return toLower(node.instanceId + L" " +
        node.parentInstanceId + L" " +
        node.displayName + L" " +
        node.className + L" " +
        node.classGuid + L" " +
        node.serviceName + L" " +
        node.location + L" " +
        node.locationPaths + L" " +
        node.hardwareIds + L" " +
        node.compatibleIds);
}

// hasFilterEvidence reports whether any registry filter source is present for a
// devnode. Input is a cached node; output is true when device/class upper/lower
// filter rows can be shown as read-only evidence.
bool hasFilterEvidence(const HardwareDeviceNode& node) {
    return !node.upperFilters.empty() ||
        !node.lowerFilters.empty() ||
        !node.classUpperFilters.empty() ||
        !node.classLowerFilters.empty();
}

// isInputDevice classifies keyboard, mouse and HID-family devnodes. Input is a
// node; processing uses only SetupAPI/CM class/service/ID text; output does not
// imply live input capture.
bool isInputDevice(const HardwareDeviceNode& node) {
    const std::wstring kText = nodeSearchText(node);
    return containsAny(kText, { L"keyboard", L"kbd", L"mouse", L"mou", L"hidclass", L"hidusb", L"hid\\", L"hid_device" });
}

// isHidDevice classifies generic HID-family rows. Input is a node; output is
// true for HID class/service/ID evidence and false otherwise.
bool isHidDevice(const HardwareDeviceNode& node) {
    const std::wstring kText = nodeSearchText(node);
    return containsAny(kText, { L"hidclass", L"hidusb", L"hid\\", L"hid_device", L"hid-compliant" });
}

// isUsbDevice classifies USB controller, hub, composite and interface rows.
// Input is a node; output is derived from instance/service/location evidence.
bool isUsbDevice(const HardwareDeviceNode& node) {
    const std::wstring kText = nodeSearchText(node);
    return containsAny(kText, { L"usb\\", L"usbstor", L"usbccgp", L"usbhub", L"usbxhci", L"ucx", L"vid_", L"pid_", L"mi_" });
}

// isPciDevice classifies PCI-backed rows. Input is a node; output is true for
// PCI instance IDs, location paths and common PCI identifier fields.
bool isPciDevice(const HardwareDeviceNode& node) {
    const std::wstring kText = nodeSearchText(node);
    return containsAny(kText, { L"pci\\", L"pciroot", L"ven_", L"dev_", L"subsys_" });
}

// isAcpiDevice classifies ACPI and power-management rows. Input is a node;
// output is true for ACPI instance IDs, services and location-path evidence.
bool isAcpiDevice(const HardwareDeviceNode& node) {
    const std::wstring kText = nodeSearchText(node);
    return containsAny(kText, { L"acpi\\", L"acpi(", L"processor", L"intelpep", L"processr", L"pdc" });
}

} // namespace

HardwareModel::HardwareModel() = default;

void HardwareModel::setDevices(std::vector<HardwareDeviceNode> devices) {
    devices_ = std::move(devices);
    rebuildRoots();
}

const std::vector<HardwareDeviceNode>& HardwareModel::devices() const {
    return devices_;
}

const std::vector<int>& HardwareModel::rootIndices() const {
    return rootIndices_;
}

const HardwareDeviceNode* HardwareModel::deviceAt(int index) const {
    if (index < 0 || index >= static_cast<int>(devices_.size())) {
        return nullptr;
    }
    return &devices_[index];
}

std::wstring HardwareModel::textForColumn(const HardwareDeviceNode& node, int column) const {
    switch (column) {
    case 0:
        return compactDeviceName(node);
    case 1:
        return node.className;
    case 2:
        return deviceStateText(node.state, node.problemCode);
    case 3:
        return node.manufacturer;
    case 4:
        return node.serviceName;
    default:
        return {};
    }
}

HardwareDeviceDetail HardwareModel::detailFromNode(const HardwareDeviceNode& node) const {
    HardwareDeviceDetail detail;
    detail.found = true;
    detail.title = compactDeviceName(node);
    detail.instanceId = node.instanceId;
    addProperty(detail, L"Display name", compactDeviceName(node));
    addProperty(detail, L"Instance ID", node.instanceId);
    addProperty(detail, L"Class", node.className);
    addProperty(detail, L"Class GUID", node.classGuid);
    addProperty(detail, L"Manufacturer", node.manufacturer);
    addProperty(detail, L"Service", node.serviceName);
    addProperty(detail, L"Driver key", node.driverKey);
    addProperty(detail, L"Location", node.location);
    addProperty(detail, L"Location paths", node.locationPaths);
    addProperty(detail, L"Hardware IDs", node.hardwareIds);
    addProperty(detail, L"Compatible IDs", node.compatibleIds);
    addProperty(detail, L"Device UpperFilters", node.upperFilters);
    addProperty(detail, L"Device LowerFilters", node.lowerFilters);
    addProperty(detail, L"Class UpperFilters", node.classUpperFilters);
    addProperty(detail, L"Class LowerFilters", node.classLowerFilters);
    addProperty(detail, L"Read-only audit", hardwareReadOnlyAuditDescription(node));
    addProperty(detail, L"State", deviceStateText(node.state, node.problemCode));
    return detail;
}

HardwareAuditSummary HardwareModel::auditSummary() const {
    HardwareAuditSummary summary;
    summary.totalDevices = devices_.size();
    for (const HardwareDeviceNode& node : devices_) {
        if (isInputDevice(node)) {
            ++summary.inputDevices;
        }
        if (isHidDevice(node)) {
            ++summary.hidDevices;
        }
        if (isUsbDevice(node)) {
            ++summary.usbDevices;
        }
        if (isPciDevice(node)) {
            ++summary.pciDevices;
        }
        if (isAcpiDevice(node)) {
            ++summary.acpiDevices;
        }
        if (hasFilterEvidence(node)) {
            ++summary.filterEvidenceDevices;
        }
        if (node.state == HardwareDeviceState::kProblem ||
            node.state == HardwareDeviceState::kDisabled ||
            node.state == HardwareDeviceState::kPhantom) {
            ++summary.problemDevices;
        }
    }
    return summary;
}

void HardwareModel::rebuildRoots() {
    rootIndices_.clear();
    for (const HardwareDeviceNode& node : devices_) {
        if (node.parentIndex < 0) {
            rootIndices_.push_back(node.index);
        }
    }
}

std::wstring deviceStateText(HardwareDeviceState state, ULONG problemCode) {
    switch (state) {
    case HardwareDeviceState::kStarted:
        return L"Started";
    case HardwareDeviceState::kStopped:
        return L"Stopped";
    case HardwareDeviceState::kDisabled:
        return L"Disabled";
    case HardwareDeviceState::kProblem:
        return L"Problem " + std::to_wstring(problemCode);
    case HardwareDeviceState::kPhantom:
        return L"Not present";
    default:
        break;
    }
    return L"Unknown";
}

std::wstring compactDeviceName(const HardwareDeviceNode& node) {
    if (!node.displayName.empty()) {
        return node.displayName;
    }
    if (!node.className.empty()) {
        return node.className;
    }
    if (!node.instanceId.empty()) {
        return node.instanceId;
    }
    return L"Unnamed device";
}

std::wstring hardwareReadOnlyAuditDescription(const HardwareDeviceNode& node) {
    std::vector<std::wstring> labels;
    if (isInputDevice(node)) {
        labels.push_back(L"Input chain");
    }
    if (isHidDevice(node)) {
        labels.push_back(L"HID");
    }
    if (isUsbDevice(node)) {
        labels.push_back(L"USB topology");
    }
    if (isPciDevice(node)) {
        labels.push_back(L"PCI/PnP");
    }
    if (isAcpiDevice(node)) {
        labels.push_back(L"ACPI/PnP");
    }
    if (hasFilterEvidence(node)) {
        labels.push_back(L"Filter registry evidence");
    }
    if (labels.empty()) {
        return L"Device stack/PnP row from SetupAPI and Configuration Manager";
    }

    std::wstring out;
    for (const std::wstring& label : labels) {
        if (!out.empty()) {
            out += L"; ";
        }
        out += label;
    }
    return out;
}

} // namespace Ksword::Features::Hardware
