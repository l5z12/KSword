#pragma once

#include "HardwareModel.h"

namespace ksword::features::hardware {

// enumerateDeviceManagerTree builds the read-only hardware audit baseline. There
// is no input; processing uses SetupAPI for device records and Configuration
// Manager for parent/status data; output contains a tree-ready snapshot.
HardwareEnumerationResult enumerateDeviceManagerTree();

// queryDeviceManagerDetails returns live details for one instance ID. Input is a
// PnP device instance ID; processing reopens that devnode through SetupAPI and
// CM APIs; output contains found=false when the device disappeared or cannot be
// opened.
HardwareDeviceDetail queryDeviceManagerDetails(const std::wstring& instanceId);

} // namespace Ksword::Features::Hardware
