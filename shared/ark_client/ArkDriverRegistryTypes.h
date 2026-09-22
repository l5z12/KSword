#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkRegistryIoctl.h"

namespace ksword::ark
{
    // RegistryReadResult is the R3 model for R0 registry value read responses.
    struct RegistryReadResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t status = KSWORD_ARK_REGISTRY_READ_STATUS_UNKNOWN; // status: R0 aggregated status.
        std::uint32_t valueType = 0;    // valueType: REG_* type.
        std::uint32_t dataBytes = 0;    // dataBytes: The length of the returned data.
        std::uint32_t requiredBytes = 0; // requiredBytes: Length of the complete value data.
        long lastStatus = 0;            // lastStatus: Underlying Zw* status.
        std::vector<std::uint8_t> data; // data: Raw registry value data.
    };

    // RegistrySubKeyEntry is a subkey enumerated by R0.
    struct RegistrySubKeyEntry
    {
        std::wstring name;              // name: Subkey name, excluding parent path.
    };

    // RegistryValueEntry is a registry value enumerated by R0.
    struct RegistryValueEntry
    {
        std::wstring name;              // name: Value name; empty string indicates the default value.
        std::uint32_t valueType = 0;    // valueType: REG_* type.
        std::uint32_t dataBytes = 0;    // dataBytes: Length of the returned preview data.
        std::uint32_t requiredBytes = 0; // requiredBytes: Total data length.
        std::vector<std::uint8_t> data; // data: Preview data, may be truncated by R0.
    };

    // RegistryEnumResult is the R3 model for R0 key enumeration responses.
    struct RegistryEnumResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t status = KSWORD_ARK_REGISTRY_ENUM_STATUS_UNKNOWN; // status: R0 aggregated status.
        std::uint32_t subKeyCount = 0;  // subKeyCount: Number of subkeys observed by R0.
        std::uint32_t returnedSubKeyCount = 0; // returnedSubKeyCount: Number of subkeys returned.
        std::uint32_t valueCount = 0;   // valueCount: Number of values observed in R0.
        std::uint32_t returnedValueCount = 0; // returnedValueCount: Number of values returned.
        long lastStatus = 0;            // lastStatus: Underlying Zw* status.
        std::vector<RegistrySubKeyEntry> subKeys; // subKeys: list of subkeys.
        std::vector<RegistryValueEntry> values;   // values: List of values.
    };

    // RegistryOperationResult is the generic response model for R0 registry write operations.
    struct RegistryOperationResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_UNKNOWN; // status: Aggregated operation status.
        long lastStatus = 0;            // lastStatus: Underlying Zw* status.
    };
}
