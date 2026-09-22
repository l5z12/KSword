#include "VirtualLocationBackend.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <QByteArray>
#include <QLatin1Char>
#include <QStringList>

#include <Windows.h>
#include <winsvc.h>

#include <cmath>
#include <cstring>
#include <vector>

// WinRT ABI headers provide only interface declarations and IIDs. Geolocator activation relies on dynamic runtime
// resolution of exports from combase.dll; thus, this file does not explicitly link against runtimeobject.lib.
#include <windows.foundation.h>
#include <windows.devices.geolocation.h>
#include <wrl/client.h>

namespace
{
    using Microsoft::WRL::ComPtr;

    // kDefaultLocationKeyPath：
    // The 'default location' landing point for lfsvc. The ACL for this key permits only SYSTEM and the lfsvc service account; opening
    //   it via Advapi32 from an administrator process typically results in ERROR_ACCESS_DENIED, so an R0 channel must be prepared.
    const wchar_t* const kDefaultLocationSubKey =
        L"SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation";
    const wchar_t* const kDefaultLocationKernelPath =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation";

    // kSensorPolicySubKey：
    // - Location-related Group Policy registry path used to disable the built-in Windows network location provider.
    const wchar_t* const kSensorPolicySubKey =
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors";
    const wchar_t* const kSensorPolicyKernelPath =
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors";

    // kConsentStoreSubKey：
    // - System-wide 'Location Access' master switch: Allow / Deny.
    const wchar_t* const kConsentStoreSubKey =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location";

    // kLatitudeValueName, etc.:
    // - Value names used by the Windows Maps app when writing default location; type is decimal REG_SZ.
    const wchar_t* const kLatitudeValueName = L"Latitude";
    const wchar_t* const kLongitudeValueName = L"Longitude";
    const wchar_t* const kAltitudeValueName = L"Altitude";
    const wchar_t* const kErrorRadiusValueName = L"ErrorRadius";
    const wchar_t* const kAltitudeAccuracyValueName = L"AltitudeAccuracy";
    const wchar_t* const kProviderPolicyValueName = L"DisableWindowsLocationProvider";
    const wchar_t* const kLocationPolicyValueName = L"DisableLocation";

    // RawValue：
    // - Purpose: A registry value's type plus raw bytes; unifies data read from two channels into this structure.
    struct RawValue
    {
        bool found = false;                // found: whether the value exists.
        DWORD type = REG_NONE;             // type: REG_* type.
        std::vector<unsigned char> bytes;  // bytes: Raw data.
    };

    // driverAvailable：
    // - Purpose: Detect if the KswordARK device can be opened to decide whether to proceed via the R0 channel.
    // - Returns: true indicates the driver is online.
    bool driverAvailable()
    {
        const ksword::ark::DriverClient kClient;
        ksword::ark::DriverHandle handle = kClient.open(GENERIC_READ | GENERIC_WRITE);
        return handle.isValid();
    }

    // win32ErrorText：
    // - Input: errorCode: return value of GetLastError.
    // - Purpose: Format Win32 error codes into 'code + system description';
    // - Returns: a single-line text; if the description cannot be retrieved, only the code is returned.
    QString win32ErrorText(const DWORD errorCode)
    {
        LPWSTR buffer = nullptr;
        const DWORD kLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr);
        QString message;
        if (kLength != 0 && buffer != nullptr) {
            message = QString::fromWCharArray(buffer, static_cast<int>(kLength)).trimmed();
        }
        if (buffer != nullptr) {
            ::LocalFree(buffer);
        }
        if (message.isEmpty()) {
            return QStringLiteral("Win32=%1").arg(static_cast<unsigned long>(errorCode));
        }
        return QStringLiteral("Win32=%1 %2")
            .arg(static_cast<unsigned long>(errorCode))
            .arg(message);
    }

    // readValueViaWin32：
    // - Input subKey/valueName: subkey and value name under HKLM
    // - Purpose: Read a value using Advapi32.
    // - Output lastErrorOut: Win32 error code on failure;
    // - Returns: RawValue; if found is false, check lastErrorOut.
    RawValue readValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        DWORD* const lastErrorOut)
    {
        RawValue value;
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }

        HKEY keyHandle = nullptr;
        LSTATUS status = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        DWORD valueType = REG_NONE;
        DWORD dataBytes = 0;
        status = ::RegQueryValueExW(keyHandle, valueName, nullptr, &valueType, nullptr, &dataBytes);
        if (status != ERROR_SUCCESS) {
            ::RegCloseKey(keyHandle);
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        std::vector<unsigned char> buffer(dataBytes == 0 ? 1U : dataBytes, 0U);
        DWORD readBytes = dataBytes;
        status = ::RegQueryValueExW(
            keyHandle,
            valueName,
            nullptr,
            &valueType,
            buffer.data(),
            &readBytes);
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        buffer.resize(readBytes);
        value.found = true;
        value.type = valueType;
        value.bytes = std::move(buffer);
        return value;
    }

    // readValueViaDriver：
    // - Input kernelPath/valueName: kernel-formatted key path and value name;
    // - Purpose: Read a value via KswordARK R0 registry IOCTL, bypassing R3 ACL denials.
    // - Return: RawValue; found is false if the driver is offline, the key does not exist, or the read failed.
    RawValue readValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName)
    {
        RawValue value;
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryReadResult kResult =
            kClient.readRegistryValue(kernelPath, valueName);
        if (!kResult.io.ok ||
            kResult.status != KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS) {
            return value;
        }
        value.found = true;
        value.type = static_cast<DWORD>(kResult.valueType);
        value.bytes.assign(kResult.data.begin(), kResult.data.end());
        return value;
    }

    // registryTypeName：
    // - Input type: REG_* type;
    // - Purpose: Convert to a UI-readable type name.
    // - Returns: Type name string; returns the decimal number for unknown types.
    QString registryTypeName(const DWORD type)
    {
        switch (type) {
        case REG_SZ:
            return QStringLiteral("REG_SZ");
        case REG_EXPAND_SZ:
            return QStringLiteral("REG_EXPAND_SZ");
        case REG_MULTI_SZ:
            return QStringLiteral("REG_MULTI_SZ");
        case REG_DWORD:
            return QStringLiteral("REG_DWORD");
        case REG_QWORD:
            return QStringLiteral("REG_QWORD");
        case REG_BINARY:
            return QStringLiteral("REG_BINARY");
        case REG_NONE:
            return QStringLiteral("REG_NONE");
        default:
            break;
        }
        return QStringLiteral("REG_%1").arg(static_cast<unsigned long>(type));
    }

    // stringFromRawValue：
    // - Input value: raw value read;
    // - Purpose: Convert string-type values to QString; return empty string for other types.
    // - Returns: text with trailing NUL removed.
    QString stringFromRawValue(const RawValue& value)
    {
        if (value.type != REG_SZ &&
            value.type != REG_EXPAND_SZ &&
            value.type != REG_MULTI_SZ) {
            return QString();
        }
        if (value.bytes.size() < sizeof(wchar_t)) {
            return QString();
        }
        const int kCharacterCount =
            static_cast<int>(value.bytes.size() / sizeof(wchar_t));
        QString text = QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(value.bytes.data()),
            kCharacterCount);
        const int kTerminatorIndex = text.indexOf(QChar(u'\0'));
        if (kTerminatorIndex >= 0) {
            text.truncate(kTerminatorIndex);
        }
        return text;
    }

    // integerFromRawValue：
    // - Input value: raw value read;
    // - Purpose: Read integers from REG_DWORD / REG_QWORD.
    // - Output valueOut: parsed result;
    // - Returns: true indicates type match and sufficient length.
    bool integerFromRawValue(const RawValue& value, unsigned long long* const valueOut)
    {
        if (valueOut == nullptr) {
            return false;
        }
        if (value.type == REG_DWORD && value.bytes.size() >= sizeof(quint32)) {
            quint32 raw = 0U;
            std::memcpy(&raw, value.bytes.data(), sizeof(raw));
            *valueOut = raw;
            return true;
        }
        if (value.type == REG_QWORD && value.bytes.size() >= sizeof(quint64)) {
            quint64 raw = 0U;
            std::memcpy(&raw, value.bytes.data(), sizeof(raw));
            *valueOut = raw;
            return true;
        }
        return false;
    }

    // doubleFromRawValue：
    // - Input value: Raw value already read; plausibleLimit: Reasonable absolute value upper bound used to select the interpretation method;
    // - Purpose: Windows Maps writes REG_SZ as decimal, but some tools may write 8-byte binary.
    //   Therefore, attempt interpretation as string, integer, and IEEE754 bit pattern in sequence.
    // - Output valueOut: parsed numeric value;
    // - Returns: true indicates successful parsing.
    bool doubleFromRawValue(
        const RawValue& value,
        const double plausibleLimit,
        double* const valueOut)
    {
        if (valueOut == nullptr || !value.found) {
            return false;
        }

        const QString kText = stringFromRawValue(value);
        if (!kText.isEmpty()) {
            bool converted = false;
            const double kParsed = kText.trimmed().toDouble(&converted);
            if (converted) {
                *valueOut = kParsed;
                return true;
            }
            return false;
        }

        if ((value.type == REG_QWORD || value.type == REG_BINARY) &&
            value.bytes.size() >= sizeof(double)) {
            double asDouble = 0.0;
            std::memcpy(&asDouble, value.bytes.data(), sizeof(asDouble));
            if (std::isfinite(asDouble) && std::fabs(asDouble) <= plausibleLimit) {
                *valueOut = asDouble;
                return true;
            }
        }

        unsigned long long asInteger = 0U;
        if (integerFromRawValue(value, &asInteger)) {
            *valueOut = static_cast<double>(asInteger);
            return true;
        }
        return false;
    }

    // previewTextFromRawValue：
    // - Input value: raw value read;
    // - Purpose: Generate a human-readable line from the raw manifest for the UI; binary types degrade to hexadecimal.
    // - Returns: Preview text.
    QString previewTextFromRawValue(const RawValue& value)
    {
        const QString kText = stringFromRawValue(value);
        if (!kText.isEmpty()) {
            return kText;
        }
        unsigned long long asInteger = 0U;
        if (integerFromRawValue(value, &asInteger)) {
            return QStringLiteral("%1").arg(asInteger);
        }
        const QByteArray kRawBytes(
            reinterpret_cast<const char*>(value.bytes.data()),
            static_cast<int>(value.bytes.size()));
        return QString::fromLatin1(kRawBytes.toHex(' ').toUpper());
    }

    // writeStringValueViaWin32：
    // - Input subKey/valueName/text: HKLM subkey, value name, and decimal text to write;
    // - Purpose: Create (or open if exists) the key and write a REG_SZ value.
    // - Output lastErrorOut: Win32 error code on failure;
    // - Returns: true indicates successful write.
    bool writeStringValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        const QString& text,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        DWORD disposition = 0;
        LSTATUS status = ::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &keyHandle,
            &disposition);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }

        const std::wstring kPayload = text.toStdWString();
        status = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(kPayload.c_str()),
            static_cast<DWORD>((kPayload.size() + 1U) * sizeof(wchar_t)));
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        return true;
    }

    // writeDwordValueViaWin32：
    // - Input subKey/valueName/data: HKLM subkey, value name, and 32-bit data;
    // - Purpose: Write a REG_DWORD value after creating the key;
    // - Output lastErrorOut: Win32 error code on failure;
    // - Returns: true indicates successful write.
    bool writeDwordValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        const DWORD data,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        DWORD disposition = 0;
        LSTATUS status = ::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &keyHandle,
            &disposition);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        status = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&data),
            sizeof(data));
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        return true;
    }

    // deleteValueViaWin32：
    // - Input subKey/valueName: HKLM subkey and value name;
    // - Purpose: Delete a value; if the value does not exist, treat it as a success.
    // - Output lastErrorOut: Win32 error code on failure;
    // - Returns: true if the value is confirmed to be deleted.
    bool deleteValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        LSTATUS status = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &keyHandle);
        if (status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        status = ::RegDeleteValueW(keyHandle, valueName);
        ::RegCloseKey(keyHandle);
        if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        if (lastErrorOut != nullptr) {
            *lastErrorOut = static_cast<DWORD>(status);
        }
        return false;
    }

    // driverOperationSucceeded：
    // - Input: result: R0 write operation response
    // - Purpose: Unified success check;
    // - Returns: Communication succeeded and the aggregated status is SUCCESS.
    bool driverOperationSucceeded(const ksword::ark::RegistryOperationResult& result)
    {
        return result.io.ok &&
            result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
    }

    // writeStringValueViaDriver：
    // - Input kernelPath/valueName/text: Kernel key path, value name, and decimal text.
    // - Action: creates key in R0 and writes REG_SZ with trailing NUL.
    // - Returns: true indicates successful write.
    bool writeStringValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName,
        const QString& text)
    {
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kCreateResult =
            kClient.createRegistryKey(kernelPath);
        const bool kKeyReady = driverOperationSucceeded(kCreateResult) ||
            (kCreateResult.io.ok &&
             kCreateResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS);
        if (!kKeyReady) {
            return false;
        }

        const std::wstring kPayload = text.toStdWString();
        const auto* const kFirstByte =
            reinterpret_cast<const std::uint8_t*>(kPayload.c_str());
        const std::vector<std::uint8_t> kData(
            kFirstByte,
            kFirstByte + (kPayload.size() + 1U) * sizeof(wchar_t));
        return driverOperationSucceeded(
            kClient.setRegistryValue(kernelPath, valueName, REG_SZ, kData));
    }

    // writeDwordValueViaDriver：
    // - Input kernelPath/valueName/data: Kernel key path, value name, and 32-bit data;
    // - Purpose: Create a registry key in R0 and write a REG_DWORD value.
    // - Returns: true indicates successful write.
    bool writeDwordValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName,
        const std::uint32_t data)
    {
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kCreateResult =
            kClient.createRegistryKey(kernelPath);
        const bool kKeyReady = driverOperationSucceeded(kCreateResult) ||
            (kCreateResult.io.ok &&
             kCreateResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS);
        if (!kKeyReady) {
            return false;
        }
        const auto* const kFirstByte = reinterpret_cast<const std::uint8_t*>(&data);
        const std::vector<std::uint8_t> kPayload(kFirstByte, kFirstByte + sizeof(data));
        return driverOperationSucceeded(
            kClient.setRegistryValue(kernelPath, valueName, REG_DWORD, kPayload));
    }

    // deleteValueViaDriver：
    // - Input kernelPath/valueName: kernel key path and value name;
    // - Purpose: deletes a value in R0; treats non-existent values as success.
    // - Returns: true if the value is confirmed to be deleted.
    bool deleteValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName)
    {
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kResult =
            kClient.deleteRegistryValue(kernelPath, valueName);
        if (driverOperationSucceeded(kResult)) {
            return true;
        }
        return kResult.io.ok &&
            kResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND;
    }
}

namespace
{
    // ===================== Coordinate System Conversion =====================
    // GCJ-02 is a non-public offset applied on top of WGS-84. The industry standard approach uses the following empirical polynomial for approximate
    // forward transformation and iterative approximation for inverse transformation. BD-09 adds a fixed polar coordinate offset on top of GCJ-02.

    constexpr double kPi = 3.1415926535897932384626;
    constexpr double kSemiMajorAxis = 6378245.0;            // Krasovsky ellipsoid semi-major axis, in meters.
    constexpr double kEccentricitySquared = 0.00669342162296594323; // First eccentricity squared.
    constexpr double kBaiduFactor = kPi * 3000.0 / 180.0;   // Angular frequency used for BD-09 offset.

    // outOfChina：
    // - Input latitude/longitude: WGS-84 or GCJ-02 coordinates;
    // - Purpose: Roughly determine if outside the valid offset range for mainland China.
    // - Returns: true if the three coordinate systems can be considered equivalent.
    bool outOfChina(const double latitude, const double longitude)
    {
        return longitude < 72.004 || longitude > 137.8347 ||
            latitude < 0.8293 || latitude > 55.8271;
    }

    // transformLatitudeOffset / transformLongitudeOffset：
    // - Input x/y: Latitude/longitude offset relative to the reference point;
    // - Purpose: GCJ-02 empirical offset polynomial.
    // - Returns: Intermediate value without ellipsoid correction.
    double transformLatitudeOffset(const double x, const double y)
    {
        double result = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y +
            0.2 * std::sqrt(std::fabs(x));
        result += (20.0 * std::sin(6.0 * x * kPi) + 20.0 * std::sin(2.0 * x * kPi)) * 2.0 / 3.0;
        result += (20.0 * std::sin(y * kPi) + 40.0 * std::sin(y / 3.0 * kPi)) * 2.0 / 3.0;
        result += (160.0 * std::sin(y / 12.0 * kPi) + 320.0 * std::sin(y * kPi / 30.0)) * 2.0 / 3.0;
        return result;
    }

    double transformLongitudeOffset(const double x, const double y)
    {
        double result = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y +
            0.1 * std::sqrt(std::fabs(x));
        result += (20.0 * std::sin(6.0 * x * kPi) + 20.0 * std::sin(2.0 * x * kPi)) * 2.0 / 3.0;
        result += (20.0 * std::sin(x * kPi) + 40.0 * std::sin(x / 3.0 * kPi)) * 2.0 / 3.0;
        result += (150.0 * std::sin(x / 12.0 * kPi) + 300.0 * std::sin(x / 30.0 * kPi)) * 2.0 / 3.0;
        return result;
    }

    // wgs84ToGcj02：
    // - Input wgsLatitude/wgsLongitude: WGS-84 coordinates;
    // - Output gcjLatitudeOut/gcjLongitudeOut: GCJ-02 coordinates.
    // - Returns: None. Coordinates outside the region are passed through unchanged.
    void wgs84ToGcj02(
        const double wgsLatitude,
        const double wgsLongitude,
        double* const gcjLatitudeOut,
        double* const gcjLongitudeOut)
    {
        if (outOfChina(wgsLatitude, wgsLongitude)) {
            *gcjLatitudeOut = wgsLatitude;
            *gcjLongitudeOut = wgsLongitude;
            return;
        }
        double latitudeOffset =
            transformLatitudeOffset(wgsLongitude - 105.0, wgsLatitude - 35.0);
        double longitudeOffset =
            transformLongitudeOffset(wgsLongitude - 105.0, wgsLatitude - 35.0);
        const double kRadianLatitude = wgsLatitude / 180.0 * kPi;
        double magic = std::sin(kRadianLatitude);
        magic = 1.0 - kEccentricitySquared * magic * magic;
        const double kSquareRootMagic = std::sqrt(magic);
        latitudeOffset = (latitudeOffset * 180.0) /
            ((kSemiMajorAxis * (1.0 - kEccentricitySquared)) / (magic * kSquareRootMagic) * kPi);
        longitudeOffset = (longitudeOffset * 180.0) /
            (kSemiMajorAxis / kSquareRootMagic * std::cos(kRadianLatitude) * kPi);
        *gcjLatitudeOut = wgsLatitude + latitudeOffset;
        *gcjLongitudeOut = wgsLongitude + longitudeOffset;
    }

    // gcj02ToWgs84：
    // - Input gcjLatitude/gcjLongitude: GCJ-02 coordinates;
    // - Output wgsLatitudeOut/wgsLongitudeOut: WGS-84 coordinates.
    // - Purpose: The forward transformation has no closed-form inverse; use fixed-point iteration to reduce the residual to sub-centimeter precision.
    // - Returns: Nothing.
    void gcj02ToWgs84(
        const double gcjLatitude,
        const double gcjLongitude,
        double* const wgsLatitudeOut,
        double* const wgsLongitudeOut)
    {
        if (outOfChina(gcjLatitude, gcjLongitude)) {
            *wgsLatitudeOut = gcjLatitude;
            *wgsLongitudeOut = gcjLongitude;
            return;
        }
        double guessLatitude = gcjLatitude;
        double guessLongitude = gcjLongitude;
        for (int iteration = 0; iteration < 12; ++iteration) {
            double forwardLatitude = 0.0;
            double forwardLongitude = 0.0;
            wgs84ToGcj02(guessLatitude, guessLongitude, &forwardLatitude, &forwardLongitude);
            const double kLatitudeResidual = gcjLatitude - forwardLatitude;
            const double kLongitudeResidual = gcjLongitude - forwardLongitude;
            guessLatitude += kLatitudeResidual;
            guessLongitude += kLongitudeResidual;
            if (std::fabs(kLatitudeResidual) < 1e-9 && std::fabs(kLongitudeResidual) < 1e-9) {
                break;
            }
        }
        *wgsLatitudeOut = guessLatitude;
        *wgsLongitudeOut = guessLongitude;
    }

    // gcj02ToBd09 / bd09ToGcj02：
    // - Purpose: Fixed polar coordinate offset on top of GCJ-02 for Baidu; both forward and inverse transformations are closed-form.
    // - Returns: Nothing.
    void gcj02ToBd09(
        const double gcjLatitude,
        const double gcjLongitude,
        double* const bdLatitudeOut,
        double* const bdLongitudeOut)
    {
        const double kRadius =
            std::sqrt(gcjLongitude * gcjLongitude + gcjLatitude * gcjLatitude) +
            0.00002 * std::sin(gcjLatitude * kBaiduFactor);
        const double kTheta = std::atan2(gcjLatitude, gcjLongitude) +
            0.000003 * std::cos(gcjLongitude * kBaiduFactor);
        *bdLongitudeOut = kRadius * std::cos(kTheta) + 0.0065;
        *bdLatitudeOut = kRadius * std::sin(kTheta) + 0.006;
    }

    void bd09ToGcj02(
        const double bdLatitude,
        const double bdLongitude,
        double* const gcjLatitudeOut,
        double* const gcjLongitudeOut)
    {
        const double kX = bdLongitude - 0.0065;
        const double kY = bdLatitude - 0.006;
        const double kRadius = std::sqrt(kX * kX + kY * kY) - 0.00002 * std::sin(kY * kBaiduFactor);
        const double kTheta = std::atan2(kY, kX) - 0.000003 * std::cos(kX * kBaiduFactor);
        *gcjLongitudeOut = kRadius * std::cos(kTheta);
        *gcjLatitudeOut = kRadius * std::sin(kTheta);
    }
}

namespace
{
    // ===================== WinRT Live Location ===================== Only uses four exports
    // from combase.dll, all resolved at runtime to avoid introducing a static dependency on
    // runtimeobject.lib for the entire main executable just for this optional feature.

    using RoInitializeFn = HRESULT(WINAPI*)(int);
    using RoUninitializeFn = void(WINAPI*)();
    using RoActivateInstanceFn = HRESULT(WINAPI*)(HSTRING, IInspectable**);
    using WindowsCreateStringFn = HRESULT(WINAPI*)(PCNZWCH, UINT32, HSTRING*);
    using WindowsDeleteStringFn = HRESULT(WINAPI*)(HSTRING);

    // ComBaseApi：
    // - Purpose: Parse COM base.dll export-related functions once.
    // - Note: combase.dll is a system resident module, so FreeLibrary is not called here.
    struct ComBaseApi
    {
        RoInitializeFn roInitialize = nullptr;
        RoUninitializeFn roUninitialize = nullptr;
        RoActivateInstanceFn roActivateInstance = nullptr;
        WindowsCreateStringFn windowsCreateString = nullptr;
        WindowsDeleteStringFn windowsDeleteString = nullptr;

        bool isComplete() const
        {
            return roInitialize != nullptr && roUninitialize != nullptr &&
                roActivateInstance != nullptr && windowsCreateString != nullptr &&
                windowsDeleteString != nullptr;
        }
    };

    // loadComBaseApi：
    // - Purpose: Parse and cache exports from combase.dll;
    // - Returns: Parsing result; do not continue calling WinRT if isComplete is false.
    const ComBaseApi& loadComBaseApi()
    {
        static const ComBaseApi kApi = []() {
            ComBaseApi resolved;
            const HMODULE kModuleHandle = ::GetModuleHandleW(L"combase.dll") != nullptr
                ? ::GetModuleHandleW(L"combase.dll")
                : ::LoadLibraryW(L"combase.dll");
            if (kModuleHandle == nullptr) {
                return resolved;
            }
            resolved.roInitialize = reinterpret_cast<RoInitializeFn>(
                reinterpret_cast<void*>(::GetProcAddress(kModuleHandle, "RoInitialize")));
            resolved.roUninitialize = reinterpret_cast<RoUninitializeFn>(
                reinterpret_cast<void*>(::GetProcAddress(kModuleHandle, "RoUninitialize")));
            resolved.roActivateInstance = reinterpret_cast<RoActivateInstanceFn>(
                reinterpret_cast<void*>(::GetProcAddress(kModuleHandle, "RoActivateInstance")));
            resolved.windowsCreateString = reinterpret_cast<WindowsCreateStringFn>(
                reinterpret_cast<void*>(::GetProcAddress(kModuleHandle, "WindowsCreateString")));
            resolved.windowsDeleteString = reinterpret_cast<WindowsDeleteStringFn>(
                reinterpret_cast<void*>(::GetProcAddress(kModuleHandle, "WindowsDeleteString")));
            return resolved;
        }();
        return kApi;
    }

    // positionSourceText：
    // - Input source: Position source reported by WinRT;
    // - Purpose: Translate to user-readable descriptions; 'Default' serves as evidence that the default location is active.
    // - Returns: The source text.
    QString positionSourceText(
        const ABI::Windows::Devices::Geolocation::PositionSource source)
    {
        using ABI::Windows::Devices::Geolocation::PositionSource;
        switch (source) {
        case PositionSource::PositionSource_Cellular:
            return QStringLiteral("蜂窝网络");
        case PositionSource::PositionSource_Satellite:
            return QStringLiteral("卫星");
        case PositionSource::PositionSource_WiFi:
            return QStringLiteral("WiFi");
        case PositionSource::PositionSource_IPAddress:
            return QStringLiteral("IP 地址");
        case PositionSource::PositionSource_Unknown:
            return QStringLiteral("未知来源");
        case PositionSource::PositionSource_Default:
            return QStringLiteral("默认位置");
        case PositionSource::PositionSource_Obfuscated:
            return QStringLiteral("已模糊化");
        default:
            break;
        }
        return QStringLiteral("未识别来源");
    }
}

namespace ks::misc::virtual_location
{
    QString defaultLocationKeyPath()
    {
        return QStringLiteral("HKLM\\%1").arg(QString::fromWCharArray(kDefaultLocationSubKey));
    }

    QString sensorPolicyKeyPath()
    {
        return QStringLiteral("HKLM\\%1").arg(QString::fromWCharArray(kSensorPolicySubKey));
    }

    DefaultLocationSnapshot readDefaultLocation()
    {
        DefaultLocationSnapshot snapshot;

        struct ValueSpec
        {
            const wchar_t* name;   // name: Registry value name.
            double limit;          // limit: reasonable absolute upper bound for binary interpretation.
            double* target;        // target: Resolution result destination.
            bool required;         // required: Whether it is a condition for determining 'default location is set'.
        };
        const ValueSpec kValueSpecs[] = {
            { kLatitudeValueName, 90.0, &snapshot.coordinate.latitude, true },
            { kLongitudeValueName, 180.0, &snapshot.coordinate.longitude, true },
            { kAltitudeValueName, 100000.0, &snapshot.coordinate.altitude, false },
            { kErrorRadiusValueName, 1.0e7, &snapshot.coordinate.errorRadiusMeters, false },
            { kAltitudeAccuracyValueName, 1.0e7, &snapshot.coordinate.altitudeAccuracyMeters, false },
        };

        DWORD firstWin32Error = ERROR_SUCCESS;
        bool anyWin32Success = false;
        bool anyDriverSuccess = false;
        int requiredHitCount = 0;

        for (const ValueSpec& spec : kValueSpecs) {
            DWORD lastError = ERROR_SUCCESS;
            RawValue value = readValueViaWin32(kDefaultLocationSubKey, spec.name, &lastError);
            bool fromDriver = false;
            if (value.found) {
                anyWin32Success = true;
            }
            else {
                if (firstWin32Error == ERROR_SUCCESS) {
                    firstWin32Error = lastError;
                }
                // When the default location is not set, the entire key is absent. This is the page's normal initial state;
                // do not request R0 for each of the five candidate values, and do not escalate NOT_FOUND to a log alert.
                // Fall back to the driver only if R3 truly cannot access the existing key (e.g., due to lfsvc ACL denial).
                if (lastError != ERROR_FILE_NOT_FOUND &&
                    lastError != ERROR_PATH_NOT_FOUND) {
                    value = readValueViaDriver(kDefaultLocationKernelPath, spec.name);
                    fromDriver = value.found;
                    if (value.found) {
                        anyDriverSuccess = true;
                    }
                }
            }
            if (!value.found) {
                continue;
            }

            snapshot.rawValueLines.append(
                QStringLiteral("%1 (%2) = %3    [%4]")
                    .arg(QString::fromWCharArray(spec.name))
                    .arg(registryTypeName(value.type))
                    .arg(previewTextFromRawValue(value))
                    .arg(fromDriver ? QStringLiteral("R0") : QStringLiteral("R3")));

            double parsed = 0.0;
            if (doubleFromRawValue(value, spec.limit, &parsed)) {
                *spec.target = parsed;
                if (spec.required) {
                    ++requiredHitCount;
                }
            }
        }

        snapshot.readable = anyWin32Success || anyDriverSuccess;
        snapshot.backend = anyDriverSuccess
            ? RegistryBackend::kDriver
            : (anyWin32Success ? RegistryBackend::kWin32 : RegistryBackend::kNone);
        snapshot.present = requiredHitCount == 2;

        if (!snapshot.readable) {
            // Note: A read failure occurs in two cases: the key has no default location (normal), or both channels are blocked.
            // Distinguish using R3 error codes: ACCESS_DENIED means the key exists but cannot be read, requiring the driver.
            if (firstWin32Error == ERROR_FILE_NOT_FOUND ||
                firstWin32Error == ERROR_PATH_NOT_FOUND) {
                snapshot.readable = true;
                snapshot.backend = RegistryBackend::kWin32;
                snapshot.present = false;
            }
            else if (firstWin32Error == ERROR_ACCESS_DENIED && !driverAvailable()) {
                snapshot.failureText = QStringLiteral(
                    "该键的 ACL 只放行 SYSTEM 与位置服务本身，R3 读取被拒绝；"
                    "请加载 KswordARK 驱动后重试。");
            }
            else {
                snapshot.failureText = win32ErrorText(firstWin32Error);
            }
        }
        return snapshot;
    }

    OperationResult applyDefaultLocation(const GeoCoordinate& coordinate)
    {
        OperationResult result;

        struct WriteSpec
        {
            const wchar_t* name; // name: Registry value name.
            double value;        // value: value to be written.
        };
        const WriteSpec kWriteSpecs[] = {
            { kLatitudeValueName, coordinate.latitude },
            { kLongitudeValueName, coordinate.longitude },
            { kAltitudeValueName, coordinate.altitude },
            { kErrorRadiusValueName, coordinate.errorRadiusMeters },
            { kAltitudeAccuracyValueName, coordinate.altitudeAccuracyMeters },
        };

        bool usedDriver = false;
        DWORD firstWin32Error = ERROR_SUCCESS;
        for (const WriteSpec& spec : kWriteSpecs) {
            // Windows Maps writes decimal strings without thousand separators and using a dot as the decimal point.
            // Format here using the C locale to avoid using a comma as the decimal separator based on the UI language.
            const QString kText = QString::number(spec.value, 'f', 8);
            DWORD lastError = ERROR_SUCCESS;
            if (writeStringValueViaWin32(kDefaultLocationSubKey, spec.name, kText, &lastError)) {
                continue;
            }
            if (firstWin32Error == ERROR_SUCCESS) {
                firstWin32Error = lastError;
            }
            if (!writeStringValueViaDriver(kDefaultLocationKernelPath, spec.name, kText)) {
                result.ok = false;
                result.backend = RegistryBackend::kNone;
                result.detailText = driverAvailable()
                    ? QStringLiteral("写入 %1 失败：R3 %2；R0 注册表 IOCTL 同样失败。")
                        .arg(QString::fromWCharArray(spec.name))
                        .arg(win32ErrorText(lastError))
                    : QStringLiteral("写入 %1 失败：R3 %2；KswordARK 驱动未加载，没有回退通道。")
                        .arg(QString::fromWCharArray(spec.name))
                        .arg(win32ErrorText(lastError));
                return result;
            }
            usedDriver = true;
        }

        result.ok = true;
        result.backend = usedDriver ? RegistryBackend::kDriver : RegistryBackend::kWin32;
        return result;
    }

    OperationResult clearDefaultLocation()
    {
        OperationResult result;
        const wchar_t* const kValueNames[] = {
            kLatitudeValueName,
            kLongitudeValueName,
            kAltitudeValueName,
            kErrorRadiusValueName,
            kAltitudeAccuracyValueName,
        };

        bool usedDriver = false;
        for (const wchar_t* const kValueName : kValueNames) {
            DWORD lastError = ERROR_SUCCESS;
            if (deleteValueViaWin32(kDefaultLocationSubKey, kValueName, &lastError)) {
                continue;
            }
            if (!deleteValueViaDriver(kDefaultLocationKernelPath, kValueName)) {
                result.ok = false;
                result.backend = RegistryBackend::kNone;
                result.detailText =
                    QStringLiteral("删除 %1 失败：R3 %2；R0 通道也没有完成删除。")
                        .arg(QString::fromWCharArray(kValueName))
                        .arg(win32ErrorText(lastError));
                return result;
            }
            usedDriver = true;
        }

        result.ok = true;
        result.backend = usedDriver ? RegistryBackend::kDriver : RegistryBackend::kWin32;
        return result;
    }

    ServiceSnapshot readServiceSnapshot()
    {
        ServiceSnapshot snapshot;

        const SC_HANDLE kManagerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (kManagerHandle != nullptr) {
            const SC_HANDLE kServiceHandle =
                ::OpenServiceW(kManagerHandle, L"lfsvc", SERVICE_QUERY_STATUS);
            if (kServiceHandle != nullptr) {
                SERVICE_STATUS_PROCESS statusProcess{};
                DWORD bytesNeeded = 0;
                if (::QueryServiceStatusEx(
                        kServiceHandle,
                        SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&statusProcess),
                        sizeof(statusProcess),
                        &bytesNeeded) != FALSE) {
                    snapshot.serviceQueryOk = true;
                    snapshot.serviceRunning =
                        statusProcess.dwCurrentState == SERVICE_RUNNING;
                    switch (statusProcess.dwCurrentState) {
                    case SERVICE_RUNNING:
                        snapshot.serviceStateText = QStringLiteral("正在运行");
                        break;
                    case SERVICE_STOPPED:
                        snapshot.serviceStateText = QStringLiteral("已停止（按需触发启动）");
                        break;
                    case SERVICE_START_PENDING:
                        snapshot.serviceStateText = QStringLiteral("正在启动");
                        break;
                    case SERVICE_STOP_PENDING:
                        snapshot.serviceStateText = QStringLiteral("正在停止");
                        break;
                    default:
                        snapshot.serviceStateText = QStringLiteral("状态 %1")
                            .arg(static_cast<unsigned long>(statusProcess.dwCurrentState));
                        break;
                    }
                }
                ::CloseServiceHandle(kServiceHandle);
            }
            ::CloseServiceHandle(kManagerHandle);
        }
        if (!snapshot.serviceQueryOk) {
            snapshot.serviceStateText = QStringLiteral("无法查询位置服务状态");
        }

        DWORD lastError = ERROR_SUCCESS;
        const RawValue kConsentValue =
            readValueViaWin32(kConsentStoreSubKey, L"Value", &lastError);
        if (kConsentValue.found) {
            snapshot.consentReadable = true;
            snapshot.locationAllowed =
                stringFromRawValue(kConsentValue).compare(
                    QStringLiteral("Allow"), Qt::CaseInsensitive) == 0;
        }

        const std::wstring kNonPackagedSubKey =
            std::wstring(kConsentStoreSubKey) + L"\\NonPackaged";
        const RawValue kNonPackagedValue =
            readValueViaWin32(kNonPackagedSubKey.c_str(), L"Value", &lastError);
        // The NonPackaged subkey defaults without a value; in this case, the desktop app follows the system-wide toggle.
        snapshot.desktopAppAllowed = kNonPackagedValue.found
            ? stringFromRawValue(kNonPackagedValue).compare(
                  QStringLiteral("Allow"), Qt::CaseInsensitive) == 0
            : snapshot.locationAllowed;

        QStringList policyLines;
        const RawValue kProviderPolicy =
            readValueViaWin32(kSensorPolicySubKey, kProviderPolicyValueName, &lastError);
        if (kProviderPolicy.found) {
            unsigned long long providerFlag = 0U;
            integerFromRawValue(kProviderPolicy, &providerFlag);
            snapshot.providerDisabledByPolicy = providerFlag != 0U;
            policyLines.append(
                QStringLiteral("DisableWindowsLocationProvider = %1").arg(providerFlag));
        }
        const RawValue kLocationPolicy =
            readValueViaWin32(kSensorPolicySubKey, kLocationPolicyValueName, &lastError);
        if (kLocationPolicy.found) {
            unsigned long long locationFlag = 0U;
            integerFromRawValue(kLocationPolicy, &locationFlag);
            snapshot.locationDisabledByPolicy = locationFlag != 0U;
            policyLines.append(QStringLiteral("DisableLocation = %1").arg(locationFlag));
        }
        snapshot.policyDetailText = policyLines.isEmpty()
            ? QStringLiteral("未设置位置相关组策略")
            : policyLines.join(QStringLiteral("；"));
        return snapshot;
    }

    OperationResult setLocationProviderDisabled(const bool disabled)
    {
        OperationResult result;
        DWORD lastError = ERROR_SUCCESS;

        if (disabled) {
            if (writeDwordValueViaWin32(
                    kSensorPolicySubKey, kProviderPolicyValueName, 1UL, &lastError)) {
                result.ok = true;
                result.backend = RegistryBackend::kWin32;
                return result;
            }
            if (writeDwordValueViaDriver(
                    kSensorPolicyKernelPath, kProviderPolicyValueName, 1U)) {
                result.ok = true;
                result.backend = RegistryBackend::kDriver;
                return result;
            }
            result.detailText =
                QStringLiteral("写入组策略失败：R3 %1；R0 通道也没有完成写入。")
                    .arg(win32ErrorText(lastError));
            return result;
        }

        if (deleteValueViaWin32(kSensorPolicySubKey, kProviderPolicyValueName, &lastError)) {
            result.ok = true;
            result.backend = RegistryBackend::kWin32;
            return result;
        }
        if (deleteValueViaDriver(kSensorPolicyKernelPath, kProviderPolicyValueName)) {
            result.ok = true;
            result.backend = RegistryBackend::kDriver;
            return result;
        }
        result.detailText =
            QStringLiteral("删除组策略失败：R3 %1；R0 通道也没有完成删除。")
                .arg(win32ErrorText(lastError));
        return result;
    }

    OperationResult restartLocationService()
    {
        OperationResult result;
        const SC_HANDLE kManagerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (kManagerHandle == nullptr) {
            result.detailText = QStringLiteral("打开服务控制管理器失败：%1")
                .arg(win32ErrorText(::GetLastError()));
            return result;
        }

        const SC_HANDLE kServiceHandle = ::OpenServiceW(
            kManagerHandle, L"lfsvc", SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (kServiceHandle == nullptr) {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseServiceHandle(kManagerHandle);
            result.detailText = QStringLiteral("打开位置服务失败：%1")
                .arg(win32ErrorText(kErrorCode));
            return result;
        }

        SERVICE_STATUS serviceStatus{};
        if (::ControlService(kServiceHandle, SERVICE_CONTROL_STOP, &serviceStatus) != FALSE) {
            result.ok = true;
        }
        else {
            const DWORD kErrorCode = ::GetLastError();
            // ControlService returns NOT_ACTIVE when the service is already stopped, which is equivalent to 'already stopped'.
            result.ok = kErrorCode == ERROR_SERVICE_NOT_ACTIVE;
            if (!result.ok) {
                result.detailText = QStringLiteral("停止位置服务失败：%1")
                    .arg(win32ErrorText(kErrorCode));
            }
        }
        ::CloseServiceHandle(kServiceHandle);
        ::CloseServiceHandle(kManagerHandle);
        return result;
    }

    LiveFixResult queryLiveFix(const unsigned long timeoutMilliseconds)
    {
        using namespace ABI::Windows::Foundation;
        using namespace ABI::Windows::Devices::Geolocation;

        LiveFixResult result;
        const ComBaseApi& api = loadComBaseApi();
        if (!api.isComplete()) {
            result.failureText = QStringLiteral("当前系统缺少 WinRT 定位入口，无法读取实况坐标。");
            return result;
        }

        // This function is called by a background thread with a clean apartment; initialize as MTA.
        // If the thread is already initialized to a different apartment, RoInitialize returns RPC_E_CHANGED_MODE; proceed with the current state.
        const HRESULT kInitializeResult = api.roInitialize(1 /* RO_INIT_MULTITHREADED */);
        const bool kShouldUninitialize =
            SUCCEEDED(kInitializeResult) || kInitializeResult == S_FALSE;
        if (FAILED(kInitializeResult) && kInitializeResult != RPC_E_CHANGED_MODE) {
            result.failureText = QStringLiteral("初始化 WinRT 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(kInitializeResult), 8, 16, QLatin1Char('0'));
            return result;
        }

        /*
         * Must use a scope guard instead of manually calling finalize before each return: All ComPtr objects in this function are
         * function-scope objects. Manual finalize would cause RoUninitialize to execute before their destructors, releasing
         * interfaces after the apartment is torn down. This is especially dangerous in timeout paths—after Cancel, requests may still
         * be in flight; tearing down the apartment cuts the RPC connection on that thread, and subsequently releasing a cross-process
         * IAsyncOperation could cause an access violation. This is a detached thread, so a crash would bring down the entire process.
         * Declare the guard before all ComPtr objects. Local objects are destroyed in reverse order, ensuring Release happens first.
         */
        struct RoApartmentScope
        {
            const ComBaseApi* api = nullptr;
            bool active = false;
            ~RoApartmentScope()
            {
                if (active && api != nullptr) {
                    api->roUninitialize();
                }
            }
        } roApartmentScope{ &api, kShouldUninitialize };

        HSTRING classId = nullptr;
        const wchar_t* const kClassName = L"Windows.Devices.Geolocation.Geolocator";
        HRESULT hr = api.windowsCreateString(
            kClassName, static_cast<UINT32>(::wcslen(kClassName)), &classId);
        if (FAILED(hr)) {
            result.failureText = QStringLiteral("创建 WinRT 类名失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IInspectable> inspectable;
        hr = api.roActivateInstance(classId, inspectable.GetAddressOf());
        api.windowsDeleteString(classId);
        if (FAILED(hr) || inspectable == nullptr) {
            result.failureText = QStringLiteral(
                "激活 Geolocator 失败：HRESULT=0x%1。位置服务被关闭或桌面应用未获授权时会出现这个错误。")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeolocator> geolocator;
        hr = inspectable.As(&geolocator);
        if (FAILED(hr) || geolocator == nullptr) {
            result.failureText = QStringLiteral("获取 IGeolocator 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }
        (void)geolocator->put_DesiredAccuracy(PositionAccuracy::PositionAccuracy_High);

        ComPtr<IAsyncOperation<Geoposition*>> operation;
        hr = geolocator->GetGeopositionAsync(operation.GetAddressOf());
        if (FAILED(hr) || operation == nullptr) {
            result.failureText = QStringLiteral("发起定位请求失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IAsyncInfo> asyncInfo;
        hr = operation.As(&asyncInfo);
        if (FAILED(hr) || asyncInfo == nullptr) {
            result.failureText = QStringLiteral("获取 IAsyncInfo 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        // Poll instead of awaiting the completion callback: callbacks must land on objects supporting free-threaded
        // marshaling, but we are already on a dedicated background thread; direct spinning is simpler and easier to cancel.
        const ULONGLONG kDeadlineTick = ::GetTickCount64() + timeoutMilliseconds;
        AsyncStatus asyncStatus = AsyncStatus::Started;
        while (true) {
            if (FAILED(asyncInfo->get_Status(&asyncStatus))) {
                break;
            }
            if (asyncStatus != AsyncStatus::Started) {
                break;
            }
            if (::GetTickCount64() >= kDeadlineTick) {
                (void)asyncInfo->Cancel();
                result.failureText = QStringLiteral("定位请求超时，系统在限定时间内没有返回坐标。");
                return result;
            }
            ::Sleep(50);
        }

        if (asyncStatus != AsyncStatus::Completed) {
            HRESULT errorCode = S_OK;
            (void)asyncInfo->get_ErrorCode(&errorCode);
            result.failureText = QStringLiteral("定位请求未完成：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(errorCode), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeoposition> geoposition;
        hr = operation->GetResults(geoposition.GetAddressOf());
        if (FAILED(hr) || geoposition == nullptr) {
            result.failureText = QStringLiteral("读取定位结果失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeocoordinate> geocoordinate;
        hr = geoposition->get_Coordinate(geocoordinate.GetAddressOf());
        if (FAILED(hr) || geocoordinate == nullptr) {
            result.failureText = QStringLiteral("读取坐标失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        // Latitude and longitude are retrieved only from IGeocoordinateWithPoint to avoid deprecated members on IGeocoordinate.
        // get_Latitude / get_Longitude。
        ComPtr<IGeocoordinateWithPoint> coordinateWithPoint;
        if (SUCCEEDED(geocoordinate.As(&coordinateWithPoint)) &&
            coordinateWithPoint != nullptr) {
            ComPtr<IGeopoint> geopoint;
            if (SUCCEEDED(coordinateWithPoint->get_Point(geopoint.GetAddressOf())) &&
                geopoint != nullptr) {
                BasicGeoposition basicPosition{};
                if (SUCCEEDED(geopoint->get_Position(&basicPosition))) {
                    result.coordinate.latitude = basicPosition.Latitude;
                    result.coordinate.longitude = basicPosition.Longitude;
                    result.coordinate.altitude = basicPosition.Altitude;
                    result.ok = true;
                }
            }
        }
        if (!result.ok) {
            result.failureText = QStringLiteral("系统返回的定位结果里没有可用的经纬度。");
            return result;
        }

        DOUBLE accuracy = 0.0;
        if (SUCCEEDED(geocoordinate->get_Accuracy(&accuracy))) {
            result.coordinate.errorRadiusMeters = accuracy;
        }
        ComPtr<IReference<double>> altitudeAccuracy;
        if (SUCCEEDED(geocoordinate->get_AltitudeAccuracy(altitudeAccuracy.GetAddressOf())) &&
            altitudeAccuracy != nullptr) {
            DOUBLE altitudeAccuracyValue = 0.0;
            if (SUCCEEDED(altitudeAccuracy->get_Value(&altitudeAccuracyValue))) {
                result.coordinate.altitudeAccuracyMeters = altitudeAccuracyValue;
            }
        }

        ComPtr<IGeocoordinateWithPositionData> coordinateWithPositionData;
        if (SUCCEEDED(geocoordinate.As(&coordinateWithPositionData)) &&
            coordinateWithPositionData != nullptr) {
            PositionSource source = PositionSource::PositionSource_Unknown;
            if (SUCCEEDED(coordinateWithPositionData->get_PositionSource(&source))) {
                result.sourceText = positionSourceText(source);
            }
        }
        if (result.sourceText.isEmpty()) {
            result.sourceText = QStringLiteral("未知来源");
        }

        return result;
    }

    GeoCoordinate convertCoordinate(
        const GeoCoordinate& source,
        const CoordinateSystem from,
        const CoordinateSystem to)
    {
        GeoCoordinate converted = source;
        if (from == to) {
            return converted;
        }

        // First normalize to the GCJ-02 intermediate state, then transform from there to the target coordinate system.
        double gcjLatitude = source.latitude;
        double gcjLongitude = source.longitude;
        switch (from) {
        case CoordinateSystem::kWgs84:
            wgs84ToGcj02(source.latitude, source.longitude, &gcjLatitude, &gcjLongitude);
            break;
        case CoordinateSystem::kBd09:
            bd09ToGcj02(source.latitude, source.longitude, &gcjLatitude, &gcjLongitude);
            break;
        case CoordinateSystem::kGcj02:
        default:
            break;
        }

        switch (to) {
        case CoordinateSystem::kWgs84:
            gcj02ToWgs84(gcjLatitude, gcjLongitude, &converted.latitude, &converted.longitude);
            break;
        case CoordinateSystem::kBd09:
            gcj02ToBd09(gcjLatitude, gcjLongitude, &converted.latitude, &converted.longitude);
            break;
        case CoordinateSystem::kGcj02:
        default:
            converted.latitude = gcjLatitude;
            converted.longitude = gcjLongitude;
            break;
        }
        return converted;
    }

    const PresetLocation* presetLocations(int* const countOut)
    {
        // Coordinates are always in WGS-84; when selecting a different coordinate system in the panel, conversion is performed first before repopulating the input field.
        static const PresetLocation kPresets[] = {
            { "misc.virtual_location.preset.beijing", "北京 天安门", 39.909187, 116.397451, 44.0 },
            { "misc.virtual_location.preset.shanghai", "上海 外滩", 31.239703, 121.484899, 4.0 },
            { "misc.virtual_location.preset.guangzhou", "广州 塔", 23.106414, 113.318977, 11.0 },
            { "misc.virtual_location.preset.shenzhen", "深圳 平安金融中心", 22.536970, 114.048262, 5.0 },
            { "misc.virtual_location.preset.chengdu", "成都 天府广场", 30.657378, 104.061981, 500.0 },
            { "misc.virtual_location.preset.hongkong", "香港 维多利亚港", 22.293321, 114.171387, 5.0 },
            { "misc.virtual_location.preset.taipei", "台北 101", 25.033551, 121.561028, 10.0 },
            { "misc.virtual_location.preset.tokyo", "东京 塔", 35.658580, 139.745433, 15.0 },
            { "misc.virtual_location.preset.singapore", "新加坡 滨海湾", 1.283404, 103.860530, 5.0 },
            { "misc.virtual_location.preset.london", "伦敦 大本钟", 51.500729, -0.124625, 11.0 },
            { "misc.virtual_location.preset.newyork", "纽约 时代广场", 40.758896, -73.985130, 10.0 },
            { "misc.virtual_location.preset.sanfrancisco", "旧金山 金门大桥", 37.819929, -122.478255, 67.0 },
        };
        if (countOut != nullptr) {
            *countOut = static_cast<int>(sizeof(kPresets) / sizeof(kPresets[0]));
        }
        return kPresets;
    }
}
