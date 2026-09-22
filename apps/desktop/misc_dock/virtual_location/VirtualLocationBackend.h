#pragma once

// ============================================================
// VirtualLocationBackend.h
// Purpose:
// 1) Read/write the Windows Location Service's "Default Location" (lfsvc DefaultLocation) registry key;
// 2) If R3 cannot open this key (its ACL only allows SYSTEM and lfsvc), automatically fall back to the KswordARK R0 registry IOCTL.
// 3) Aggregate location service runtime status, privacy toggle, and group policy to determine if virtual coordinates will actually be adopted.
// 4) Read the system's actual location response once via WinRT Geolocator for application-side comparison.
// 5) Provides conversion between WGS-84, GCJ-02, and BD-09 coordinates for convenient pasting of domestic map coordinates.
//
// This file handles only data and system access, with no QWidget dependencies; the UI resides in VirtualLocationPage.
// ============================================================

#include <QString>
#include <QStringList>

namespace ks::misc::virtual_location
{
    // CoordinateSystem：
    // - Purpose: Marks the geodetic coordinate system to which a set of latitude/longitude coordinates belongs.
    // - Wgs84 is the native coordinate system used by Windows Location Services and GPS; always convert to it before writing to the registry.
    enum class CoordinateSystem
    {
        kWgs84 = 0,  // Wgs84: international standard coordinate system; used directly by Windows location APIs.
        kGcj02 = 1,  // Gcj02: GCJ-02 encrypted coordinates obtained from Amap or Tencent Maps.
        kBd09 = 2    // Bd09: Coordinates offset again by Baidu on top of GCJ-02.
    };

    // RegistryBackend：
    // - Purpose: Record which channel successfully handled a registry access so the UI can inform the user who performed the operation.
    enum class RegistryBackend
    {
        kNone = 0,    // None: Neither channel succeeded.
        kWin32 = 1,   // Win32: R3 Advapi32 completes directly.
        kDriver = 2   // Driver: Completed by KswordARK R0 after R3 is denied by ACL.
    };

    // GeoCoordinate：
    // - Purpose: A set of location readings; fields other than latitude and longitude may be 0 to indicate the system did not provide that component.
    struct GeoCoordinate
    {
        double latitude = 0.0;               // latitude: Latitude in degrees; positive for North, negative for South.
        double longitude = 0.0;              // longitude: Longitude in degrees (positive for East, negative for West).
        double altitude = 0.0;               // altitude: Altitude in meters.
        double errorRadiusMeters = 0.0;      // errorRadiusMeters: Horizontal error radius in meters.
        double altitudeAccuracyMeters = 0.0; // altitudeAccuracyMeters: Vertical error in meters.
    };

    // DefaultLocationSnapshot：
    // - Purpose: Complete result of a single 'Default Location' registry read, including the original value list for user verification.
    struct DefaultLocationSnapshot
    {
        bool readable = false;          // readable: Whether the key was successfully opened and read.
        bool present = false;           // present: Whether usable latitude and longitude are already stored in the key.
        RegistryBackend backend = RegistryBackend::kNone; // backend: the channel successfully used for this read.
        GeoCoordinate coordinate;       // coordinate: The parsed coordinate; meaningless if present is false.
        QStringList rawValueLines;      // rawValueLines: A raw list of 'Name (Type) = Text' entries, one value per line.
        QString failureText;            // failureText: reason for failure when readable is false.
    };

    // ServiceSnapshot：
    // - Purpose: Determine all environmental states required to verify if virtual coordinates are effective.
    struct ServiceSnapshot
    {
        bool serviceQueryOk = false;      // serviceQueryOk: Indicates whether the lfsvc service was successfully queried.
        bool serviceRunning = false;      // serviceRunning: Whether the location service is currently running.
        QString serviceStateText;         // serviceStateText: Human-readable description of the service state.
        bool consentReadable = false;     // consentReadable: Whether the system location master switch was read.
        bool locationAllowed = false;     // locationAllowed: Whether the system location global switch is set to Allow.
        bool desktopAppAllowed = false;   // desktopAppAllowed: Whether desktop applications (NonPackaged) are allowed.
        bool providerDisabledByPolicy = false; // providerDisabledByPolicy: Whether group policy has disabled the Windows location provider.
        bool locationDisabledByPolicy = false; // locationDisabledByPolicy: Whether group policy has globally disabled location services.
        QString policyDetailText;         // policyDetailText: The literal description value of the policy item.
    };

    // LiveFixResult：
    // - Purpose: Request a single location result from WinRT Geolocator.
    struct LiveFixResult
    {
        bool ok = false;             // ok: Whether the coordinates were obtained.
        GeoCoordinate coordinate;    // coordinate: Coordinates returned by the system; meaningless if ok is false.
        QString sourceText;          // sourceText: Location source (satellite / cellular / WiFi / IP / default location).
        QString failureText;         // failureText: Failure reason when ok is false.
    };

    // OperationResult：
    // - Purpose: Unified result for a single write operation.
    struct OperationResult
    {
        bool ok = false;                                  // ok: Whether the operation succeeded.
        RegistryBackend backend = RegistryBackend::kNone;  // backend: The channel used on success.
        QString detailText;                               // detailText: failure reason or success supplementary explanation.
    };

    // defaultLocationKeyPath：
    // - Purpose: Return the HKLM key path for the 'default location' for direct display in the UI.
    // - Returns: Full path text without a trailing backslash.
    QString defaultLocationKeyPath();

    // sensorPolicyKeyPath：
    // - Purpose: Return the group policy key path related to location.
    // - Returns: Full path text without a trailing backslash.
    QString sensorPolicyKeyPath();

    // readDefaultLocation：
    // - Purpose: Read the current system default location; try R3 first, and automatically fall back to R0 if access is denied.
    // - Return: Snapshot; if readable is false, check failureText.
    DefaultLocationSnapshot readDefaultLocation();

    // applyDefaultLocation：
    // - Input coordinate: coordinate already converted to WGS-84;
    // - Purpose: Create a key and write Latitude, Longitude, Altitude, ErrorRadius, and AltitudeAccuracy;
    // - Returns: OperationResult; ok is true if all five values were written successfully.
    OperationResult applyDefaultLocation(const GeoCoordinate& coordinate);

    // clearDefaultLocation：
    // - Purpose: Remove the five values for the default location and restore the system to the state of 'no default location set'.
    // - Return: OperationResult; the key itself is not deleted to avoid affecting other subkeys maintained by lfsvc.
    OperationResult clearDefaultLocation();

    // readServiceSnapshot：
    // - Purpose: Query lfsvc status, privacy toggle, and group policy; all read-only.
    // - Returns: ServiceSnapshot; if any item cannot be read, the corresponding *Readable flag indicates it.
    ServiceSnapshot readServiceSnapshot();

    // setLocationProviderDisabled：
    // - Input disabled: write DisableWindowsLocationProvider=1 if true; delete the value if false.
    // - Purpose: Disable the built-in Windows network location provider to force location queries to fall back to the default location.
    // - Return: OperationResult. This affects the entire system; the caller must confirm with the user first.
    OperationResult setLocationProviderDisabled(bool disabled);

    // restartLocationService：
    // - Purpose: stop lfsvc to discard in-process location cache; the service itself is triggered on demand and will auto-start on the next application request.
    // - Return: OperationResult; ok is true if the service was stopped or was not running.
    OperationResult restartLocationService();

    // queryLiveFix：
    // - Input timeoutMilliseconds: upper limit for waiting on WinRT async location;
    // - Purpose: Synchronously requests a single location fix from Geolocator within the calling thread to confirm if the virtual coordinate is accepted;
    // - Returns: LiveFixResult. This function blocks and must be called from a background thread.
    LiveFixResult queryLiveFix(unsigned long timeoutMilliseconds);

    // convertCoordinate：
    // - Input source: Source coordinate; from/to: Source and target coordinate systems;
    // - Purpose: convert between WGS-84 / GCJ-02 / BD-09; only latitude/longitude are modified, other components remain unchanged.
    // - Return: Coordinates in the target coordinate system. Outside mainland China, the three systems are equivalent; return the original value directly.
    GeoCoordinate convertCoordinate(
        const GeoCoordinate& source,
        CoordinateSystem from,
        CoordinateSystem to);

    // PresetLocation：
    // - Purpose: Preset coordinate points; latitude and longitude are always recorded in WGS-84.
    struct PresetLocation
    {
        const char* nameKey;   // nameKey: i18n semantic key.
        const char* nameText;  // nameText: Chinese name, serving as a fallback when the English name is missing.
        double latitude;       // latitude: WGS-84 latitude.
        double longitude;      // longitude: WGS-84 longitude.
        double altitude;       // altitude: reference altitude, unit meters.
    };

    // presetLocations：
    // - Purpose: Return the built-in preset location table and its length.
    // - Output countOut: table length;
    // - Returns: Address of the first element of the static read-only array.
    const PresetLocation* presetLocations(int* countOut);
}
