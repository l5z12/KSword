#pragma once

// ============================================================
// ksword/startup/startup_internal.h
// Namespace: ks::startup::detail
// Purpose:
// - Share the registry/entry plumbing that startup.cpp already implements.
// - Let sibling translation units (startup_hidden.cpp) build StartupEntry records
//   with exactly the same location text, risk wording and action locators.
// - This header is backend-internal: no UI layer may include it.
// ============================================================

#include "Startup.h" // ks::startup::StartupEntry and the public enums it carries.

#ifndef NOMINMAX
#define NOMINMAX // Windows.h must not define the min/max macros; <algorithm> users depend on that.
#endif
#include <Windows.h>      // HKEY, DWORD and the registry API types used across the helpers.
#include <ShTypes.h>      // KNOWNFOLDERID: the GUID alias KnownFolders.h constants are typed with.
#include <KnownFolders.h> // FOLDERID_*: identifies shell folders without trusting %ENV%.

#include <cstdint> // std::uint8_t: raw registry data bytes.
#include <optional> // std::optional: "value may be absent" registry reads.
#include <string>  // std::string / std::wstring: UTF-8 storage and Win32 boundary text.
#include <vector>  // std::vector: value/subkey collections.

namespace ks::startup::detail
{
    // RegistryValueRecord:
    // - Purpose: one registry value converted to UTF-8 display text plus its raw bytes.
    // - valueNameText: UTF-8 value name; empty means the key default value.
    // - valueDataText: display text produced by registryDataToText.
    // - valueType: original REG_* type, preserved so a disable/restore keeps fidelity.
    // - rawData: untouched bytes, used as the rollback snapshot for reversible actions.
    struct RegistryValueRecord
    {
        std::string valueNameText;
        std::string valueDataText;
        DWORD valueType = REG_NONE;
        std::vector<std::uint8_t> rawData;
    };

    // ===================== Text helpers =====================

    // FromWide: converts a UTF-16 Win32 string into the UTF-8 text the backend stores.
    std::string fromWide(const std::wstring& text);

    // ToWide: converts backend UTF-8 text back into UTF-16 for Win32 calls.
    std::wstring toWide(const std::string& text);

    // TrimWide: removes leading/trailing whitespace from UTF-16 text.
    std::wstring trimWide(const std::wstring& text);

    // lowerWideCopy: lowercases UTF-16 text for case-insensitive comparison keys.
    std::wstring lowerWideCopy(std::wstring text);

    // lowerAsciiCopy: lowercases ASCII ranges only, leaving UTF-8 multibyte sequences untouched.
    std::string lowerAsciiCopy(std::string text);

    // startsWithI: case-insensitive ASCII prefix test.
    bool startsWithI(const std::string& text, const std::string& prefix);

    // endsWithI: case-insensitive UTF-16 suffix test.
    bool endsWithI(const std::wstring& text, const std::wstring& suffix);

    // toNativeSeparators: normalizes forward slashes into backslashes for display paths.
    std::string toNativeSeparators(std::string text);

    // expandEnvironmentWide: expands %VAR% references; returns the input when expansion fails.
    std::wstring expandEnvironmentWide(const std::wstring& text);

    // queryEnvironmentWide: reads one environment variable; returns empty when unset.
    std::wstring queryEnvironmentWide(const wchar_t* name);

    // knownFolderPath: resolves a shell folder without trusting caller-controlled environment text.
    std::wstring knownFolderPath(const KNOWNFOLDERID& folderId);

    // appendDetailPart: appends one diagnostics fragment to detailText using the shared separator.
    void appendDetailPart(std::string& detailText, const std::string& partText);

    // joinStrings: joins values with separator; used for multi-string registry data.
    std::string joinStrings(const std::vector<std::string>& values, const std::string& separator);

    // fileExists: reports whether the path resolves to an existing file system object.
    bool fileExists(const std::string& pathText);

    // formatBinaryText: renders REG_BINARY style payloads as a bounded hex preview.
    std::string formatBinaryText(const std::vector<std::uint8_t>& rawBuffer);

    // ===================== Registry helpers =====================

    // rootKeyText: maps a supported hive handle to its HKLM/HKCU/HKCR display prefix.
    std::string rootKeyText(HKEY rootKey);

    // buildRegistryLocationText: builds the exact "HKLM\Sub\Key" syntax the UI actions parse.
    std::string buildRegistryLocationText(HKEY rootKey, const std::wstring& subKeyText);

    // equalWideI: ordinal case-insensitive comparison used for locator equality, not display.
    bool equalWideI(const std::wstring& left, const std::wstring& right);

    // registryWideStringFromBuffer: decodes REG_SZ/REG_EXPAND_SZ bytes without trusting termination.
    std::wstring registryWideStringFromBuffer(const std::vector<std::uint8_t>& rawBuffer);

    // registryDataToText: converts any common REG_* payload into compact UTF-8 display text.
    std::string registryDataToText(DWORD valueType, const std::vector<std::uint8_t>& rawBuffer);

    // queryRegistryValueRecord: reads one named (or default) value; nullopt when absent or unreadable.
    std::optional<RegistryValueRecord> queryRegistryValueRecord(
        HKEY rootKey,
        const std::wstring& subKeyText,
        const std::wstring& valueNameText);

    // enumerateRegistryValues: lists every value under a key; unreadable keys simply yield no rows.
    std::vector<RegistryValueRecord> enumerateRegistryValues(HKEY rootKey, const std::wstring& subKeyText);

    // enumerateRegistrySubKeys: lists first-level subkey names under a key.
    std::vector<std::wstring> enumerateRegistrySubKeys(HKEY rootKey, const std::wstring& subKeyText);

    // ===================== COM helpers =====================

    // isClsidText: relaxed "{GUID}" shape test shared by every COM-backed persistence family.
    bool isClsidText(const std::string& text);

    // queryClsidFriendlyName: reads the HKCR CLSID default value, or empty when unnamed.
    std::string queryClsidFriendlyName(const std::string& clsidText);

    // queryClsidServerPath: resolves InprocServer32/LocalServer32 into a normalized image path.
    std::string queryClsidServerPath(const std::string& clsidText);

    // ===================== StartupEntry configuration =====================

    // markEntryActionUnavailable: clears every action locator so synthetic rows cannot be mutated.
    void markEntryActionUnavailable(
        StartupEntry& entry,
        StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText);

    // configureRegistryValueAction: wires the reversible "disable this registry value" action.
    void configureRegistryValueAction(
        StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText,
        const RegistryValueRecord& valueRecord,
        StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText);

    // configureRegistryTreeDeletion: wires the "delete the whole subkey" action with a stale-check snapshot.
    void configureRegistryTreeDeletion(
        StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText);

    // finalizeRegistryEntry: fills command text, resolved image path, publisher and deletion metadata.
    void finalizeRegistryEntry(
        StartupEntry& entry,
        const std::string& rawCommandText,
        const std::string& fallbackClsidText,
        const std::string& registryValueNameText,
        bool deleteRegistryTree,
        bool resolveClsidFromValueData);
}
