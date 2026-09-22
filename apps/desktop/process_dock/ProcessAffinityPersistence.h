#pragma once

// ============================================================
// ProcessAffinityPersistence.h
// Purpose:
// - Write the user-saved CPU affinity for the process to the current user registry.
// - Uses versioned REG_BINARY to save processor group/logic processor coordinates;
// - Compatible with reading legacy REG_QWORD bitmaps and automatically migrates after successful restoration.
// ============================================================

#include "ProcessAffinityUtils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace ks::process
{
    inline constexpr wchar_t kProcessAffinityRegistrySubKey[] =
        L"Software\\Ksword\\ProcessAffinity";

    // utf8ToWide: Converts the full process UTF-8 path to a registry value name.
    inline std::wstring utf8ToWide(const std::string& text)
    {
        if (text.empty())
        {
            return {};
        }

        const int kCharacterCount = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0);
        if (kCharacterCount <= 0)
        {
            return {};
        }

        std::wstring result(static_cast<std::size_t>(kCharacterCount), L'\0');
        if (::MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(text.size()),
                result.data(),
                kCharacterCount) != kCharacterCount)
        {
            return {};
        }
        return result;
    }

    // loadPersistedProcessAffinityRule:
    // - Reads the current version REG_BINARY.
    // - Convert legacy REG_QWORD to stable coordinates using legacyProcessorGroupHint, but do not write back.
    inline bool loadPersistedProcessAffinityRule(
        const std::string& imagePath,
        ProcessAffinityRule* const affinityRuleOut,
        bool* const foundOut,
        std::string* const detailTextOut,
        const std::uint16_t legacyProcessorGroupHint = 0U)
    {
        if (affinityRuleOut == nullptr || foundOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid persisted affinity read output";
            }
            return false;
        }

        *affinityRuleOut = ProcessAffinityRule{};
        *foundOut = false;
        const std::wstring kValueName = utf8ToWide(imagePath);
        if (kValueName.empty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process image path is unavailable";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            KEY_QUERY_VALUE,
            &registryKey);
        if (kOpenResult == ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (kOpenResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegOpenKeyExW failed(" +
                    std::to_string(kOpenResult) + ")";
            }
            return false;
        }

        DWORD valueType = 0U;
        DWORD storedSize = 0U;
        LONG queryResult = ::RegQueryValueExW(
            registryKey,
            kValueName.c_str(),
            nullptr,
            &valueType,
            nullptr,
            &storedSize);
        if (queryResult == ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegQueryValueExW(size) failed(" +
                    std::to_string(queryResult) + ")";
            }
            return false;
        }

        const DWORD kMaximumStoredSize = static_cast<DWORD>(
            kProcessAffinityRuleHeaderSize +
            kProcessAffinityRuleMaximumProcessorCount *
                kProcessAffinityRuleCoordinateSize);
        if ((valueType == REG_QWORD && storedSize != sizeof(std::uint64_t)) ||
            (valueType == REG_BINARY &&
                (storedSize < kProcessAffinityRuleHeaderSize ||
                    storedSize > kMaximumStoredSize)) ||
            (valueType != REG_QWORD && valueType != REG_BINARY))
        {
            ::RegCloseKey(registryKey);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "persisted affinity value type or size is invalid";
            }
            return false;
        }

        std::vector<std::uint8_t> storedBytes(storedSize, 0U);
        DWORD readSize = storedSize;
        queryResult = ::RegQueryValueExW(
            registryKey,
            kValueName.c_str(),
            nullptr,
            &valueType,
            storedBytes.data(),
            &readSize);
        ::RegCloseKey(registryKey);
        if (queryResult != ERROR_SUCCESS || readSize != storedSize)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegQueryValueExW(data) failed(" +
                    std::to_string(queryResult) + ")";
            }
            return false;
        }

        ProcessAffinityRule affinityRule;
        if (valueType == REG_QWORD)
        {
            std::uint64_t legacyMask = 0U;
            std::memcpy(
                &legacyMask,
                storedBytes.data(),
                sizeof(legacyMask));
            if (legacyMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "persisted legacy affinity mask is empty";
                }
                return false;
            }
            affinityRule = affinityRuleFromLegacyMask(
                legacyMask,
                legacyProcessorGroupHint);
        }
        else if (!deserializeProcessAffinityRule(
                     storedBytes,
                     &affinityRule))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "persisted affinity rule is invalid or unsupported";
            }
            return false;
        }

        *affinityRuleOut = std::move(affinityRule);
        *foundOut = true;
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // savePersistedProcessAffinityRule purpose: Atomically replace a single path rule with current version REG_BINARY.
    inline bool savePersistedProcessAffinityRule(
        const std::string& imagePath,
        const ProcessAffinityRule& affinityRule,
        std::string* const detailTextOut)
    {
        const std::wstring kValueName = utf8ToWide(imagePath);
        std::vector<std::uint8_t> storedBytes;
        if (kValueName.empty() ||
            !serializeProcessAffinityRule(affinityRule, &storedBytes))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "process image path or affinity rule is invalid";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG kCreateResult = ::RegCreateKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &registryKey,
            nullptr);
        if (kCreateResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegCreateKeyExW failed(" +
                    std::to_string(kCreateResult) + ")";
            }
            return false;
        }

        const LONG kSetResult = ::RegSetValueExW(
            registryKey,
            kValueName.c_str(),
            0U,
            REG_BINARY,
            storedBytes.data(),
            static_cast<DWORD>(storedBytes.size()));
        ::RegCloseKey(registryKey);
        if (kSetResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegSetValueExW failed(" +
                    std::to_string(kSetResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // removePersistedProcessAffinityRule: Removes a Ksword private rule for the specified full path.
    inline bool removePersistedProcessAffinityRule(
        const std::string& imagePath,
        std::string* const detailTextOut)
    {
        const std::wstring kValueName = utf8ToWide(imagePath);
        if (kValueName.empty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process image path is unavailable";
            }
            return false;
        }

        HKEY registryKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kProcessAffinityRegistrySubKey,
            0U,
            KEY_SET_VALUE,
            &registryKey);
        if (kOpenResult == ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
        if (kOpenResult != ERROR_SUCCESS)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegOpenKeyExW failed(" +
                    std::to_string(kOpenResult) + ")";
            }
            return false;
        }

        const LONG kDeleteResult =
            ::RegDeleteValueW(registryKey, kValueName.c_str());
        ::RegCloseKey(registryKey);
        if (kDeleteResult != ERROR_SUCCESS &&
            kDeleteResult != ERROR_FILE_NOT_FOUND)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "RegDeleteValueW failed(" +
                    std::to_string(kDeleteResult) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // inferLegacyAffinityGroup:
    // - Legacy QWORDs lack a group field;
    // - Uses the current group if the selection falls within a single group; otherwise, uses group 0 per legacy default semantics.
    inline std::uint16_t inferLegacyAffinityGroup(
        const ProcessAffinitySnapshot& snapshot)
    {
        std::set<std::uint16_t> selectedGroups;
        for (const LogicalProcessorState& processor : snapshot.processors)
        {
            if (processor.available && processor.selected)
            {
                selectedGroups.insert(processor.coordinate.group);
            }
        }
        return selectedGroups.size() == 1U
            ? *selectedGroups.begin()
            : 0U;
    }

    // filterAffinityRuleForTopology purpose: filter out non-existent coordinates on the current machine to prevent restoring an empty selection.
    inline bool filterAffinityRuleForTopology(
        const ProcessAffinityRule& sourceRule,
        const ProcessAffinitySnapshot& snapshot,
        ProcessAffinityRule* const applicableRuleOut,
        std::size_t* const missingCoordinateCountOut)
    {
        if (applicableRuleOut == nullptr)
        {
            return false;
        }
        if (missingCoordinateCountOut != nullptr)
        {
            *missingCoordinateCountOut = 0U;
        }

        ProcessAffinityRule applicableRule = sourceRule;
        applicableRule.migratedFromLegacyQword = false;
        if (!applicableRule.selectAllAvailable)
        {
            normalizeLogicalProcessorCoordinates(
                &applicableRule.processors);
            std::size_t missingCoordinateCount = 0U;
            for (const LogicalProcessorCoordinate& coordinate :
                 applicableRule.processors)
            {
                const bool kCoordinateAvailable = std::any_of(
                    snapshot.processors.begin(),
                    snapshot.processors.end(),
                    [&coordinate](const LogicalProcessorState& processor)
                    {
                        return processor.available &&
                            processor.coordinate == coordinate;
                    });
                if (!kCoordinateAvailable)
                {
                    ++missingCoordinateCount;
                }
            }
            if (missingCoordinateCountOut != nullptr)
            {
                *missingCoordinateCountOut = missingCoordinateCount;
            }
            // Do not silently reduce rules: a subset after topology changes might leave only one processor and unexpectedly lock the target.
            if (applicableRule.processors.empty() ||
                missingCoordinateCount != 0U)
            {
                return false;
            }
        }
        *applicableRuleOut = std::move(applicableRule);
        return true;
    }

    // restorePersistedProcessAffinityRule:
    // - Maps stable coordinates to the current boot CPU Set ID and restores them;
    // - The old QWORD is automatically upgraded to a versioned REG_BINARY after successful application.
    inline bool restorePersistedProcessAffinityRule(
        const DWORD processId,
        const std::string& imagePath,
        bool* const ruleFoundOut,
        std::string* const detailTextOut)
    {
        if (ruleFoundOut != nullptr)
        {
            *ruleFoundOut = false;
        }

        ProcessAffinityRule storedRule;
        bool ruleFound = false;
        if (!loadPersistedProcessAffinityRule(
                imagePath,
                &storedRule,
                &ruleFound,
                detailTextOut))
        {
            return false;
        }
        if (ruleFoundOut != nullptr)
        {
            *ruleFoundOut = ruleFound;
        }
        if (!ruleFound)
        {
            return true;
        }

        ProcessAffinitySnapshot snapshot;
        if (!queryProcessAffinityState(
                processId,
                &snapshot,
                detailTextOut))
        {
            return false;
        }

        if (storedRule.migratedFromLegacyQword)
        {
            const std::uint16_t kLegacyGroup =
                inferLegacyAffinityGroup(snapshot);
            for (LogicalProcessorCoordinate& coordinate :
                 storedRule.processors)
            {
                coordinate.group = kLegacyGroup;
            }
        }

        ProcessAffinityRule applicableRule;
        std::size_t missingCoordinateCount = 0U;
        if (!filterAffinityRuleForTopology(
                storedRule,
                snapshot,
                &applicableRule,
                &missingCoordinateCount))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = missingCoordinateCount == 0U
                    ? "saved affinity has no logical processor in the current topology"
                    : "saved affinity topology changed; refusing partial restore because " +
                        std::to_string(missingCoordinateCount) +
                        " processor coordinate(s) are unavailable";
            }
            return false;
        }

        if (!setProcessAffinityRuleByPid(
                processId,
                applicableRule,
                detailTextOut))
        {
            return false;
        }

        if (storedRule.migratedFromLegacyQword &&
            !savePersistedProcessAffinityRule(
                imagePath,
                applicableRule,
                detailTextOut))
        {
            return false;
        }
        return true;
    }
}
