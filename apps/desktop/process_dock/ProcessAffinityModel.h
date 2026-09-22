#pragma once

// ============================================================
// ProcessAffinityModel.h
// Purpose:
// - Define processor group/logical processor coordinates decoupled from Windows CPU Set IDs;
// - Provide pure-function serialization of versioned persistent data, old QWORD migration, and topology remapping;
// - Does not depend on Qt or Windows APIs, enabling verification of multiple behavior sets using temporary harnesses.
// ============================================================

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace ks::process
{
    inline constexpr std::uint16_t kProcessAffinityRuleVersion = 1U;
    inline constexpr std::uint32_t kProcessAffinityRuleMagic = 0x4641534BU; // Little-endian byte order is "KSAF".
    inline constexpr std::uint16_t kProcessAffinityRuleSelectAllFlag = 0x0001U;
    inline constexpr std::size_t kProcessAffinityRuleHeaderSize = 12U;
    inline constexpr std::size_t kProcessAffinityRuleCoordinateSize = 4U;
    inline constexpr std::size_t kProcessAffinityRuleMaximumProcessorCount = 4096U;

    // LogicalProcessorCoordinate:
    // - group stores the Windows processor group;
    // - logicalIndex stores the logical processor index within this group, independent of temporary CPU Set IDs across reboots.
    struct LogicalProcessorCoordinate
    {
        std::uint16_t group = 0U;
        std::uint16_t logicalIndex = 0U;
    };

    inline bool operator==(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group == right.group &&
            left.logicalIndex == right.logicalIndex;
    }

    inline bool operator<(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group < right.group ||
            (left.group == right.group && left.logicalIndex < right.logicalIndex);
    }

    // processorCoordinateAllowedByLegacyAffinity:
    // - Calculate the actual intersection between the CPU Set and the readable single-group/legacy hard affinity;
    // - Without hard constraints, do not reduce the available set for cross-group processes with the Win11 default.
    inline bool processorCoordinateAllowedByLegacyAffinity(
        const LogicalProcessorCoordinate& coordinate,
        const bool legacyConstraintAvailable,
        const std::uint16_t legacyProcessorGroup,
        const std::uint64_t legacyProcessorMask)
    {
        if (!legacyConstraintAvailable)
        {
            return true;
        }
        return coordinate.group == legacyProcessorGroup &&
            coordinate.logicalIndex < 64U &&
            (legacyProcessorMask &
                (1ULL << coordinate.logicalIndex)) != 0U;
    }

    // LogicalProcessorState:
    // - Describes the mapping between a runtime-queried CPU set and stable coordinates.
    // - selected: Indicates whether this processor is selected under the current process's default CPU Set or legacy affinity constraints.
    struct LogicalProcessorState
    {
        LogicalProcessorCoordinate coordinate;
        std::uint32_t cpuSetId = 0U;
        std::uint16_t coreIndex = 0U;
        std::uint8_t efficiencyClass = 0U;
        bool available = false;
        bool selected = false;
        bool parked = false;
        bool allocated = false;
        bool allocatedToTargetProcess = false;
        bool constrainedByHardAffinity = false;
        std::string topologyLabel;
    };

    // ProcessAffinitySnapshot purpose: holds a process affinity snapshot shared between the UI and the persistence layer.
    struct ProcessAffinitySnapshot
    {
        std::vector<LogicalProcessorState> processors;
        bool usesCpuSets = false;
        bool unrestricted = false;
    };

    // logicalProcessorGroupCount:
    // - Count the number of unique processor groups actually displayed in the current UI.
    // - When in a single group, omitting the repeated Gx prefix and group header is allowed; when in multiple groups, the unambiguous identity is still preserved.
    inline std::size_t logicalProcessorGroupCount(
        const std::vector<LogicalProcessorCoordinate>& coordinates)
    {
        std::vector<std::uint16_t> processorGroups;
        processorGroups.reserve(coordinates.size());
        for (const LogicalProcessorCoordinate& coordinate : coordinates)
        {
            processorGroups.push_back(coordinate.group);
        }
        std::sort(processorGroups.begin(), processorGroups.end());
        processorGroups.erase(
            std::unique(processorGroups.begin(), processorGroups.end()),
            processorGroups.end());
        return processorGroups.size();
    }

    inline std::size_t logicalProcessorGroupCount(
        const std::vector<LogicalProcessorState>& processors)
    {
        std::vector<LogicalProcessorCoordinate> coordinates;
        coordinates.reserve(processors.size());
        for (const LogicalProcessorState& processor : processors)
        {
            coordinates.push_back(processor.coordinate);
        }
        return logicalProcessorGroupCount(coordinates);
    }

    // processorDisplayIdentityText:
    // - Logs and persistence continue using the stable full Gx:Ly identity;
    // - Display Gx only when the UI confirms multiple processor groups exist; simplify to Ly for a single group.
    inline std::string processorDisplayIdentityText(
        const LogicalProcessorCoordinate& coordinate,
        const bool includeProcessorGroup)
    {
        const std::string kLogicalProcessorText =
            "L" + std::to_string(coordinate.logicalIndex);
        return includeProcessorGroup
            ? "G" + std::to_string(coordinate.group) + ":" +
                kLogicalProcessorText
            : kLogicalProcessorText;
    }

    // ProcessAffinityRule:
    // - selectAllAvailable=true clears the process's default CPU Set restrictions and follows the currently available processors;
    // - processors stores the stable group/index coordinates when explicitly selected;
    // - migratedFromLegacyQword is used only for migration judgment after this read and is not written to persistent bytes.
    struct ProcessAffinityRule
    {
        std::uint16_t schemaVersion = kProcessAffinityRuleVersion;
        bool selectAllAvailable = false;
        std::vector<LogicalProcessorCoordinate> processors;
        bool migratedFromLegacyQword = false;
    };

    // normalizeLogicalProcessorCoordinates: Sorts and deduplicates coordinates to ensure stability in UI, persistence, and comparison results.
    inline void normalizeLogicalProcessorCoordinates(
        std::vector<LogicalProcessorCoordinate>* const coordinates)
    {
        if (coordinates == nullptr)
        {
            return;
        }
        std::sort(coordinates->begin(), coordinates->end());
        coordinates->erase(
            std::unique(coordinates->begin(), coordinates->end()),
            coordinates->end());
    }

    // containsLogicalProcessorCoordinate: Check if the coordinate list contains the specified group/index.
    inline bool containsLogicalProcessorCoordinate(
        const std::vector<LogicalProcessorCoordinate>& coordinates,
        const LogicalProcessorCoordinate& coordinate)
    {
        return std::find(coordinates.begin(), coordinates.end(), coordinate) !=
            coordinates.end();
    }

    // selectAllCpuSetSelectionMatches:
    // - selectAll only indicates clearing the process's default CPU Set list.
    // - Processor group, thread affinity, and job constraints form independent intersections; snapshots cannot be required to be globally unrestricted.
    inline bool selectAllCpuSetSelectionMatches(
        const ProcessAffinityRule& rule,
        const std::vector<std::uint32_t>& defaultCpuSetIds)
    {
        return rule.selectAllAvailable &&
            defaultCpuSetIds.empty();
    }

    // affinityRuleFromSnapshot:
    // - Convert the current runtime snapshot into a saveable rule.
    // - Unrestricted state retains the 'all available' semantics; explicit states store only selected and available stable coordinates.
    inline ProcessAffinityRule affinityRuleFromSnapshot(
        const ProcessAffinitySnapshot& snapshot)
    {
        ProcessAffinityRule rule;
        rule.selectAllAvailable = snapshot.unrestricted;
        if (!rule.selectAllAvailable)
        {
            for (const LogicalProcessorState& processor : snapshot.processors)
            {
                if (processor.available && processor.selected)
                {
                    rule.processors.push_back(processor.coordinate);
                }
            }
            normalizeLogicalProcessorCoordinates(&rule.processors);
        }
        return rule;
    }

    // affinityRuleFromLegacyMask:
    // - Migrate the legacy REG_QWORD bitmap to stable logical processor coordinates within the specified processor group;
    // - Returns a rule with the migratedFromLegacyQword flag set, enabling automatic registry format upgrade after successful restoration.
    inline ProcessAffinityRule affinityRuleFromLegacyMask(
        const std::uint64_t legacyMask,
        const std::uint16_t processorGroup)
    {
        ProcessAffinityRule rule;
        rule.migratedFromLegacyQword = true;
        for (std::uint16_t logicalIndex = 0U; logicalIndex < 64U; ++logicalIndex)
        {
            const std::uint64_t kProcessorBit = 1ULL << logicalIndex;
            if ((legacyMask & kProcessorBit) != 0U)
            {
                rule.processors.push_back(
                    LogicalProcessorCoordinate{ processorGroup, logicalIndex });
            }
        }
        return rule;
    }

    // appendAffinityUnsigned purpose: writes unsigned integers to the persistent buffer in a fixed little-endian order.
    inline void appendAffinityUnsigned(
        std::vector<std::uint8_t>* const bytes,
        const std::uint64_t value,
        const std::size_t byteCount)
    {
        if (bytes == nullptr)
        {
            return;
        }
        for (std::size_t byteIndex = 0U; byteIndex < byteCount; ++byteIndex)
        {
            bytes->push_back(static_cast<std::uint8_t>(
                (value >> (byteIndex * 8U)) & 0xFFU));
        }
    }

    // readAffinityUnsigned: Reads an unsigned integer from a fixed little-endian buffer and advances the offset.
    inline bool readAffinityUnsigned(
        const std::vector<std::uint8_t>& bytes,
        std::size_t* const offset,
        const std::size_t byteCount,
        std::uint64_t* const valueOut)
    {
        if (offset == nullptr || valueOut == nullptr ||
            *offset > bytes.size() || byteCount > bytes.size() - *offset)
        {
            return false;
        }

        std::uint64_t value = 0U;
        for (std::size_t byteIndex = 0U; byteIndex < byteCount; ++byteIndex)
        {
            value |= static_cast<std::uint64_t>(bytes[*offset + byteIndex]) <<
                (byteIndex * 8U);
        }
        *offset += byteCount;
        *valueOut = value;
        return true;
    }

    // serializeProcessAffinityRule:
    // - Encodes version, flags, and stable coordinates into REG_BINARY data;
    // - Returns false on explicit null selection, out-of-bounds logical index, or oversized list.
    inline bool serializeProcessAffinityRule(
        const ProcessAffinityRule& sourceRule,
        std::vector<std::uint8_t>* const bytesOut)
    {
        if (bytesOut == nullptr)
        {
            return false;
        }

        ProcessAffinityRule rule = sourceRule;
        normalizeLogicalProcessorCoordinates(&rule.processors);
        if (rule.selectAllAvailable)
        {
            // "All available" is fully expressed by flags; persistence does not carry invalid coordinates, ensuring a unique byte representation.
            rule.processors.clear();
        }
        if (rule.schemaVersion != kProcessAffinityRuleVersion ||
            (!rule.selectAllAvailable && rule.processors.empty()) ||
            rule.processors.size() > kProcessAffinityRuleMaximumProcessorCount)
        {
            bytesOut->clear();
            return false;
        }
        for (const LogicalProcessorCoordinate& coordinate : rule.processors)
        {
            if (coordinate.logicalIndex >= 64U)
            {
                bytesOut->clear();
                return false;
            }
        }

        bytesOut->clear();
        bytesOut->reserve(
            kProcessAffinityRuleHeaderSize +
            rule.processors.size() * kProcessAffinityRuleCoordinateSize);
        appendAffinityUnsigned(bytesOut, kProcessAffinityRuleMagic, sizeof(std::uint32_t));
        appendAffinityUnsigned(bytesOut, rule.schemaVersion, sizeof(std::uint16_t));
        appendAffinityUnsigned(
            bytesOut,
            rule.selectAllAvailable ? kProcessAffinityRuleSelectAllFlag : 0U,
            sizeof(std::uint16_t));
        appendAffinityUnsigned(
            bytesOut,
            static_cast<std::uint32_t>(rule.processors.size()),
            sizeof(std::uint32_t));
        for (const LogicalProcessorCoordinate& coordinate : rule.processors)
        {
            appendAffinityUnsigned(bytesOut, coordinate.group, sizeof(std::uint16_t));
            appendAffinityUnsigned(bytesOut, coordinate.logicalIndex, sizeof(std::uint16_t));
        }
        return true;
    }

    // deserializeProcessAffinityRule:
    // - Strictly parse current version REG_BINARY data;
    // - Reject unknown flags, invalid coordinates other than duplicates, truncated data, or trailing bytes to prevent silent misapplication.
    inline bool deserializeProcessAffinityRule(
        const std::vector<std::uint8_t>& bytes,
        ProcessAffinityRule* const ruleOut)
    {
        if (ruleOut == nullptr || bytes.size() < kProcessAffinityRuleHeaderSize)
        {
            return false;
        }

        std::size_t offset = 0U;
        std::uint64_t magic = 0U;
        std::uint64_t version = 0U;
        std::uint64_t flags = 0U;
        std::uint64_t processorCount = 0U;
        if (!readAffinityUnsigned(bytes, &offset, sizeof(std::uint32_t), &magic) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &version) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &flags) ||
            !readAffinityUnsigned(bytes, &offset, sizeof(std::uint32_t), &processorCount))
        {
            return false;
        }

        const bool kSelectAllAvailable =
            (flags & kProcessAffinityRuleSelectAllFlag) != 0U;
        const std::size_t kExpectedSize =
            kProcessAffinityRuleHeaderSize +
            static_cast<std::size_t>(processorCount) *
                kProcessAffinityRuleCoordinateSize;
        if (magic != kProcessAffinityRuleMagic ||
            version != kProcessAffinityRuleVersion ||
            (flags & ~static_cast<std::uint64_t>(kProcessAffinityRuleSelectAllFlag)) != 0U ||
            processorCount > kProcessAffinityRuleMaximumProcessorCount ||
            kExpectedSize != bytes.size() ||
            (kSelectAllAvailable && processorCount != 0U) ||
            (!kSelectAllAvailable && processorCount == 0U))
        {
            return false;
        }

        ProcessAffinityRule rule;
        rule.schemaVersion = static_cast<std::uint16_t>(version);
        rule.selectAllAvailable = kSelectAllAvailable;
        rule.processors.reserve(static_cast<std::size_t>(processorCount));
        for (std::size_t processorIndex = 0U;
             processorIndex < static_cast<std::size_t>(processorCount);
             ++processorIndex)
        {
            std::uint64_t group = 0U;
            std::uint64_t logicalIndex = 0U;
            if (!readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &group) ||
                !readAffinityUnsigned(bytes, &offset, sizeof(std::uint16_t), &logicalIndex) ||
                logicalIndex >= 64U)
            {
                return false;
            }
            rule.processors.push_back(LogicalProcessorCoordinate{
                static_cast<std::uint16_t>(group),
                static_cast<std::uint16_t>(logicalIndex)
            });
        }
        normalizeLogicalProcessorCoordinates(&rule.processors);
        *ruleOut = std::move(rule);
        return true;
    }

    // remapAffinityRuleToCpuSetIds:
    // - Look up the CPU Set ID for this startup using stable group/index coordinates in the current topology.
    // - Allows returning partial mapping results while explicitly reporting missing coordinates via missingCoordinatesOut.
    inline bool remapAffinityRuleToCpuSetIds(
        const ProcessAffinityRule& rule,
        const std::vector<LogicalProcessorState>& currentTopology,
        std::vector<std::uint32_t>* const cpuSetIdsOut,
        std::vector<LogicalProcessorCoordinate>* const missingCoordinatesOut)
    {
        if (cpuSetIdsOut == nullptr)
        {
            return false;
        }

        cpuSetIdsOut->clear();
        if (missingCoordinatesOut != nullptr)
        {
            missingCoordinatesOut->clear();
        }
        if (rule.selectAllAvailable)
        {
            return true;
        }

        std::vector<LogicalProcessorCoordinate> requestedCoordinates = rule.processors;
        normalizeLogicalProcessorCoordinates(&requestedCoordinates);
        for (const LogicalProcessorCoordinate& coordinate : requestedCoordinates)
        {
            const auto kProcessorIt = std::find_if(
                currentTopology.begin(),
                currentTopology.end(),
                [&coordinate](const LogicalProcessorState& processor)
                {
                    return processor.coordinate == coordinate && processor.available;
                });
            if (kProcessorIt == currentTopology.end())
            {
                if (missingCoordinatesOut != nullptr)
                {
                    missingCoordinatesOut->push_back(coordinate);
                }
                continue;
            }
            cpuSetIdsOut->push_back(kProcessorIt->cpuSetId);
        }

        std::sort(cpuSetIdsOut->begin(), cpuSetIdsOut->end());
        cpuSetIdsOut->erase(
            std::unique(cpuSetIdsOut->begin(), cpuSetIdsOut->end()),
            cpuSetIdsOut->end());
        return !cpuSetIdsOut->empty();
    }
}
