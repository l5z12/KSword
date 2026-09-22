#include "WorkspaceConfig.h"

#include <limits>

namespace ksword::core {
namespace {

constexpr std::size_t kMagicOffset = 0U;
constexpr std::size_t kVersionOffset = 4U;
constexpr std::size_t kDeclaredSizeOffset = 6U;
constexpr std::size_t kFlagsOffset = 8U;
constexpr std::size_t kRectLeftOffset = 12U;
constexpr std::size_t kRectTopOffset = 16U;
constexpr std::size_t kRectRightOffset = 20U;
constexpr std::size_t kRectBottomOffset = 24U;
constexpr std::size_t kActiveCommandIdOffset = 28U;
constexpr std::size_t kReservedOffset = 32U;

constexpr std::uint8_t kMagic[] = { static_cast<std::uint8_t>('K'), static_cast<std::uint8_t>('S'),
    static_cast<std::uint8_t>('L'), static_cast<std::uint8_t>('W') };
constexpr std::uint32_t kKnownFlags = kWorkspaceConfigFlagHasNormalRect | kWorkspaceConfigFlagMaximized;

void writeU16Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value & 0x00FFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0x00FFU);
}

void writeU32Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::uint32_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value & 0x000000FFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU);
    bytes[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU);
}

void writeI32Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::int32_t value) noexcept {
    writeU32Le(bytes, offset, static_cast<std::uint32_t>(value));
}

std::uint16_t readU16Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
}

std::uint32_t readU32Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
        (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

std::int32_t readI32Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    const std::uint32_t kValue = readU32Le(bytes, offset);
    if ((kValue & 0x80000000U) == 0U) {
        return static_cast<std::int32_t>(kValue);
    }
    if (kValue == 0x80000000U) {
        return (std::numeric_limits<std::int32_t>::min)();
    }
    const std::uint32_t kMagnitude = (~kValue) + 1U;
    return -static_cast<std::int32_t>(kMagnitude);
}

bool hasCommandId(
    const std::span<const WorkspaceCommandId> availableCommandIds,
    const WorkspaceCommandId commandId) noexcept {
    if (commandId == 0) {
        return false;
    }
    for (const WorkspaceCommandId kAvailableCommandId : availableCommandIds) {
        if (kAvailableCommandId == commandId) {
            return true;
        }
    }
    return false;
}

} // namespace

bool isWorkspaceNormalRectValid(const WorkspaceNormalRect& rect) noexcept {
    return rect.right > rect.left && rect.bottom > rect.top;
}

WorkspaceConfigBinary serializeWorkspaceConfig(const WorkspaceConfig& config) noexcept {
    WorkspaceConfigBinary bytes{};
    for (std::size_t index = 0U; index < sizeof(kMagic); ++index) {
        bytes[kMagicOffset + index] = kMagic[index];
    }
    writeU16Le(bytes, kVersionOffset, kWorkspaceConfigVersion);
    writeU16Le(bytes, kDeclaredSizeOffset, kWorkspaceConfigDeclaredSize);

    const bool kPersistNormalRect = config.hasNormalRect && isWorkspaceNormalRectValid(config.normalRect);
    std::uint32_t flags = config.maximized ? kWorkspaceConfigFlagMaximized : 0U;
    if (kPersistNormalRect) {
        flags |= kWorkspaceConfigFlagHasNormalRect;
    }
    writeU32Le(bytes, kFlagsOffset, flags);
    writeI32Le(bytes, kRectLeftOffset, kPersistNormalRect ? config.normalRect.left : 0);
    writeI32Le(bytes, kRectTopOffset, kPersistNormalRect ? config.normalRect.top : 0);
    writeI32Le(bytes, kRectRightOffset, kPersistNormalRect ? config.normalRect.right : 0);
    writeI32Le(bytes, kRectBottomOffset, kPersistNormalRect ? config.normalRect.bottom : 0);
    writeI32Le(bytes, kActiveCommandIdOffset, config.activeCommandId);
    writeU32Le(bytes, kReservedOffset, 0U);
    return bytes;
}

WorkspaceConfigDecodeResult deserializeWorkspaceConfig(const std::span<const std::uint8_t> bytes) noexcept {
    WorkspaceConfigDecodeResult result{};
    if (bytes.size() != kWorkspaceConfigBinarySize) {
        return result;
    }
    for (std::size_t index = 0U; index < sizeof(kMagic); ++index) {
        if (bytes[kMagicOffset + index] != kMagic[index]) {
            result.status = WorkspaceConfigDecodeStatus::kInvalidMagic;
            return result;
        }
    }
    if (readU16Le(bytes, kVersionOffset) != kWorkspaceConfigVersion) {
        result.status = WorkspaceConfigDecodeStatus::kUnsupportedVersion;
        return result;
    }
    if (readU16Le(bytes, kDeclaredSizeOffset) != kWorkspaceConfigDeclaredSize) {
        result.status = WorkspaceConfigDecodeStatus::kInvalidDeclaredSize;
        return result;
    }
    const std::uint32_t kFlags = readU32Le(bytes, kFlagsOffset);
    if ((kFlags & ~kKnownFlags) != 0U) {
        result.status = WorkspaceConfigDecodeStatus::kInvalidFlags;
        return result;
    }
    if (readU32Le(bytes, kReservedOffset) != 0U) {
        result.status = WorkspaceConfigDecodeStatus::kInvalidReserved;
        return result;
    }

    result.config.maximized = (kFlags & kWorkspaceConfigFlagMaximized) != 0U;
    result.config.activeCommandId = readI32Le(bytes, kActiveCommandIdOffset);
    if ((kFlags & kWorkspaceConfigFlagHasNormalRect) != 0U) {
        const WorkspaceNormalRect kRect{
            readI32Le(bytes, kRectLeftOffset),
            readI32Le(bytes, kRectTopOffset),
            readI32Le(bytes, kRectRightOffset),
            readI32Le(bytes, kRectBottomOffset)
        };
        if (isWorkspaceNormalRectValid(kRect)) {
            result.config.hasNormalRect = true;
            result.config.normalRect = kRect;
        } else {
            result.discardedNormalRect = true;
        }
    }
    result.status = WorkspaceConfigDecodeStatus::kValid;
    return result;
}

WorkspaceCommandId resolveWorkspaceCommandId(
    const WorkspaceCommandId savedCommandId,
    const std::span<const WorkspaceCommandId> availableCommandIds,
    const WorkspaceCommandId fallbackCommandId) noexcept {
    if (hasCommandId(availableCommandIds, savedCommandId)) {
        return savedCommandId;
    }
    if (hasCommandId(availableCommandIds, fallbackCommandId)) {
        return fallbackCommandId;
    }

    WorkspaceCommandId resolved = 0;
    for (const WorkspaceCommandId kAvailableCommandId : availableCommandIds) {
        if (kAvailableCommandId != 0 && (resolved == 0 || kAvailableCommandId < resolved)) {
            resolved = kAvailableCommandId;
        }
    }
    return resolved;
}

} // namespace Ksword::Core
