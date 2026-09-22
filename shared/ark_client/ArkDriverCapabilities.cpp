#include "ArkDriverCapabilities.h"

namespace ksword::ark
{
    DriverCapabilities::DriverCapabilities(const std::uint32_t cachedBits) noexcept
        : cachedBits_(cachedBits)
    {
    }

    bool DriverCapabilities::has(const DriverCapability capability) const noexcept
    {
        const auto kRequestedBit = static_cast<std::uint32_t>(capability);
        return kRequestedBit == 0 || (cachedBits_ & kRequestedBit) == kRequestedBit;
    }

    std::uint32_t DriverCapabilities::bits() const noexcept
    {
        return cachedBits_;
    }

    void DriverCapabilities::setBits(const std::uint32_t cachedBits) noexcept
    {
        cachedBits_ = cachedBits;
    }
}
