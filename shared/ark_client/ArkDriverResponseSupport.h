#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstddef>
#include <string>

namespace ksword::ark::detail
{
    // Fixed protocol fields need not contain a terminator. Never scan past
    // the supplied field capacity, including when an older driver fills it.
    template <typename Character>
    std::basic_string<Character> readFixedString(
        const Character* const buffer,
        const std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < capacity && buffer[length] != Character{})
        {
            ++length;
        }
        return std::basic_string<Character>(buffer, length);
    }

    inline bool isMissingIoctlError(const unsigned long error) noexcept
    {
        return error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED;
    }

    // Preserve the legacy compatibility policy at one named boundary.
    // Access denied and transport failures must not be reported as unsupported.
    inline bool isUnsupportedIoctlError(const unsigned long error) noexcept
    {
        return isMissingIoctlError(error) || error == ERROR_INVALID_PARAMETER;
    }

    // Versioned protocols distinguish an incompatible version from bad input.
    inline bool isUnsupportedProtocolError(const unsigned long error) noexcept
    {
        return isMissingIoctlError(error) || error == ERROR_REVISION_MISMATCH;
    }
}
