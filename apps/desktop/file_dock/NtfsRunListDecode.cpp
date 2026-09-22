#include "NtfsRunListDecode.h"

#include <cstring>
#include <limits>
#include <utility>

namespace ks::file
{
    std::int64_t readSignedLittleEndian(const std::byte* const ptr, const std::uint8_t byteCount)
    {
        std::uint64_t rawValue = 0;
        if (ptr == nullptr || byteCount == 0 || byteCount > 8)
        {
            return 0;
        }

        for (std::uint8_t i = 0; i < byteCount; ++i)
        {
            rawValue |=
                static_cast<std::uint64_t>(
                    static_cast<std::uint8_t>(ptr[i]))
                << (i * 8);
        }

        // If the sign bit of the most significant byte is 1, manual sign extension is required.
        const std::uint64_t kSignMask =
            std::uint64_t{1} << (byteCount * 8 - 1);
        if (byteCount < 8 && (rawValue & kSignMask) != 0)
        {
            rawValue |=
                std::numeric_limits<std::uint64_t>::max()
                << (byteCount * 8);
        }
        std::int64_t signedValue = 0;
        static_assert(sizeof(signedValue) == sizeof(rawValue));
        std::memcpy(&signedValue, &rawValue, sizeof(signedValue));
        return signedValue;
    }

    bool parseNtfsRunList(
        const std::byte* runListPtr,
        const std::byte* const runListEnd,
        std::vector<NtfsDataRun>& dataRunsOut)
    {
        dataRunsOut.clear();
        if (runListPtr == nullptr || runListEnd == nullptr || runListPtr >= runListEnd)
        {
            return false;
        }

        std::int64_t currentLcn = 0;
        while (runListPtr < runListEnd)
        {
            const std::uint8_t kHeaderValue = static_cast<std::uint8_t>(*runListPtr);
            runListPtr += 1;
            if (kHeaderValue == 0)
            {
                return !dataRunsOut.empty();
            }

            const std::uint8_t kLengthFieldBytes = (kHeaderValue & 0x0F);
            const std::uint8_t kOffsetFieldBytes = ((kHeaderValue >> 4) & 0x0F);
            if (kLengthFieldBytes == 0
                || kLengthFieldBytes > 8
                || kOffsetFieldBytes > 8
                || runListPtr + kLengthFieldBytes + kOffsetFieldBytes > runListEnd)
            {
                dataRunsOut.clear();
                return false;
            }

            std::uint64_t clusterCountValue = 0;
            for (std::uint8_t i = 0; i < kLengthFieldBytes; ++i)
            {
                clusterCountValue |=
                    (static_cast<std::uint64_t>(static_cast<std::uint8_t>(runListPtr[i])) << (i * 8));
            }
            if (clusterCountValue == 0)
            {
                dataRunsOut.clear();
                return false;
            }

            NtfsDataRun runValue{};
            runValue.clusterCount = clusterCountValue;
            if (kOffsetFieldBytes == 0)
            {
                runValue.isSparse = true;
            }
            else
            {
                const std::int64_t kLcnDeltaValue =
                    readSignedLittleEndian(runListPtr + kLengthFieldBytes, kOffsetFieldBytes);
                const bool kPositiveOverflow =
                    kLcnDeltaValue > 0 &&
                    currentLcn >
                        std::numeric_limits<std::int64_t>::max() -
                            kLcnDeltaValue;
                // Must exclude INT64_MIN before negating: -INT64_MIN is itself a signed overflow.
                const bool kNegativeOrOverflow =
                    kLcnDeltaValue ==
                        std::numeric_limits<std::int64_t>::min() ||
                    (kLcnDeltaValue < 0 &&
                     currentLcn < -kLcnDeltaValue);
                if (kPositiveOverflow || kNegativeOrOverflow)
                {
                    dataRunsOut.clear();
                    return false;
                }
                currentLcn += kLcnDeltaValue;
                runValue.startLcn = static_cast<std::uint64_t>(currentLcn);
            }

            dataRunsOut.push_back(std::move(runValue));
            runListPtr += kLengthFieldBytes + kOffsetFieldBytes;
        }
        return !dataRunsOut.empty();
    }
}
