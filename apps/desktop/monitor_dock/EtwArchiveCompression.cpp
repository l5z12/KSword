#include <monitor_dock/EtwArchiveCompression.h>

#include <new>
#include <stdexcept>
#include <utility>

#include <zstd.h>

namespace ksword_etw_archive_compression
{
    namespace
    {
        constexpr int kEtwTextCompressionLevel = 3;
    }

    bool compressBlock(const std::span<const char> source, EncodedBlock* encodedOut)
    {
        if (source.empty() || encodedOut == nullptr)
        {
            return false;
        }

        try
        {
            const std::size_t kCompressionBound = ZSTD_compressBound(source.size());
            if (ZSTD_isError(kCompressionBound)
                || kCompressionBound > encodedOut->payload.max_size())
            {
                return false;
            }

            std::vector<char> compressed(kCompressionBound);
            const std::size_t kCompressedSize = ZSTD_compress(
                compressed.data(),
                compressed.size(),
                source.data(),
                source.size(),
                kEtwTextCompressionLevel);
            if (ZSTD_isError(kCompressedSize))
            {
                return false;
            }

            if (kCompressedSize < source.size())
            {
                compressed.resize(kCompressedSize);
                encodedOut->method = BlockMethod::kZstandard;
                encodedOut->payload = std::move(compressed);
            }
            else
            {
                encodedOut->method = BlockMethod::kStored;
                encodedOut->payload.assign(source.begin(), source.end());
            }
            return true;
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        catch (const std::length_error&)
        {
            return false;
        }
    }

    bool decompressBlock(
        const BlockMethod method,
        const std::span<const char> encoded,
        const std::size_t expectedSize,
        std::vector<char>* decodedOut)
    {
        if (encoded.empty() || expectedSize == 0 || decodedOut == nullptr)
        {
            return false;
        }

        try
        {
            if (method == BlockMethod::kStored)
            {
                if (encoded.size() != expectedSize)
                {
                    return false;
                }
                decodedOut->assign(encoded.begin(), encoded.end());
                return true;
            }
            if (method != BlockMethod::kZstandard)
            {
                return false;
            }

            const unsigned long long kFrameSize = ZSTD_getFrameContentSize(
                encoded.data(),
                encoded.size());
            if (kFrameSize == ZSTD_CONTENTSIZE_ERROR
                || kFrameSize == ZSTD_CONTENTSIZE_UNKNOWN
                || kFrameSize != expectedSize
                || kFrameSize > decodedOut->max_size())
            {
                return false;
            }

            std::vector<char> decoded(expectedSize);
            const std::size_t kDecodedSize = ZSTD_decompress(
                decoded.data(),
                decoded.size(),
                encoded.data(),
                encoded.size());
            if (ZSTD_isError(kDecodedSize) || kDecodedSize != expectedSize)
            {
                return false;
            }

            *decodedOut = std::move(decoded);
            return true;
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        catch (const std::length_error&)
        {
            return false;
        }
    }
}
