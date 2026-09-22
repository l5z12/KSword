#include "DiskRangeTools.h"

// ============================================================
// DiskRangeTools.cpp
// Purpose:
// 1) Implement advanced disk range tools for search, hashing, export, import, comparison, and bad sector scanning.
// 2) Use sequential block processing to avoid allocating huge memory for large-scale tasks at once;
// 3) All disk writes still go through DiskEditorBackend::writeBytes to enforce sector alignment protection.
// ============================================================

#include "DiskEditorBackend.h"

#include <QElapsedTimer>
#include <QFile>
#include <QStringList>

#include <algorithm>
#include <limits>

namespace
{
    using ks::misc::DiskRangeTaskResult;
    using ks::misc::DiskSearchPatternMode;
    using ks::misc::DiskSearchResult;

    // kIoChunkBytes: Default sequential processing block size for the range tool.
    constexpr std::uint32_t kIoChunkBytes = 1024U * 1024U;

    // kPreviewBeforeBytes: Number of bytes to preview before a search match.
    constexpr int kPreviewBeforeBytes = 16;

    // kPreviewAfterBytes: Number of bytes to preview after a search match.
    constexpr int kPreviewAfterBytes = 32;

    // appendError：
    // - Populate failure result;
    // - result is the task result;
    // - errorText is the failure message;
    // - Returns the result reference to allow direct return from the caller.
    DiskRangeTaskResult& appendError(DiskRangeTaskResult& result, const QString& errorText)
    {
        result.success = false;
        result.errorText = errorText;
        result.summary = errorText;
        return result;
    }

    // formatHexDigest：
    // - Convert hash digest to uppercase HEX.
    // - digest is the raw digest;
    // - Returns display text.
    QString formatHexDigest(const QByteArray& digest)
    {
        return QString::fromLatin1(digest.toHex(' ')).toUpper();
    }

    // estimateSpeed：
    // - Calculate MiB/s based on the timer and byte count.
    // - timer: started timer
    // - bytes is the processed byte count;
    // - Returns throughput speed.
    double estimateSpeed(const QElapsedTimer& timer, const std::uint64_t bytes)
    {
        const qint64 kElapsedMs = std::max<qint64>(1, timer.elapsed());
        return (static_cast<double>(bytes) / 1048576.0) / (static_cast<double>(kElapsedMs) / 1000.0);
    }

    // parseHexPattern：
    // - Parse hexadecimal search patterns in the format AA BB ??;
    // - patternText is the user input.
    // - patternOut receives the byte template.
    // - maskOut receives the mask: 0 for wildcard, 0xFF for exact match;
    // - errorTextOut returns the failure explanation.
    bool parseHexPattern(
        const QString& patternText,
        QByteArray& patternOut,
        QByteArray& maskOut,
        QString& errorTextOut)
    {
        patternOut.clear();
        maskOut.clear();
        errorTextOut.clear();

        QString normalized = patternText.trimmed();
        if (normalized.isEmpty())
        {
            errorTextOut = QStringLiteral("搜索模式为空。");
            return false;
        }
        normalized.replace(QStringLiteral("0x"), QString(), Qt::CaseInsensitive);
        normalized.replace(QChar(','), QChar(' '));
        normalized.replace(QChar(';'), QChar(' '));
        normalized.replace(QChar('\t'), QChar(' '));

        const bool kHasSeparators = normalized.contains(QChar(' '));
        if (kHasSeparators)
        {
            const QStringList kTokens = normalized.split(QChar(' '), Qt::SkipEmptyParts);
            for (const QString& token : kTokens)
            {
                if (token == QStringLiteral("?") || token == QStringLiteral("??"))
                {
                    patternOut.append('\0');
                    maskOut.append('\0');
                    continue;
                }
                if (token.size() != 2)
                {
                    errorTextOut = QStringLiteral("HEX 模式 token 长度必须为 2：%1").arg(token);
                    return false;
                }
                bool ok = false;
                const int kValue = token.toInt(&ok, 16);
                if (!ok || kValue < 0 || kValue > 0xFF)
                {
                    errorTextOut = QStringLiteral("HEX 模式包含非法字节：%1").arg(token);
                    return false;
                }
                patternOut.append(static_cast<char>(kValue));
                maskOut.append(static_cast<char>(0xFF));
            }
        }
        else
        {
            normalized.remove(QChar(' '));
            if ((normalized.size() % 2) != 0)
            {
                errorTextOut = QStringLiteral("连续 HEX 字符串长度必须为偶数。");
                return false;
            }
            for (int index = 0; index < normalized.size(); index += 2)
            {
                const QString kToken = normalized.mid(index, 2);
                if (kToken == QStringLiteral("??"))
                {
                    patternOut.append('\0');
                    maskOut.append('\0');
                    continue;
                }
                bool ok = false;
                const int kValue = kToken.toInt(&ok, 16);
                if (!ok || kValue < 0 || kValue > 0xFF)
                {
                    errorTextOut = QStringLiteral("HEX 模式包含非法字节：%1").arg(kToken);
                    return false;
                }
                patternOut.append(static_cast<char>(kValue));
                maskOut.append(static_cast<char>(0xFF));
            }
        }

        if (patternOut.isEmpty())
        {
            errorTextOut = QStringLiteral("搜索模式为空。");
            return false;
        }
        return true;
    }

    // buildPattern：
    // - Build byte template and mask based on search mode;
    // - mode controls HEX/ASCII/UTF-16.
    // - Returns true if parsing was successful.
    bool buildPattern(
        const QString& patternText,
        const DiskSearchPatternMode mode,
        QByteArray& patternOut,
        QByteArray& maskOut,
        QString& errorTextOut)
    {
        if (mode == DiskSearchPatternMode::kHexBytes)
        {
            return parseHexPattern(patternText, patternOut, maskOut, errorTextOut);
        }
        if (mode == DiskSearchPatternMode::kAsciiText)
        {
            patternOut = patternText.toLocal8Bit();
            maskOut = QByteArray(patternOut.size(), static_cast<char>(0xFF));
        }
        else
        {
            patternOut = QByteArray(
                reinterpret_cast<const char*>(patternText.utf16()),
                patternText.size() * static_cast<int>(sizeof(char16_t)));
            maskOut = QByteArray(patternOut.size(), static_cast<char>(0xFF));
        }

        if (patternOut.isEmpty())
        {
            errorTextOut = QStringLiteral("搜索模式为空。");
            return false;
        }
        return true;
    }

    // matchesAt：
    // - Check if the specified offset in the buffer matches the pattern.
    // - Positions where mask is 0 represent wildcards.
    // - Returns true if a match is found.
    bool matchesAt(
        const QByteArray& buffer,
        const int offset,
        const QByteArray& pattern,
        const QByteArray& mask)
    {
        if (offset < 0 || offset + pattern.size() > buffer.size())
        {
            return false;
        }
        for (int index = 0; index < pattern.size(); ++index)
        {
            const auto kMaskValue = static_cast<unsigned char>(mask.at(index));
            if (kMaskValue == 0)
            {
                continue;
            }
            const auto kLeft = static_cast<unsigned char>(buffer.at(offset + index));
            const auto kRight = static_cast<unsigned char>(pattern.at(index));
            if ((kLeft & kMaskValue) != (kRight & kMaskValue))
            {
                return false;
            }
        }
        return true;
    }

    // readChunk：
    // - Reads a chunk using DiskEditorBackend.
    // - devicePath/offsetBytes/bytesToRead specify the range.
    // - bytesOut receives the data;
    // - errorTextOut returns the error message.
    bool readChunk(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint32_t bytesToRead,
        QByteArray& bytesOut,
        QString& errorTextOut)
    {
        return ks::misc::DiskEditorBackend::readBytes(
            devicePath,
            offsetBytes,
            bytesToRead,
            bytesOut,
            errorTextOut);
    }

    // safeToUInt32：
    // Clamp 64-bit length to the range representable by DWORD.
    // - value is the input length.
    // - Returns a 32-bit length.
    std::uint32_t safeToUInt32(const std::uint64_t value)
    {
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(
            value,
            static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())));
    }
}

namespace ks::misc
{
    DiskRangeTaskResult DiskRangeTools::searchRange(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint64_t lengthBytes,
        const QString& patternText,
        const DiskSearchPatternMode mode,
        const int maxResults)
    {
        DiskRangeTaskResult result;
        if (lengthBytes == 0)
        {
            return appendError(result, QStringLiteral("搜索长度为 0。"));
        }

        QByteArray pattern;
        QByteArray mask;
        QString parseError;
        if (!buildPattern(patternText, mode, pattern, mask, parseError))
        {
            return appendError(result, parseError);
        }

        const int kPatternSize = pattern.size();
        if (kPatternSize <= 0)
        {
            return appendError(result, QStringLiteral("搜索模式为空。"));
        }

        QElapsedTimer timer;
        timer.start();
        QByteArray carry;
        std::uint64_t processed = 0;
        const int kResultLimit = std::max(1, maxResults);

        while (processed < lengthBytes && static_cast<int>(result.searchResults.size()) < kResultLimit)
        {
            const std::uint64_t kRemaining = lengthBytes - processed;
            const std::uint32_t kRequestBytes = safeToUInt32(std::min<std::uint64_t>(kRemaining, kIoChunkBytes));
            QByteArray chunk;
            QString errorText;
            if (!readChunk(devicePath, offsetBytes + processed, kRequestBytes, chunk, errorText))
            {
                return appendError(result, QStringLiteral("搜索读取失败 @ %1：%2")
                    .arg(offsetBytes + processed)
                    .arg(errorText));
            }
            if (chunk.isEmpty())
            {
                break;
            }

            const QByteArray kScanBuffer = carry + chunk;
            const std::uint64_t kScanBase = offsetBytes + processed - static_cast<std::uint64_t>(carry.size());
            const int kMaxScanOffset = kScanBuffer.size() - kPatternSize;
            for (int index = 0; index <= kMaxScanOffset && static_cast<int>(result.searchResults.size()) < kResultLimit; ++index)
            {
                if (!matchesAt(kScanBuffer, index, pattern, mask))
                {
                    continue;
                }

                const int kPreviewStart = std::max(0, index - kPreviewBeforeBytes);
                const int kPreviewEnd = std::min<int>(
                    static_cast<int>(kScanBuffer.size()),
                    index + kPatternSize + kPreviewAfterBytes);
                DiskSearchResult hit;
                hit.offsetBytes = kScanBase + static_cast<std::uint64_t>(index);
                hit.preview = kScanBuffer.mid(kPreviewStart, kPreviewEnd - kPreviewStart);
                result.searchResults.push_back(std::move(hit));
            }

            const int kCarryBytes = std::min<int>(
                std::max(kPatternSize - 1, 0),
                static_cast<int>(kScanBuffer.size()));
            carry = kScanBuffer.right(kCarryBytes);
            processed += static_cast<std::uint64_t>(chunk.size());
        }

        result.success = true;
        result.bytesProcessed = processed;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = QStringLiteral("搜索完成：处理 %1，命中 %2 条，速度 %3 MiB/s。")
            .arg(DiskEditorBackend::formatBytes(processed))
            .arg(static_cast<int>(result.searchResults.size()))
            .arg(result.mibPerSecond, 0, 'f', 2);
        result.detailLines << QStringLiteral("模式长度：%1 字节").arg(kPatternSize);
        if (static_cast<int>(result.searchResults.size()) >= kResultLimit)
        {
            result.detailLines << QStringLiteral("已达到最大结果数 %1，搜索提前停止。").arg(kResultLimit);
        }
        return result;
    }

    DiskRangeTaskResult DiskRangeTools::hashRange(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint64_t lengthBytes,
        const QCryptographicHash::Algorithm algorithm)
    {
        DiskRangeTaskResult result;
        if (lengthBytes == 0)
        {
            return appendError(result, QStringLiteral("哈希长度为 0。"));
        }

        QCryptographicHash hasher(algorithm);
        QElapsedTimer timer;
        timer.start();
        std::uint64_t processed = 0;
        while (processed < lengthBytes)
        {
            const std::uint64_t kRemaining = lengthBytes - processed;
            const std::uint32_t kRequestBytes = safeToUInt32(std::min<std::uint64_t>(kRemaining, kIoChunkBytes));
            QByteArray chunk;
            QString errorText;
            if (!readChunk(devicePath, offsetBytes + processed, kRequestBytes, chunk, errorText))
            {
                return appendError(result, QStringLiteral("哈希读取失败 @ %1：%2")
                    .arg(offsetBytes + processed)
                    .arg(errorText));
            }
            if (chunk.isEmpty())
            {
                break;
            }
            hasher.addData(chunk);
            processed += static_cast<std::uint64_t>(chunk.size());
        }

        result.success = true;
        result.digestBytes = hasher.result();
        result.bytesProcessed = processed;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = QStringLiteral("哈希完成：%1，速度 %2 MiB/s。")
            .arg(formatHexDigest(result.digestBytes))
            .arg(result.mibPerSecond, 0, 'f', 2);
        result.detailLines << QStringLiteral("处理范围：offset=%1 length=%2")
            .arg(offsetBytes)
            .arg(lengthBytes);
        return result;
    }

    DiskRangeTaskResult DiskRangeTools::exportRangeToFile(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint64_t lengthBytes,
        const QString& filePath)
    {
        DiskRangeTaskResult result;
        if (lengthBytes == 0)
        {
            return appendError(result, QStringLiteral("导出长度为 0。"));
        }
        QFile output(filePath);
        if (!output.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            return appendError(result, QStringLiteral("无法打开导出文件：%1").arg(output.errorString()));
        }

        QElapsedTimer timer;
        timer.start();
        std::uint64_t processed = 0;
        while (processed < lengthBytes)
        {
            const std::uint64_t kRemaining = lengthBytes - processed;
            const std::uint32_t kRequestBytes = safeToUInt32(std::min<std::uint64_t>(kRemaining, kIoChunkBytes));
            QByteArray chunk;
            QString errorText;
            if (!readChunk(devicePath, offsetBytes + processed, kRequestBytes, chunk, errorText))
            {
                output.close();
                return appendError(result, QStringLiteral("导出读取失败 @ %1：%2")
                    .arg(offsetBytes + processed)
                    .arg(errorText));
            }
            if (chunk.isEmpty())
            {
                break;
            }
            if (output.write(chunk) != chunk.size())
            {
                output.close();
                return appendError(result, QStringLiteral("写入导出文件失败：%1").arg(output.errorString()));
            }
            processed += static_cast<std::uint64_t>(chunk.size());
        }
        output.close();

        result.success = true;
        result.bytesProcessed = processed;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = QStringLiteral("导出完成：%1 -> %2，速度 %3 MiB/s。")
            .arg(DiskEditorBackend::formatBytes(processed))
            .arg(filePath)
            .arg(result.mibPerSecond, 0, 'f', 2);
        return result;
    }

    DiskRangeTaskResult DiskRangeTools::importFileToRange(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const QString& filePath,
        const std::uint32_t bytesPerSector,
        const bool requireSectorAligned)
    {
        DiskRangeTaskResult result;
        QFile input(filePath);
        if (!input.open(QIODevice::ReadOnly))
        {
            return appendError(result, QStringLiteral("无法打开导入文件：%1").arg(input.errorString()));
        }

        const std::uint64_t kFileBytes = static_cast<std::uint64_t>(input.size());
        const std::uint32_t kSectorSize = bytesPerSector == 0 ? 512U : bytesPerSector;
        if (kFileBytes == 0)
        {
            return appendError(result, QStringLiteral("导入文件为空。"));
        }
        if (requireSectorAligned
            && ((offsetBytes % kSectorSize) != 0 || (kFileBytes % kSectorSize) != 0))
        {
            return appendError(result, QStringLiteral("导入被拒绝：偏移和文件长度必须按 %1 字节扇区对齐。").arg(kSectorSize));
        }
        if (requireSectorAligned && (kIoChunkBytes % kSectorSize) != 0)
        {
            return appendError(result, QStringLiteral("导入被拒绝：内部块大小不能被 %1 字节扇区整除。").arg(kSectorSize));
        }

        QElapsedTimer timer;
        timer.start();
        std::uint64_t processed = 0;
        while (!input.atEnd())
        {
            QByteArray chunk = input.read(kIoChunkBytes);
            if (chunk.isEmpty())
            {
                break;
            }
            QString errorText;
            if (!DiskEditorBackend::writeBytes(
                devicePath,
                offsetBytes + processed,
                chunk,
                bytesPerSector,
                false,
                errorText))
            {
                return appendError(result, QStringLiteral("导入写入失败 @ %1：%2")
                    .arg(offsetBytes + processed)
                    .arg(errorText));
            }
            processed += static_cast<std::uint64_t>(chunk.size());
        }

        result.success = true;
        result.bytesProcessed = processed;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = QStringLiteral("导入完成：%1 -> offset %2，速度 %3 MiB/s。")
            .arg(filePath)
            .arg(offsetBytes)
            .arg(result.mibPerSecond, 0, 'f', 2);
        return result;
    }

    DiskRangeTaskResult DiskRangeTools::compareRangeWithFile(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint64_t lengthBytes,
        const QString& filePath,
        const int maxDifferences)
    {
        DiskRangeTaskResult result;
        QFile input(filePath);
        if (!input.open(QIODevice::ReadOnly))
        {
            return appendError(result, QStringLiteral("无法打开对比文件：%1").arg(input.errorString()));
        }

        const std::uint64_t kCompareBytes = std::min<std::uint64_t>(
            lengthBytes,
            static_cast<std::uint64_t>(input.size()));
        if (kCompareBytes == 0)
        {
            return appendError(result, QStringLiteral("对比长度为 0。"));
        }

        QElapsedTimer timer;
        timer.start();
        std::uint64_t processed = 0;
        int differences = 0;
        const int kDifferenceLimit = std::max(1, maxDifferences);
        while (processed < kCompareBytes)
        {
            const std::uint64_t kRemaining = kCompareBytes - processed;
            const std::uint32_t kRequestBytes = safeToUInt32(std::min<std::uint64_t>(kRemaining, kIoChunkBytes));
            QByteArray diskBytes;
            QString errorText;
            if (!readChunk(devicePath, offsetBytes + processed, kRequestBytes, diskBytes, errorText))
            {
                return appendError(result, QStringLiteral("对比读取失败 @ %1：%2")
                    .arg(offsetBytes + processed)
                    .arg(errorText));
            }
            const QByteArray kFileBytes = input.read(diskBytes.size());
            const int kCompareSize = std::min(diskBytes.size(), kFileBytes.size());
            for (int index = 0; index < kCompareSize; ++index)
            {
                if (diskBytes.at(index) == kFileBytes.at(index))
                {
                    continue;
                }
                ++differences;
                if (result.detailLines.size() < kDifferenceLimit)
                {
                    result.detailLines << QStringLiteral("差异 @ %1：磁盘=%2 文件=%3")
                        .arg(offsetBytes + processed + static_cast<std::uint64_t>(index))
                        .arg(static_cast<unsigned int>(static_cast<unsigned char>(diskBytes.at(index))), 2, 16, QChar('0'))
                        .arg(static_cast<unsigned int>(static_cast<unsigned char>(kFileBytes.at(index))), 2, 16, QChar('0'))
                        .toUpper();
                }
            }
            processed += static_cast<std::uint64_t>(kCompareSize);
            if (kCompareSize == 0)
            {
                break;
            }
        }

        result.success = true;
        result.bytesProcessed = processed;
        result.failureCount = differences;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = differences == 0
            ? QStringLiteral("对比完成：完全一致，处理 %1。").arg(DiskEditorBackend::formatBytes(processed))
            : QStringLiteral("对比完成：发现 %1 处字节差异，处理 %2。").arg(differences).arg(DiskEditorBackend::formatBytes(processed));
        if (static_cast<std::uint64_t>(input.size()) != lengthBytes)
        {
            result.detailLines << QStringLiteral("提示：文件长度 %1 与指定长度 %2 不一致，仅对比交集。")
                .arg(input.size())
                .arg(lengthBytes);
        }
        return result;
    }

    DiskRangeTaskResult DiskRangeTools::scanReadableBlocks(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint64_t lengthBytes,
        const std::uint32_t blockBytes)
    {
        DiskRangeTaskResult result;
        if (lengthBytes == 0)
        {
            return appendError(result, QStringLiteral("扫描长度为 0。"));
        }

        const std::uint32_t kEffectiveBlockBytes = std::clamp<std::uint32_t>(
            blockBytes == 0 ? kIoChunkBytes : blockBytes,
            512U,
            kIoChunkBytes * 8U);
        QElapsedTimer timer;
        timer.start();
        std::uint64_t processed = 0;
        int failedBlocks = 0;

        while (processed < lengthBytes)
        {
            const std::uint64_t kRemaining = lengthBytes - processed;
            const std::uint32_t kRequestBytes = safeToUInt32(std::min<std::uint64_t>(kRemaining, kEffectiveBlockBytes));
            QByteArray chunk;
            QString errorText;
            if (!readChunk(devicePath, offsetBytes + processed, kRequestBytes, chunk, errorText))
            {
                ++failedBlocks;
                if (result.detailLines.size() < 128)
                {
                    result.detailLines << QStringLiteral("读取失败块 @ %1 length=%2：%3")
                        .arg(offsetBytes + processed)
                        .arg(kRequestBytes)
                        .arg(errorText);
                }
                processed += kRequestBytes;
                continue;
            }
            processed += static_cast<std::uint64_t>(chunk.size());
            if (chunk.isEmpty())
            {
                break;
            }
        }

        result.success = failedBlocks == 0;
        result.bytesProcessed = processed;
        result.failureCount = failedBlocks;
        result.mibPerSecond = estimateSpeed(timer, processed);
        result.summary = failedBlocks == 0
            ? QStringLiteral("读扫完成：未发现读取失败块，速度 %1 MiB/s。").arg(result.mibPerSecond, 0, 'f', 2)
            : QStringLiteral("读扫完成：发现 %1 个读取失败块，速度 %2 MiB/s。").arg(failedBlocks).arg(result.mibPerSecond, 0, 'f', 2);
        return result;
    }
}
