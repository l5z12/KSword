#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    QByteArray serializeEtwArchiveRow(const MonitorDock::EtwCapturedEventRow& row)
    {
        const QByteArray kDetailJsonUtf8 = row.detailJson.toUtf8();
        QByteArray payload;
        payload.reserve(kDetailJsonUtf8.size() + 4096);
        QDataStream stream(&payload, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.setVersion(QDataStream::Qt_6_0);
        stream
            << static_cast<quint32>(kEtwArchiveRowVersion)
            << static_cast<quint64>(row.archiveSequence)
            << row.decodedReady
            << row.timestampText
            << static_cast<quint64>(row.timestampValue)
            << row.providerName << row.providerGuid << row.providerCategory
            << static_cast<qint32>(row.eventId) << row.eventName
            << static_cast<qint32>(row.task) << row.taskName
            << static_cast<qint32>(row.opcode) << row.opcodeName
            << static_cast<qint32>(row.level) << row.levelText
            << static_cast<quint64>(row.keywordMaskValue) << row.keywordMaskText
            << static_cast<quint32>(row.headerPid) << static_cast<quint32>(row.headerTid)
            << row.activityId << row.pidTidText
            << row.detailSummary << kDetailJsonUtf8
            << row.resourceTypeText << row.actionText << row.targetText << row.statusText
            << static_cast<quint32>(row.targetPid) << row.targetPidValid
            << static_cast<quint32>(row.parentPid) << row.parentPidValid
            << static_cast<quint32>(row.targetTid) << row.targetTidValid
            << row.processNameText << row.imagePathText << row.commandLineText
            << row.filePathText << row.fileOldPathText << row.fileNewPathText
            << row.fileOperationText << row.fileStatusCodeText << row.fileAccessMaskText
            << row.registryKeyPathText << row.registryValueNameText << row.registryHiveText
            << row.registryOperationText << row.registryStatusText
            << row.sourceIpText << static_cast<quint32>(row.sourceIpValue) << row.sourceIpValid
            << static_cast<quint16>(row.sourcePort) << row.sourcePortValid
            << row.destinationIpText << static_cast<quint32>(row.destinationIpValue) << row.destinationIpValid
            << static_cast<quint16>(row.destinationPort) << row.destinationPortValid
            << row.protocolText << row.directionText << row.domainText << row.hostText
            << row.auditResultText << row.userText << row.sidText
            << static_cast<quint32>(row.securityPid) << row.securityPidValid
            << static_cast<quint32>(row.securityTid) << row.securityTidValid
            << row.securityLevelText
            << row.scriptHostProcessText << row.scriptKeywordText << row.scriptTaskNameText
            << row.wmiClassNameText << row.wmiNamespaceText;
        return stream.status() == QDataStream::Ok ? payload : QByteArray();
    }

    bool deserializeEtwArchiveRow(
        const QByteArray& payload,
        MonitorDock::EtwCapturedEventRow* rowOut)
    {
        if (payload.isEmpty() || rowOut == nullptr)
        {
            return false;
        }

        QBuffer buffer;
        buffer.setData(payload);
        if (!buffer.open(QIODevice::ReadOnly))
        {
            return false;
        }

        QDataStream stream(&buffer);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.setVersion(QDataStream::Qt_6_0);

        quint32 rowVersion = 0;
        quint64 archiveSequence = 0;
        quint64 timestampValue = 0;
        qint32 eventId = 0;
        qint32 task = 0;
        qint32 opcode = 0;
        qint32 level = 0;
        quint64 keywordMaskValue = 0;
        quint32 headerPid = 0;
        quint32 headerTid = 0;
        quint32 targetPid = 0;
        quint32 parentPid = 0;
        quint32 targetTid = 0;
        quint32 sourceIpValue = 0;
        quint16 sourcePort = 0;
        quint32 destinationIpValue = 0;
        quint16 destinationPort = 0;
        quint32 securityPid = 0;
        quint32 securityTid = 0;
        QByteArray detailJsonUtf8;

        MonitorDock::EtwCapturedEventRow row;
        stream
            >> rowVersion
            >> archiveSequence
            >> row.decodedReady
            >> row.timestampText
            >> timestampValue
            >> row.providerName >> row.providerGuid >> row.providerCategory
            >> eventId >> row.eventName
            >> task >> row.taskName
            >> opcode >> row.opcodeName
            >> level >> row.levelText
            >> keywordMaskValue >> row.keywordMaskText
            >> headerPid >> headerTid
            >> row.activityId >> row.pidTidText
            >> row.detailSummary >> detailJsonUtf8
            >> row.resourceTypeText >> row.actionText >> row.targetText >> row.statusText
            >> targetPid >> row.targetPidValid
            >> parentPid >> row.parentPidValid
            >> targetTid >> row.targetTidValid
            >> row.processNameText >> row.imagePathText >> row.commandLineText
            >> row.filePathText >> row.fileOldPathText >> row.fileNewPathText
            >> row.fileOperationText >> row.fileStatusCodeText >> row.fileAccessMaskText
            >> row.registryKeyPathText >> row.registryValueNameText >> row.registryHiveText
            >> row.registryOperationText >> row.registryStatusText
            >> row.sourceIpText >> sourceIpValue >> row.sourceIpValid
            >> sourcePort >> row.sourcePortValid
            >> row.destinationIpText >> destinationIpValue >> row.destinationIpValid
            >> destinationPort >> row.destinationPortValid
            >> row.protocolText >> row.directionText >> row.domainText >> row.hostText
            >> row.auditResultText >> row.userText >> row.sidText
            >> securityPid >> row.securityPidValid
            >> securityTid >> row.securityTidValid
            >> row.securityLevelText
            >> row.scriptHostProcessText >> row.scriptKeywordText >> row.scriptTaskNameText
            >> row.wmiClassNameText >> row.wmiNamespaceText;

        if (stream.status() != QDataStream::Ok || rowVersion != kEtwArchiveRowVersion)
        {
            return false;
        }

        row.archiveSequence = static_cast<std::uint64_t>(archiveSequence);
        row.timestampValue = static_cast<std::uint64_t>(timestampValue);
        row.eventId = static_cast<int>(eventId);
        row.task = static_cast<int>(task);
        row.opcode = static_cast<int>(opcode);
        row.level = static_cast<int>(level);
        row.keywordMaskValue = static_cast<std::uint64_t>(keywordMaskValue);
        row.headerPid = static_cast<std::uint32_t>(headerPid);
        row.headerTid = static_cast<std::uint32_t>(headerTid);
        row.targetPid = static_cast<std::uint32_t>(targetPid);
        row.parentPid = static_cast<std::uint32_t>(parentPid);
        row.targetTid = static_cast<std::uint32_t>(targetTid);
        row.sourceIpValue = static_cast<std::uint32_t>(sourceIpValue);
        row.sourcePort = static_cast<std::uint16_t>(sourcePort);
        row.destinationIpValue = static_cast<std::uint32_t>(destinationIpValue);
        row.destinationPort = static_cast<std::uint16_t>(destinationPort);
        row.securityPid = static_cast<std::uint32_t>(securityPid);
        row.securityTid = static_cast<std::uint32_t>(securityTid);
        row.detailJson = QString::fromUtf8(detailJsonUtf8);
        row.detailVisibleText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(row.timestampText)
            .arg(row.providerName)
            .arg(row.eventId)
            .arg(row.eventName)
            .arg(row.pidTidText)
            .arg(row.detailSummary)
            .arg(row.activityId);
        row.detailAllText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7 %8 %9 %10")
            .arg(row.detailVisibleText)
            .arg(row.resourceTypeText)
            .arg(row.actionText)
            .arg(row.targetText)
            .arg(row.statusText)
            .arg(row.processNameText)
            .arg(row.filePathText)
            .arg(row.registryKeyPathText)
            .arg(row.scriptKeywordText)
            .arg(row.detailJson);
        row.detailAllText.replace(QChar(u'\r'), QChar(u' '));
        row.detailAllText.replace(QChar(u'\n'), QChar(u' '));
        row.detailAllText = row.detailAllText.simplified();
        *rowOut = std::move(row);
        return true;
    }

    QByteArray buildEtwArchiveFileHeader()
    {
        QByteArray header;
        QDataStream stream(&header, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.writeRawData(kEtwArchiveMagic, static_cast<int>(sizeof(kEtwArchiveMagic) - 1));
        stream << static_cast<quint32>(kEtwArchiveFileVersion);
        return header;
    }

    bool writeAllToHandle(const HANDLE fileHandle, const QByteArray& data)
    {
        if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE || data.isEmpty())
        {
            return data.isEmpty();
        }

        qsizetype writtenTotal = 0;
        while (writtenTotal < data.size())
        {
            const qsizetype kRemaining = data.size() - writtenTotal;
            const DWORD kRequestBytes = static_cast<DWORD>(std::min<qsizetype>(
                kRemaining,
                static_cast<qsizetype>(std::numeric_limits<DWORD>::max())));
            DWORD writtenBytes = 0;
            if (::WriteFile(
                fileHandle,
                data.constData() + writtenTotal,
                kRequestBytes,
                &writtenBytes,
                nullptr) == FALSE
                || writtenBytes == 0)
            {
                return false;
            }
            writtenTotal += static_cast<qsizetype>(writtenBytes);
        }
        return true;
    }

    bool writeEtwArchiveBlockToHandle(const HANDLE fileHandle, const QByteArray& uncompressedData)
    {
        if (uncompressedData.isEmpty())
        {
            return true;
        }
        if (uncompressedData.size() > static_cast<qsizetype>(kEtwArchiveMaximumBlockBytes))
        {
            return false;
        }

        ksword_etw_archive_compression::EncodedBlock encodedBlock;
        if (!ksword_etw_archive_compression::compressBlock(
            std::span<const char>(
                uncompressedData.constData(),
                static_cast<std::size_t>(uncompressedData.size())),
            &encodedBlock)
            || encodedBlock.payload.empty()
            || encodedBlock.payload.size() > kEtwArchiveMaximumStoredBlockBytes)
        {
            return false;
        }

        QByteArray blockHeader;
        blockHeader.reserve(static_cast<qsizetype>(sizeof(quint32) * 3));
        const quint32 kMethodLittleEndian = qToLittleEndian(
            static_cast<quint32>(encodedBlock.method));
        const quint32 kUncompressedSizeLittleEndian = qToLittleEndian(
            static_cast<quint32>(uncompressedData.size()));
        const quint32 kStoredSizeLittleEndian = qToLittleEndian(
            static_cast<quint32>(encodedBlock.payload.size()));
        blockHeader.append(
            reinterpret_cast<const char*>(&kMethodLittleEndian),
            static_cast<qsizetype>(sizeof(kMethodLittleEndian)));
        blockHeader.append(
            reinterpret_cast<const char*>(&kUncompressedSizeLittleEndian),
            static_cast<qsizetype>(sizeof(kUncompressedSizeLittleEndian)));
        blockHeader.append(
            reinterpret_cast<const char*>(&kStoredSizeLittleEndian),
            static_cast<qsizetype>(sizeof(kStoredSizeLittleEndian)));

        const QByteArray kStoredData = QByteArray::fromRawData(
            encodedBlock.payload.data(),
            static_cast<qsizetype>(encodedBlock.payload.size()));
        return writeAllToHandle(fileHandle, blockHeader)
            && writeAllToHandle(fileHandle, kStoredData);
    }

    bool scanEtwArchiveFile(
        const QString& filePath,
        const std::function<bool(const MonitorDock::EtwCapturedEventRow&)>& rowVisitor,
        const std::function<bool()>& shouldCancel,
        std::uint64_t* scannedRowsInOut,
        std::uint64_t* maxSequenceInOut,
        QString* errorTextOut)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法读取 ETW 归档分段：%1").arg(filePath);
            }
            return false;
        }

        constexpr qint64 kMagicBytes = static_cast<qint64>(sizeof(kEtwArchiveMagic) - 1);
        constexpr qint64 kHeaderBytes = kMagicBytes + static_cast<qint64>(sizeof(quint32));
        const qint64 kFileSize = file.size();
        if (kFileSize < kHeaderBytes)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
            }
            return false;
        }

        uchar* mappedData = file.map(0, kFileSize);
        if (mappedData == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法读取 ETW 归档分段：%1").arg(filePath);
            }
            return false;
        }
        const auto kMappedGuard = std::unique_ptr<uchar, std::function<void(uchar*)>>(
            mappedData,
            [&file](uchar* data) {
                file.unmap(data);
            });

        const quint32 kFileVersion = qFromLittleEndian<quint32>(mappedData + kMagicBytes);
        if (std::memcmp(mappedData, kEtwArchiveMagic, static_cast<std::size_t>(kMagicBytes)) != 0
            || (kFileVersion != kEtwArchiveLegacyFileVersion
                && kFileVersion != kEtwArchiveFileVersion))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
            }
            return false;
        }

        bool stopRequested = false;
        const auto kScanRecordBuffer = [&](
            const char* recordData,
            const qint64 recordBytes) -> bool {
            qint64 recordOffset = 0;
            while (recordOffset < recordBytes)
            {
                if (shouldCancel && shouldCancel())
                {
                    stopRequested = true;
                    return true;
                }
                if (recordBytes - recordOffset < static_cast<qint64>(sizeof(quint32)))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档分段尾部不完整：%1").arg(filePath);
                    }
                    return false;
                }

                const quint32 kPayloadSize = qFromLittleEndian<quint32>(
                    reinterpret_cast<const uchar*>(recordData + recordOffset));
                recordOffset += static_cast<qint64>(sizeof(quint32));
                if (kPayloadSize == 0 || kPayloadSize > kEtwArchiveMaximumRecordBytes)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录长度无效：%1").arg(filePath);
                    }
                    return false;
                }
                if (static_cast<qint64>(kPayloadSize) > recordBytes - recordOffset)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录内容不完整：%1").arg(filePath);
                    }
                    return false;
                }

                const QByteArray kPayload = QByteArray::fromRawData(
                    recordData + recordOffset,
                    static_cast<qsizetype>(kPayloadSize));
                recordOffset += static_cast<qint64>(kPayloadSize);
                MonitorDock::EtwCapturedEventRow row;
                if (!deserializeEtwArchiveRow(kPayload, &row))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录解析失败：%1").arg(filePath);
                    }
                    return false;
                }

                if (scannedRowsInOut != nullptr)
                {
                    ++(*scannedRowsInOut);
                }
                if (maxSequenceInOut != nullptr)
                {
                    *maxSequenceInOut = std::max(*maxSequenceInOut, row.archiveSequence);
                }
                if (rowVisitor && !rowVisitor(row))
                {
                    stopRequested = true;
                    return true;
                }
            }
            return true;
        };

        if (kFileVersion == kEtwArchiveLegacyFileVersion)
        {
            return kScanRecordBuffer(
                reinterpret_cast<const char*>(mappedData + kHeaderBytes),
                kFileSize - kHeaderBytes);
        }

        qint64 blockOffset = kHeaderBytes;
        constexpr qint64 kBlockHeaderBytes = static_cast<qint64>(sizeof(quint32) * 3);
        while (blockOffset < kFileSize)
        {
            if (shouldCancel && shouldCancel())
            {
                return true;
            }
            if (kFileSize - blockOffset < kBlockHeaderBytes)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段尾部不完整：%1").arg(filePath);
                }
                return false;
            }

            const quint32 kMethodValue = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));
            const quint32 kUncompressedSize = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));
            const quint32 kStoredSize = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));

            if (kUncompressedSize == 0
                || kUncompressedSize > kEtwArchiveMaximumBlockBytes
                || kStoredSize == 0
                || kStoredSize > kEtwArchiveMaximumStoredBlockBytes
                || static_cast<qint64>(kStoredSize) > kFileSize - blockOffset)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
                }
                return false;
            }

            std::vector<char> decodedBlock;
            if (!ksword_etw_archive_compression::decompressBlock(
                static_cast<ksword_etw_archive_compression::BlockMethod>(kMethodValue),
                std::span<const char>(
                    reinterpret_cast<const char*>(mappedData + blockOffset),
                    static_cast<std::size_t>(kStoredSize)),
                static_cast<std::size_t>(kUncompressedSize),
                &decodedBlock))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
                }
                return false;
            }
            blockOffset += static_cast<qint64>(kStoredSize);

            if (!kScanRecordBuffer(
                decodedBlock.data(),
                static_cast<qint64>(decodedBlock.size())))
            {
                return false;
            }
            if (stopRequested)
            {
                return true;
            }
        }
        return true;
    }
}
