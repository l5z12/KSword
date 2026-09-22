#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // normalizeEtwPropertyName：
    // - Purpose: normalize the property name to lowercase alphanumeric characters to facilitate heuristic matching across Providers.
    QString normalizeEtwPropertyName(const QString& propertyNameText)
    {
        QString normalizedText;
        normalizedText.reserve(propertyNameText.size());
        for (const QChar kCurrentChar : propertyNameText.toLower())
        {
            if (kCurrentChar.isLetterOrNumber())
            {
                normalizedText.push_back(kCurrentChar);
            }
        }
        return normalizedText;
    }

    // etwPropertyMeaningText：
    // - Purpose: Provide Chinese semantic descriptions for common property names.
    // - Call: Written to cache during schema construction to avoid subsequent repeated checks.
    QString etwPropertyMeaningText(const QString& normalizedNameText)
    {
        static const std::unordered_map<std::string, QString> kMeaningMap{
            {"processid", QStringLiteral("进程ID")},
            {"threadid", QStringLiteral("线程ID")},
            {"parentprocessid", QStringLiteral("父进程ID")},
            {"imagename", QStringLiteral("映像路径")},
            {"imagefilename", QStringLiteral("映像文件")},
            {"commandline", QStringLiteral("命令行")},
            {"processname", QStringLiteral("进程名称")},
            {"pid", QStringLiteral("进程ID")},
            {"parentid", QStringLiteral("父进程ID")},
            {"filename", QStringLiteral("文件路径")},
            {"filepath", QStringLiteral("文件路径")},
            {"pathname", QStringLiteral("路径")},
            {"targetfilename", QStringLiteral("目标文件路径")},
            {"targetname", QStringLiteral("目标名称")},
            {"relativefilename", QStringLiteral("相对文件名")},
            {"oldfilename", QStringLiteral("源文件路径")},
            {"newfilename", QStringLiteral("新文件路径")},
            {"fileobject", QStringLiteral("文件对象指针")},
            {"keyname", QStringLiteral("注册表键路径")},
            {"keypath", QStringLiteral("注册表键路径")},
            {"hive", QStringLiteral("注册表根键")},
            {"valuename", QStringLiteral("注册表值名称")},
            {"objectname", QStringLiteral("对象路径")},
            {"path", QStringLiteral("对象路径")},
            {"operation", QStringLiteral("操作类型")},
            {"disposition", QStringLiteral("处置结果")},
            {"desiredaccess", QStringLiteral("目标访问权限")},
            {"shareaccess", QStringLiteral("共享访问权限")},
            {"status", QStringLiteral("状态码")},
            {"ntstatus", QStringLiteral("NT状态码")},
            {"result", QStringLiteral("结果码")},
            {"opcode", QStringLiteral("操作码")},
            {"informationclass", QStringLiteral("信息类")},
            {"hostname", QStringLiteral("主机名")},
            {"url", QStringLiteral("URL")},
            {"domainname", QStringLiteral("域名")},
            {"daddr", QStringLiteral("目标IP")},
            {"saddr", QStringLiteral("源IP")},
            {"dport", QStringLiteral("目标端口")},
            {"sport", QStringLiteral("源端口")}
        };

        const auto kFound = kMeaningMap.find(normalizedNameText.toStdString());
        if (kFound == kMeaningMap.end())
        {
            return QString();
        }
        return kFound->second;
    }

    // etwTypeText：
    // - Purpose: Convert the TDH InType to a human-readable type name.
    // - Call: Outputs the type description for each property in JSON.
    QString etwTypeText(const USHORT inTypeValue)
    {
        switch (inTypeValue)
        {
        case TDH_INTYPE_UNICODESTRING: return QStringLiteral("UnicodeString");
        case TDH_INTYPE_ANSISTRING: return QStringLiteral("AnsiString");
        case TDH_INTYPE_INT8: return QStringLiteral("Int8");
        case TDH_INTYPE_UINT8: return QStringLiteral("UInt8");
        case TDH_INTYPE_INT16: return QStringLiteral("Int16");
        case TDH_INTYPE_UINT16: return QStringLiteral("UInt16");
        case TDH_INTYPE_INT32: return QStringLiteral("Int32");
        case TDH_INTYPE_UINT32: return QStringLiteral("UInt32");
        case TDH_INTYPE_HEXINT32: return QStringLiteral("HexInt32");
        case TDH_INTYPE_INT64: return QStringLiteral("Int64");
        case TDH_INTYPE_UINT64: return QStringLiteral("UInt64");
        case TDH_INTYPE_HEXINT64: return QStringLiteral("HexInt64");
        case TDH_INTYPE_FLOAT: return QStringLiteral("Float32");
        case TDH_INTYPE_DOUBLE: return QStringLiteral("Float64");
        case TDH_INTYPE_BOOLEAN: return QStringLiteral("Boolean");
        case TDH_INTYPE_BINARY: return QStringLiteral("Binary");
        case TDH_INTYPE_GUID: return QStringLiteral("Guid");
        case TDH_INTYPE_POINTER: return QStringLiteral("Pointer");
        case TDH_INTYPE_FILETIME: return QStringLiteral("FileTime");
        case TDH_INTYPE_SYSTEMTIME: return QStringLiteral("SystemTime");
        case TDH_INTYPE_SID: return QStringLiteral("Sid");
        case TDH_INTYPE_HEXDUMP: return QStringLiteral("HexDump");
        default: return QStringLiteral("Type_%1").arg(static_cast<int>(inTypeValue));
        }
    }

    // etwTextAtOffset：
    // - Purpose: Read UTF-16 text stored by offset in TRACE_EVENT_INFO.
    // - Usage: Parses event name, task name, opcode name, and property name.
    QString etwTextAtOffset(const unsigned char* infoBufferPointer, const ULONG offsetValue)
    {
        if (infoBufferPointer == nullptr || offsetValue == 0)
        {
            return QString();
        }

        const wchar_t* textPointer = reinterpret_cast<const wchar_t*>(infoBufferPointer + offsetValue);
        if (textPointer == nullptr || *textPointer == L'\0')
        {
            return QString();
        }
        return QString::fromWCharArray(textPointer).trimmed();
    }

    // etwHexPreview：
    // - Purpose: Format byte buffer into a single-line hex preview.
    // - Usage: Outputs a raw byte summary when attributes cannot be fully parsed.
    QString etwHexPreview(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes )
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        const ULONG kVisibleBytes = std::min(dataSize, maxBytes);
        QStringList byteTextList;
        byteTextList.reserve(static_cast<int>(kVisibleBytes));
        for (ULONG indexValue = 0; indexValue < kVisibleBytes; ++indexValue)
        {
            byteTextList << QStringLiteral("%1").arg(dataPointer[indexValue], 2, 16, QChar(u'0')).toUpper();
        }

        QString previewText = byteTextList.join(' ');
        if (dataSize > kVisibleBytes)
        {
            previewText += QStringLiteral(" ... (%1 bytes)").arg(dataSize);
        }
        return previewText;
    }

    // etwHexDump：
    // - Purpose: Format a byte buffer into multi-line hexadecimal viewer text;
    // - Usage: Fallback display for unknown fields and unparsed trailing bytes.
    QString etwHexDump(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes )
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        const ULONG kVisibleBytes = std::min(dataSize, maxBytes);
        QStringList lineList;
        for (ULONG offsetValue = 0; offsetValue < kVisibleBytes; offsetValue += 16)
        {
            const ULONG kLineBytes = std::min<ULONG>(16, kVisibleBytes - offsetValue);
            QStringList hexCellList;
            hexCellList.reserve(16);

            QString asciiText;
            asciiText.reserve(16);
            for (ULONG columnIndex = 0; columnIndex < kLineBytes; ++columnIndex)
            {
                const unsigned char kByteValue = dataPointer[offsetValue + columnIndex];
                hexCellList << QStringLiteral("%1").arg(kByteValue, 2, 16, QChar(u'0')).toUpper();
                asciiText.push_back((kByteValue >= 32 && kByteValue <= 126) ? QChar(kByteValue) : QChar(u'.'));
            }
            for (ULONG columnIndex = kLineBytes; columnIndex < 16; ++columnIndex)
            {
                hexCellList << QStringLiteral("  ");
                asciiText.push_back(QChar(u' '));
            }

            lineList << QStringLiteral("%1  %2  |%3|")
                .arg(offsetValue, 4, 16, QChar(u'0'))
                .arg(hexCellList.join(' '))
                .arg(asciiText);
        }

        if (dataSize > kVisibleBytes)
        {
            lineList << QStringLiteral("... 已截断，原始长度=%1 bytes，展示=%2 bytes")
                .arg(dataSize)
                .arg(kVisibleBytes);
        }

        return lineList.join('\n');
    }

    // etwPointerSizeByHeader：
    // - Purpose: Derives pointer length based on the event header bit width.
    // - Call: Decoding Pointer type properties.
    ULONG etwPointerSizeByHeader(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return static_cast<ULONG>(sizeof(void*));
        }
        return (eventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4UL : 8UL;
    }

    // etwFixedTypeSize：
    // - Purpose: Return the fixed byte length for common InType values.
    // - Returns 0 to indicate 'variable length or unknown length'.
    ULONG etwFixedTypeSize(const USHORT inTypeValue, const ULONG pointerSize)
    {
        switch (inTypeValue)
        {
        case TDH_INTYPE_INT8:
        case TDH_INTYPE_UINT8:
        case TDH_INTYPE_ANSICHAR:
            return 1;
        case TDH_INTYPE_INT16:
        case TDH_INTYPE_UINT16:
        case TDH_INTYPE_UNICODECHAR:
            return 2;
        case TDH_INTYPE_INT32:
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_HEXINT32:
        case TDH_INTYPE_FLOAT:
        case TDH_INTYPE_BOOLEAN:
            return 4;
        case TDH_INTYPE_INT64:
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_HEXINT64:
        case TDH_INTYPE_DOUBLE:
        case TDH_INTYPE_FILETIME:
            return 8;
        case TDH_INTYPE_GUID:
            return 16;
        case TDH_INTYPE_POINTER:
            return pointerSize == 4 || pointerSize == 8 ? pointerSize : static_cast<ULONG>(sizeof(void*));
        default:
            return 0;
        }
    }

    // etwUnicodeBytesToText：
    // - Purpose: Convert UTF-16LE byte buffer to QString and trim the trailing NUL.
    // - Usage: Decoding UnicodeString class properties.
    QString etwUnicodeBytesToText(const unsigned char* dataPointer, const ULONG dataSize)
    {
        if (dataPointer == nullptr || dataSize < sizeof(wchar_t))
        {
            return QString();
        }

        const ULONG kAlignedBytes = dataSize - (dataSize % sizeof(wchar_t));
        if (kAlignedBytes == 0)
        {
            return QString();
        }

        std::wstring tempWideText(static_cast<std::size_t>(kAlignedBytes / sizeof(wchar_t)), L'\0');
        std::memcpy(tempWideText.data(), dataPointer, kAlignedBytes);
        QString textValue = QString::fromWCharArray(tempWideText.c_str(), static_cast<int>(tempWideText.size()));

        const int kNullPosition = textValue.indexOf(QChar(u'\0'));
        if (kNullPosition >= 0)
        {
            textValue.truncate(kNullPosition);
        }
        return textValue.trimmed();
    }

    // etwAnsiBytesToText：
    // - Purpose: Convert ANSI byte buffer to QString and trim trailing NULs;
    // - Invocation: Decode via the AnsiString class property.
    QString etwAnsiBytesToText(const unsigned char* dataPointer, const ULONG dataSize)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QString();
        }

        QByteArray byteArray(reinterpret_cast<const char*>(dataPointer), static_cast<int>(dataSize));
        const int kNullPosition = byteArray.indexOf('\0');
        if (kNullPosition >= 0)
        {
            byteArray.truncate(kNullPosition);
        }
        return QString::fromLocal8Bit(byteArray).trimmed();
    }

    // tryConsumeUnicodeString：
    // - Purpose: Read Unicode strings according to the rule: explicit length takes precedence, otherwise scan for NUL termination.
    // - Called: for TDH_INTYPE_UNICODESTRING decoding.
    bool tryConsumeUnicodeString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut)
    {
        if (textOut != nullptr)
        {
            *textOut = QString();
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = 0;
        }
        if (dataPointer == nullptr || availableBytes == 0)
        {
            return false;
        }

        ULONG consumeBytes = 0;
        if (explicitLengthBytes > 0)
        {
            consumeBytes = std::min(explicitLengthBytes, availableBytes);
        }
        else
        {
            for (ULONG offsetValue = 0; offsetValue + 1 < availableBytes; offsetValue += 2)
            {
                if (dataPointer[offsetValue] == 0 && dataPointer[offsetValue + 1] == 0)
                {
                    consumeBytes = offsetValue + 2;
                    break;
                }
            }
            if (consumeBytes == 0)
            {
                consumeBytes = availableBytes;
            }
        }

        if (consumeBytes == 0)
        {
            return false;
        }
        if ((consumeBytes % 2) != 0)
        {
            --consumeBytes;
        }
        if (consumeBytes == 0)
        {
            return false;
        }

        if (textOut != nullptr)
        {
            *textOut = etwUnicodeBytesToText(dataPointer, consumeBytes);
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = consumeBytes;
        }
        return true;
    }

    // tryConsumeAnsiString：
    // - Purpose: Read ANSI strings according to the rule: explicit length first, otherwise scan for NUL termination;
    // - Call: TDH_INTYPE_ANSISTRING decoding.
    bool tryConsumeAnsiString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut)
    {
        if (textOut != nullptr)
        {
            *textOut = QString();
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = 0;
        }
        if (dataPointer == nullptr || availableBytes == 0)
        {
            return false;
        }

        ULONG consumeBytes = 0;
        if (explicitLengthBytes > 0)
        {
            consumeBytes = std::min(explicitLengthBytes, availableBytes);
        }
        else
        {
            for (ULONG offsetValue = 0; offsetValue < availableBytes; ++offsetValue)
            {
                if (dataPointer[offsetValue] == 0)
                {
                    consumeBytes = offsetValue + 1;
                    break;
                }
            }
            if (consumeBytes == 0)
            {
                consumeBytes = availableBytes;
            }
        }

        if (consumeBytes == 0)
        {
            return false;
        }
        if (textOut != nullptr)
        {
            *textOut = etwAnsiBytesToText(dataPointer, consumeBytes);
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = consumeBytes;
        }
        return true;
    }
}
