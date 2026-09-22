#include "CodeEditorFileSession.h"

// ============================================================
// CodeEditorFileSession.cpp
// Purpose:
// - Implement metadata recognition for text file sessions;
// - Implement encoding/BOM/line ending style preservation.
// - Provides unified file read/write strategy capabilities for CodeEditorWidget.
// ============================================================

#include <QBuffer>
#include <QTextStream>

namespace
{
    // readAllTextWithEncoding：
    // - Purpose: Parse byte block into text by specified encoding.
    // - Call: Unified read entry point for UTF-16 LE/BE scenarios.
    // - Input rawBytes: Raw bytes; encoding: Target encoding.
    // - Returns: Decoded text content.
    QString readAllTextWithEncoding(const QByteArray& rawBytes, const QStringConverter::Encoding encoding)
    {
        QBuffer byteBuffer;
        byteBuffer.setData(rawBytes);
        if (!byteBuffer.open(QIODevice::ReadOnly))
        {
            return QString();
        }

        QTextStream textStream(&byteBuffer);
        textStream.setEncoding(encoding);
        return textStream.readAll();
    }
}

namespace code_editor_file_session
{
    QString decodeTextFileBytes(const QByteArray& fileBytes, FileSessionMetadata* metadataOut)
    {
        FileSessionMetadata sessionMetadata;
        QString decodedText;

        // BOM detection: prioritize identifying UTF-8 / UTF-16 LE / UTF-16 BE.
        if (fileBytes.startsWith("\xEF\xBB\xBF"))
        {
            sessionMetadata.encoding = QStringConverter::Utf8;
            sessionMetadata.hasBom = true;
            decodedText = QString::fromUtf8(fileBytes.constData() + 3, fileBytes.size() - 3);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFF
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFE)
        {
            sessionMetadata.encoding = QStringConverter::Utf16LE;
            sessionMetadata.hasBom = true;
            decodedText = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16LE);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFE
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFF)
        {
            sessionMetadata.encoding = QStringConverter::Utf16BE;
            sessionMetadata.hasBom = true;
            decodedText = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16BE);
        }
        else
        {
            // No BOM: Attempt UTF-8 first; if replacement characters appear, fall back to the local encoding.
            const QString kUtf8Text = QString::fromUtf8(fileBytes);
            if (!fileBytes.isEmpty() && kUtf8Text.contains(QChar::ReplacementCharacter))
            {
                sessionMetadata.encoding = QStringConverter::System;
                sessionMetadata.hasBom = false;
                decodedText = QString::fromLocal8Bit(fileBytes);
            }
            else
            {
                sessionMetadata.encoding = QStringConverter::Utf8;
                sessionMetadata.hasBom = false;
                decodedText = kUtf8Text;
            }
        }

        sessionMetadata.lineEndingText = detectDominantLineEnding(decodedText);
        sessionMetadata.validFromFile = true;
        if (metadataOut != nullptr)
        {
            *metadataOut = sessionMetadata;
        }
        return decodedText;
    }

    QString detectDominantLineEnding(const QString& textValue)
    {
        // Count occurrences of three line-break types and use the most frequent one as the dominant style.
        int crlfCount = 0;
        int lfCount = 0;
        int crCount = 0;

        for (int index = 0; index < textValue.size(); ++index)
        {
            const QChar kCurrentChar = textValue.at(index);
            if (kCurrentChar == QChar('\r'))
            {
                if ((index + 1) < textValue.size() && textValue.at(index + 1) == QChar('\n'))
                {
                    ++crlfCount;
                    ++index;
                }
                else
                {
                    ++crCount;
                }
            }
            else if (kCurrentChar == QChar('\n'))
            {
                ++lfCount;
            }
        }

        if (crlfCount >= lfCount && crlfCount >= crCount)
        {
            return QStringLiteral("\r\n");
        }
        if (lfCount >= crCount)
        {
            return QStringLiteral("\n");
        }
        return QStringLiteral("\r");
    }

    QString normalizeLineEndingForSaving(const QString& textValue, const QString& lineEndingText)
    {
        // normalize to LF first, then export according to the target style to prevent mixed line endings from spreading.
        QString normalizedText = textValue;
        normalizedText.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        normalizedText.replace(QChar('\r'), QChar('\n'));

        if (lineEndingText == QStringLiteral("\r"))
        {
            return normalizedText.replace(QChar('\n'), QChar('\r'));
        }
        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return normalizedText.replace(QStringLiteral("\n"), QStringLiteral("\r\n"));
        }
        return normalizedText;
    }

    QString buildEncodingDisplayText(const FileSessionMetadata& metadata)
    {
        QString encodingName = QStringLiteral("UTF-8");
        switch (metadata.encoding)
        {
        case QStringConverter::Utf8:
            encodingName = QStringLiteral("UTF-8");
            break;
        case QStringConverter::Utf16LE:
            encodingName = QStringLiteral("UTF-16 LE");
            break;
        case QStringConverter::Utf16BE:
            encodingName = QStringLiteral("UTF-16 BE");
            break;
        case QStringConverter::System:
            encodingName = QStringLiteral("本地编码");
            break;
        default:
            encodingName = QStringLiteral("UTF-8");
            break;
        }
        if (metadata.hasBom)
        {
            encodingName += QStringLiteral(" BOM");
        }
        return encodingName;
    }

    QString buildLineEndingDisplayText(const QString& lineEndingText)
    {
        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return QStringLiteral("CRLF");
        }
        if (lineEndingText == QStringLiteral("\r"))
        {
            return QStringLiteral("CR");
        }
        return QStringLiteral("LF");
    }
}
