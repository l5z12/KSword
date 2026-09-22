#pragma once

// ============================================================
// CodeEditorFileSession.h
// Purpose:
// - Provides metadata structure for text file sessions (encoding/BOM/newline style);
// - Provides unified text decoding, newline normalization, and status display helper functions.
// - Reusable by CodeEditorWidget to avoid reimplementing file encoding/decoding logic on each page.
// ============================================================

#include <QByteArray>
#include <QString>
#include <QStringConverter>

namespace code_editor_file_session
{
    // FileSessionMetadata：
    // - Record the session metadata for the current text file.
    // - Save strategy for 'preserve original encoding/BOM/line ending style after opening'.
    struct FileSessionMetadata
    {
        // encoding: Target text encoding (default UTF-8).
        QStringConverter::Encoding encoding = QStringConverter::Utf8;

        // hasBom: Whether to output BOM when saving.
        bool hasBom = false;

        // lineEndingText: Line ending style; common values are "\r\n", "\n", "\r".
        QString lineEndingText = QStringLiteral("\r\n");

        // validFromFile: Indicates whether the data originated from a real file load (true = from file, false = in-memory text).
        bool validFromFile = false;
    };

    // decodeTextFileBytes：
    // - Purpose: Decode file bytes according to BOM / UTF-8 / local encoding rules.
    // - Invocation: Called after CodeEditorWidget loads a file;
    // - Input parameter fileBytes: the original file bytes;
    // - Output: metadataOut returns the file session metadata to preserve after decoding.
    // - Returns: A QString text suitable for direct insertion into the editor.
    QString decodeTextFileBytes(const QByteArray& fileBytes, FileSessionMetadata* metadataOut);

    // detectDominantLineEnding：
    // - Purpose: Detect the dominant line ending style in the text.
    // - Usage: Can be used to infer line ending strategy after loading a file and before saving.
    // - Input parameter textValue: target text;
    // - Returns: "\r\n", "\n", or "\r".
    QString detectDominantLineEnding(const QString& textValue);

    // normalizeLineEndingForSaving：
    // - Purpose: normalize text line endings to a specified style.
    // - Invocation: Called before writing the file to ensure controllable line endings.
    // - Input textValue: Original text; lineEndingText: Target line ending;
    // - Returns: The converted text.
    QString normalizeLineEndingForSaving(const QString& textValue, const QString& lineEndingText);

    // buildEncodingDisplayText：
    // - Purpose: Convert encoding metadata into status bar readable text.
    // - Invocation: Called by CodeEditorWidget when updating the status bar;
    // - Input parameter metadata: session metadata;
    // - Returns: Strings like "UTF-8", "UTF-8 BOM", "UTF-16 LE BOM", or "Local Encoding".
    QString buildEncodingDisplayText(const FileSessionMetadata& metadata);

    // buildLineEndingDisplayText：
    // - Purpose: Convert line ending styles to status bar readable phrases.
    // - Invocation: Called by CodeEditorWidget when updating the status bar;
    // - Parameter lineEndingText: Line ending text.
    // - Returns: e.g., "CRLF", "LF", "CR".
    QString buildLineEndingDisplayText(const QString& lineEndingText);
}
