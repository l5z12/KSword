#include "CodeEditorWidget.h"

// ============================================================
// CodeEditorWidget.cpp
// Purpose:
// - Implement a reusable code editor for the "Immediate Window";
// - Provides line numbers, bracket highlighting, find/replace, line jumping, and text file read/write.
// ============================================================

#include "ReportStructuredView.h"

#include "../Theme.h"
#include "../internationalization/LanguageManager.h"

#include <QBuffer>
#include <QComboBox>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QPaintEvent>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QResizeEvent>
#include <QScrollBar>
#include <QShortcut>
#include <QSize>
#include <QSvgRenderer>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextStream>
#include <QToolButton>
#include <QVBoxLayout>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>
#include <QStringConverter>

#include <algorithm>

namespace
{
    // g_preferStructuredReportView:
    // - Remember the user's last selection between 'Structured View' and 'Raw Text'; new reports generated subsequently inherit the same selection.
    // - Valid only in-process and not persisted to disk: this represents 'how I want to view this investigation session', not a preference to be saved long-term.
    // - Default structured view: detail reports are essentially field lists, so reading them item-by-item is faster than reading a block of text.
    bool gPreferStructuredReportView = true;

    // localizeReportValueCore: Translates report field values; composite permissions/flags are translated item-by-item separated by pipes.
    QString localizeReportValueCore(const QString& valueCore)
    {
        const QString kLocalizedWholeValue = ks::i18n::displayText(valueCore);
        if (kLocalizedWholeValue != valueCore || !valueCore.contains(QLatin1Char('|')))
        {
            return kLocalizedWholeValue;
        }

        QStringList valueParts = valueCore.split(QLatin1Char('|'), Qt::KeepEmptyParts);
        bool anyPartChanged = false;
        for (QString& valuePart : valueParts)
        {
            qsizetype startIndex = 0;
            while (startIndex < valuePart.size() && valuePart.at(startIndex).isSpace())
            {
                ++startIndex;
            }
            qsizetype endIndex = valuePart.size();
            while (endIndex > startIndex && valuePart.at(endIndex - 1).isSpace())
            {
                --endIndex;
            }

            const QString kPartCore = valuePart.mid(startIndex, endIndex - startIndex);
            const QString kLocalizedPartCore = ks::i18n::displayText(kPartCore);
            if (kLocalizedPartCore == kPartCore)
            {
                continue;
            }
            valuePart = valuePart.left(startIndex) + kLocalizedPartCore + valuePart.mid(endIndex);
            anyPartChanged = true;
        }
        return anyPartChanged ? valueParts.join(QLatin1Char('|')) : valueCore;
    }

    // localizeEmbeddedReportValue: Translates the status value in 'Label: Dynamic Status'.
    // Template translation preserves %1 capture content as-is; here, only the translatable state after the colon is processed, while paths and hashes remain naturally unchanged.
    QString localizeEmbeddedReportValue(const QString& sourceLine, const QString& localizedLine)
    {
        const bool kHasNewline = sourceLine.endsWith(QLatin1Char('\n'));
        const bool kLocalizedHasNewline = localizedLine.endsWith(QLatin1Char('\n'));
        const QString kSourceBody = kHasNewline ? sourceLine.chopped(1) : sourceLine;
        QString localizedBody = kLocalizedHasNewline ? localizedLine.chopped(1) : localizedLine;

        qsizetype separatorIndex = kSourceBody.indexOf(QLatin1Char(':'));
        const qsizetype kFullWidthSeparatorIndex = kSourceBody.indexOf(QChar(0xFF1A));
        if (separatorIndex < 0 ||
            (kFullWidthSeparatorIndex >= 0 && kFullWidthSeparatorIndex < separatorIndex))
        {
            separatorIndex = kFullWidthSeparatorIndex;
        }
        if (separatorIndex < 0)
        {
            return localizedLine;
        }

        const QString kSourceValue = kSourceBody.mid(separatorIndex + 1);
        qsizetype valueStart = 0;
        while (valueStart < kSourceValue.size() && kSourceValue.at(valueStart).isSpace())
        {
            ++valueStart;
        }
        qsizetype valueEnd = kSourceValue.size();
        while (valueEnd > valueStart && kSourceValue.at(valueEnd - 1).isSpace())
        {
            --valueEnd;
        }
        const QString kValueCore = kSourceValue.mid(valueStart, valueEnd - valueStart);
        const QString kLocalizedValueCore = localizeReportValueCore(kValueCore);
        if (kValueCore.isEmpty() || kLocalizedValueCore == kValueCore || !localizedBody.endsWith(kSourceValue))
        {
            return localizedLine;
        }

        localizedBody.chop(kSourceValue.size());
        localizedBody += kSourceValue.left(valueStart);
        localizedBody += kLocalizedValueCore;
        localizedBody += kSourceValue.mid(valueEnd);
        return kHasNewline ? localizedBody + QLatin1Char('\n') : localizedBody;
    }

    // localizeGeneratedReport: Processes only line-by-line templates for generated reports.
    // Dynamic values like paths, hashes, and certificate contents are preserved verbatim via placeholders; user file bodies do not invoke this function.
    QString localizeGeneratedReport(const QString& sourceText)
    {
        QString localizedText;
        localizedText.reserve(sourceText.size());

        qsizetype lineStart = 0;
        while (lineStart < sourceText.size())
        {
            const qsizetype kNewlineIndex = sourceText.indexOf(QLatin1Char('\n'), lineStart);
            const bool kHasNewline = kNewlineIndex >= 0;
            const qsizetype kLineLength = kHasNewline
                ? (kNewlineIndex - lineStart + 1)
                : (sourceText.size() - lineStart);
            const QString kSourceLine = sourceText.mid(lineStart, kLineLength);
            QString localizedLine = ks::i18n::displayText(kSourceLine);
            if (localizedLine == kSourceLine && kHasNewline)
            {
                localizedLine = ks::i18n::displayText(kSourceLine.left(kSourceLine.size() - 1));
                localizedLine += QLatin1Char('\n');
            }
            localizedLine = localizeEmbeddedReportValue(kSourceLine, localizedLine);
            localizedText += localizedLine;
            lineStart += kLineLength;
        }
        return localizedText;
    }

    // buildToolButtonStyle：
    // - Unify tool button styles by removing borders to make the icons more prominent.
    // - hover/pressed: retain only lightweight background color feedback to prevent the SVG from being clipped by the border
    QString buildToolButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  border:none;"
            "  border-radius:4px;"
            "  padding:1px;"
            "  background:transparent;"
            "  color:%1;"
            "}"
            "QToolButton:hover{"
            "  background:%2;"
            "  color:%4;"
            "}"
            "QToolButton:pressed{"
            "  background:%3;"
            "  color:%4;"
            "}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue, -14, -40))
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // buildFloatingSwitchStyle：
    // - Style for the floating switch dropdown in the top-right corner of the content area;
    // - It overlays the main content, so it must have its own opaque background and border; otherwise, it becomes unreadable when stacked over property table rows or report text.
    // - Explicitly set the background color for the drop-down list as well: the popup panel is an independent window and will not inherit the background here.
    // - All colors use the palette(...) token format; they update with theme changes, not as snapshots.
    QString buildFloatingSwitchStyle()
    {
        return QStringLiteral(
            "QComboBox{"
            "  border:1px solid %1;"
            "  border-radius:6px;"
            "  padding:4px 8px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QComboBox:hover{"
            "  border:1px solid %4;"
            "}"
            "QComboBox QAbstractItemView{"
            "  border:1px solid %1;"
            "  background:%2;"
            "  color:%3;"
            "  selection-background-color:%4;"
            "  selection-color:%5;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // buildInputStyle：
    // - Unified input box styles to support both light and dark themes.
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:3px;padding:2px 6px;background:transparent;/* %2 */color:%3;}"
            "QLineEdit:focus{border:1px solid %4;}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // buildToolbarSvgIcon：
    // - Generate toolbar icons from SVG resources;
    // - Use theme blue for coloring to prevent icons from appearing too dark and unreadable in dark mode.
    QIcon buildToolbarSvgIcon(const QString& resourcePath, const QSize& iconSize = QSize(22, 22))
    {
        QSvgRenderer renderer(resourcePath);
        if (!renderer.isValid())
        {
            return QIcon(resourcePath);
        }

        QPixmap iconPixmap(iconSize);
        iconPixmap.fill(Qt::transparent);

        QPainter painter(&iconPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(iconPixmap.rect(), ksword_theme::primaryBlueColor);
        painter.end();

        return QIcon(iconPixmap);
    }

    // isOpenBracket：
    // - Check if the character is an opening bracket.
    bool isOpenBracket(const QChar ch)
    {
        return ch == QChar('(') || ch == QChar('[') || ch == QChar('{');
    }

    // isCloseBracket：
    // - Check if the character is a closing bracket.
    bool isCloseBracket(const QChar ch)
    {
        return ch == QChar(')') || ch == QChar(']') || ch == QChar('}');
    }

    // pairBracket：
    // - Returns the matching bracket character.
    QChar pairBracket(const QChar ch)
    {
        if (ch == QChar('('))
        {
            return QChar(')');
        }
        if (ch == QChar('['))
        {
            return QChar(']');
        }
        if (ch == QChar('{'))
        {
            return QChar('}');
        }
        if (ch == QChar(')'))
        {
            return QChar('(');
        }
        if (ch == QChar(']'))
        {
            return QChar('[');
        }
        if (ch == QChar('}'))
        {
            return QChar('{');
        }
        return QChar();
    }

    // FileDecodeResult：
    // - Holds text file decoding results and session metadata.
    struct FileDecodeResult
    {
        QString text;
        QStringConverter::Encoding encoding = QStringConverter::Utf8;
        bool hasBom = false;
        QString lineEndingText = QStringLiteral("\n");
        bool success = false;
    };

    // readAllTextWithEncoding：
    // - Reads the full text using the specified encoding.
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

    // detectDominantLineEnding：
    // - Detect dominant line ending style in text.
    QString detectDominantLineEnding(const QString& textValue)
    {
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

    // normalizeLineEndingForSaving：
    // - normalize line endings before writing back to the file to prevent mixed line endings from persisting.
    QString normalizeLineEndingForSaving(const QString& textValue, const QString& lineEndingText)
    {
        QString normalizedText = textValue;
        normalizedText.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        normalizedText.replace(QChar('\r'), QChar('\n'));

        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return normalizedText.replace(QStringLiteral("\n"), QStringLiteral("\r\n"));
        }
        if (lineEndingText == QStringLiteral("\r"))
        {
            return normalizedText.replace(QChar('\n'), QChar('\r'));
        }
        return normalizedText;
    }

    // buildEncodingDisplayText：
    // - Convert encoding display text (including BOM marker).
    QString buildEncodingDisplayText(const QStringConverter::Encoding encoding, const bool hasBom)
    {
        QString encodingName = QStringLiteral("UTF-8");
        switch (encoding)
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

        if (hasBom)
        {
            encodingName += QStringLiteral(" BOM");
        }
        return encodingName;
    }

    // stripKnownBom：
    // - Remove common BOM headers and return whether one was found.
    QByteArray stripKnownBom(const QByteArray& fileBytes, bool* hadBomOut)
    {
        QByteArray payload = fileBytes;
        bool hadBom = false;
        if (payload.startsWith("\xEF\xBB\xBF"))
        {
            payload.remove(0, 3);
            hadBom = true;
        }
        else if (payload.size() >= 2
            && static_cast<unsigned char>(payload.at(0)) == 0xFF
            && static_cast<unsigned char>(payload.at(1)) == 0xFE)
        {
            payload.remove(0, 2);
            hadBom = true;
        }
        else if (payload.size() >= 2
            && static_cast<unsigned char>(payload.at(0)) == 0xFE
            && static_cast<unsigned char>(payload.at(1)) == 0xFF)
        {
            payload.remove(0, 2);
            hadBom = true;
        }

        if (hadBomOut != nullptr)
        {
            *hadBomOut = hadBom;
        }
        return payload;
    }

    // decodeTextFileBytesAuto：
    // - Automatically detect BOM, UTF-8, or local encoding.
    FileDecodeResult decodeTextFileBytesAuto(const QByteArray& fileBytes)
    {
        FileDecodeResult result;
        result.success = true;

        if (fileBytes.startsWith("\xEF\xBB\xBF"))
        {
            result.encoding = QStringConverter::Utf8;
            result.hasBom = true;
            result.text = QString::fromUtf8(fileBytes.constData() + 3, fileBytes.size() - 3);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFF
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFE)
        {
            result.encoding = QStringConverter::Utf16LE;
            result.hasBom = true;
            result.text = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16LE);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFE
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFF)
        {
            result.encoding = QStringConverter::Utf16BE;
            result.hasBom = true;
            result.text = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16BE);
        }
        else
        {
            const QString kUtf8Text = QString::fromUtf8(fileBytes);
            if (!fileBytes.isEmpty() && kUtf8Text.contains(QChar::ReplacementCharacter))
            {
                result.encoding = QStringConverter::System;
                result.hasBom = false;
                result.text = QString::fromLocal8Bit(fileBytes);
            }
            else
            {
                result.encoding = QStringConverter::Utf8;
                result.hasBom = false;
                result.text = kUtf8Text;
            }
        }

        result.lineEndingText = detectDominantLineEnding(result.text);
        return result;
    }

    // decodeTextFileBytesForced：
    // Read text using the encoding specified by the caller.
    FileDecodeResult decodeTextFileBytesForced(const QByteArray& fileBytes, QStringConverter::Encoding forcedEncoding)
    {
        FileDecodeResult result;
        result.success = true;
        result.encoding = forcedEncoding;

        bool hadBom = false;
        const QByteArray kPayload = stripKnownBom(fileBytes, &hadBom);
        result.hasBom = hadBom;

        switch (forcedEncoding)
        {
        case QStringConverter::Utf8:
            result.text = QString::fromUtf8(kPayload);
            break;
        case QStringConverter::Utf16LE:
            result.text = readAllTextWithEncoding(kPayload, QStringConverter::Utf16LE);
            break;
        case QStringConverter::Utf16BE:
            result.text = readAllTextWithEncoding(kPayload, QStringConverter::Utf16BE);
            break;
        case QStringConverter::System:
            result.text = QString::fromLocal8Bit(kPayload);
            break;
        default:
            result.encoding = QStringConverter::Utf8;
            result.text = QString::fromUtf8(kPayload);
            break;
        }

        result.lineEndingText = detectDominantLineEnding(result.text);
        return result;
    }

    // tryFormatJsonText：
    // - Attempt to detect and format JSON.
    bool tryFormatJsonText(const QString& inputText, QString* formattedTextOut)
    {
        const QString kTrimmedText = inputText.trimmed();
        if (kTrimmedText.size() < 2)
        {
            return false;
        }

        const QChar kFirstChar = kTrimmedText.front();
        const QChar kLastChar = kTrimmedText.back();
        const bool kLooksLikeJson =
            (kFirstChar == QChar('{') && kLastChar == QChar('}'))
            || (kFirstChar == QChar('[') && kLastChar == QChar(']'));
        if (!kLooksLikeJson)
        {
            return false;
        }

        QJsonParseError parseError;
        const QJsonDocument kJsonDocument = QJsonDocument::fromJson(kTrimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError || kJsonDocument.isNull())
        {
            return false;
        }

        QString formattedText = QString::fromUtf8(kJsonDocument.toJson(QJsonDocument::Indented));
        if (formattedText.endsWith(QChar('\n')))
        {
            formattedText.chop(1);
        }

        if (formattedTextOut != nullptr)
        {
            *formattedTextOut = formattedText;
        }
        return true;
    }

    // tryFormatXmlText：
    // - Attempt to identify and format XML.
    bool tryFormatXmlText(const QString& inputText, QString* formattedTextOut)
    {
        const QString kTrimmedText = inputText.trimmed();
        if (kTrimmedText.size() < 3 || !kTrimmedText.startsWith(QChar('<')) || !kTrimmedText.endsWith(QChar('>')))
        {
            return false;
        }
        if (!kTrimmedText.contains(QStringLiteral("</"))
            && !kTrimmedText.contains(QStringLiteral("/>"))
            && !kTrimmedText.startsWith(QStringLiteral("<?xml")))
        {
            return false;
        }

        QXmlStreamReader xmlReader(kTrimmedText);
        QString formattedXmlText;
        QXmlStreamWriter xmlWriter(&formattedXmlText);
        xmlWriter.setAutoFormatting(true);
        xmlWriter.setAutoFormattingIndent(2);

        while (!xmlReader.atEnd())
        {
            xmlReader.readNext();
            if (xmlReader.tokenType() == QXmlStreamReader::Invalid)
            {
                break;
            }
            xmlWriter.writeCurrentToken(xmlReader);
        }

        if (xmlReader.hasError())
        {
            return false;
        }

        if (formattedTextOut != nullptr)
        {
            *formattedTextOut = formattedXmlText;
        }
        return true;
    }

    // autoFormatStructuredText：
    // - Default auto-formatting for JSON/XML.
    QString autoFormatStructuredText(const QString& inputText, QString* detectedKindOut)
    {
        if (detectedKindOut != nullptr)
        {
            detectedKindOut->clear();
        }

        // Skip structured formatting for extremely large text to prioritize editor responsiveness.
        constexpr int kAutoFormatMaxChars = 2 * 1024 * 1024;
        if (inputText.size() > kAutoFormatMaxChars)
        {
            return inputText;
        }

        QString formattedText;
        if (tryFormatJsonText(inputText, &formattedText))
        {
            if (detectedKindOut != nullptr)
            {
                *detectedKindOut = QStringLiteral("JSON");
            }
            return formattedText;
        }

        if (tryFormatXmlText(inputText, &formattedText))
        {
            if (detectedKindOut != nullptr)
            {
                *detectedKindOut = QStringLiteral("XML");
            }
            return formattedText;
        }

        return inputText;
    }
}

namespace ks::ui
{
    QString localizeGeneratedReport(const QString& sourceText)
    {
        return ::localizeGeneratedReport(sourceText);
    }
}

class BracketHighlighter final : public QSyntaxHighlighter
{
public:
    // Constructor: binds the target text document.
    explicit BracketHighlighter(QTextDocument* document)
        : QSyntaxHighlighter(document)
    {
    }

protected:
    // highlightBlock: Set colors based on bracket type.
    void highlightBlock(const QString& text) override
    {
        QTextCharFormat roundFormat;
        roundFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, 22, -4));

        QTextCharFormat squareFormat;
        squareFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kGreen, 42, 16));

        QTextCharFormat braceFormat;
        braceFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kOrange, 38, 12));

        for (int index = 0; index < text.size(); ++index)
        {
            const QChar kCh = text.at(index);
            if (kCh == QChar('(') || kCh == QChar(')'))
            {
                setFormat(index, 1, roundFormat);
                continue;
            }
            if (kCh == QChar('[') || kCh == QChar(']'))
            {
                setFormat(index, 1, squareFormat);
                continue;
            }
            if (kCh == QChar('{') || kCh == QChar('}'))
            {
                setFormat(index, 1, braceFormat);
            }
        }
    }
};

class CodeTextEdit;

class LineNumberArea final : public QWidget
{
public:
    // Constructor: saves the main editor pointer.
    explicit LineNumberArea(CodeTextEdit* owner);

    // sizeHint: Returns the width of the line number area.
    QSize sizeHint() const override;

protected:
    // paintEvent: forwards to the main editor for unified painting.
    void paintEvent(QPaintEvent* event) override;

private:
    // m_owner: Main code editor.
    CodeTextEdit* owner_ = nullptr;
};

class CodeTextEdit final : public QPlainTextEdit
{
public:
    // Constructor: initialize line numbers, font, and bracket matching highlighting.
    explicit CodeTextEdit(QWidget* parent = nullptr)
        : QPlainTextEdit(parent)
    {
        QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        // When the system monospace font lacks Chinese glyphs, Windows falls back to SimSun; explicitly specify Microsoft YaHei for Chinese text.
        fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
        fixedFont.setPointSize(std::max(12, fixedFont.pointSize()));
        setFont(fixedFont);
        setTabStopDistance(QFontMetricsF(fixedFont).horizontalAdvance(QChar(' ')) * 4.0);
        setLineWrapMode(QPlainTextEdit::WidgetWidth);
        setFrameShape(QFrame::NoFrame);

        lineNumberArea_ = new LineNumberArea(this);
        bracketHighlighter_ = new BracketHighlighter(document());

        connect(this, &QPlainTextEdit::blockCountChanged, this, [this](int)
            {
                setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
            });

        connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, int deltaY)
            {
                if (deltaY != 0)
                {
                    lineNumberArea_->scroll(0, deltaY);
                }
                else
                {
                    lineNumberArea_->update(0, rect.y(), lineNumberArea_->width(), rect.height());
                }
                if (rect.contains(viewport()->rect()))
                {
                    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
                }
            });

        connect(this, &QPlainTextEdit::cursorPositionChanged, this, [this]()
            {
                refreshExtraSelections();
            });

        connect(this, &QPlainTextEdit::textChanged, this, [this]()
            {
                refreshExtraSelections();
            });

        setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
        refreshExtraSelections();
    }

    // Destructor: releases the bracket highlighter object.
    ~CodeTextEdit() override
    {
        delete bracketHighlighter_;
        bracketHighlighter_ = nullptr;
    }

    // lineNumberAreaWidth: Calculates line number width based on document line count.
    int lineNumberAreaWidth() const
    {
        int digits = 1;
        int maxLines = std::max(1, blockCount());
        while (maxLines >= 10)
        {
            maxLines /= 10;
            ++digits;
        }
        return 8 + fontMetrics().horizontalAdvance(QChar('9')) * digits;
    }

    // paintLineNumberArea: Draw line numbers for the visible area.
    void paintLineNumberArea(QPaintEvent* event)
    {
        QPainter painter(lineNumberArea_);
        painter.fillRect(event->rect(), ksword_theme::surfaceMutedColor());

        QTextBlock block = firstVisibleBlock();
        int blockNumber = block.blockNumber();
        int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());
        int bottom = top + static_cast<int>(blockBoundingRect(block).height());

        while (block.isValid() && top <= event->rect().bottom())
        {
            if (block.isVisible() && bottom >= event->rect().top())
            {
                painter.setPen(ksword_theme::textSecondaryColor());
                painter.drawText(
                    0,
                    top,
                    lineNumberArea_->width() - 4,
                    fontMetrics().height(),
                    Qt::AlignRight,
                    QString::number(blockNumber + 1));
            }

            block = block.next();
            top = bottom;
            bottom = top + static_cast<int>(blockBoundingRect(block).height());
            ++blockNumber;
        }
    }

    // gotoLine: Jump to the specified 1-based line number.
    bool gotoLine(int oneBasedLine)
    {
        if (oneBasedLine <= 0)
        {
            return false;
        }

        const QTextBlock kBlock = document()->findBlockByLineNumber(oneBasedLine - 1);
        if (!kBlock.isValid())
        {
            return false;
        }

        QTextCursor cursor(document());
        cursor.setPosition(kBlock.position());
        setTextCursor(cursor);
        centerCursor();
        return true;
    }

protected:
    // resizeEvent: Synchronize line number area geometry when the window changes.
    void resizeEvent(QResizeEvent* event) override
    {
        QPlainTextEdit::resizeEvent(event);
        const QRect kRect = contentsRect();
        lineNumberArea_->setGeometry(kRect.left(), kRect.top(), lineNumberAreaWidth(), kRect.height());
    }

private:
    // refreshExtraSelections: Highlights for the current line and bracket matching.
    void refreshExtraSelections()
    {
        QList<QTextEdit::ExtraSelection> extraSelections;

        QTextEdit::ExtraSelection lineSelection;
        lineSelection.cursor = textCursor();
        lineSelection.cursor.clearSelection();
        lineSelection.format.setProperty(QTextFormat::FullWidthSelection, true);
        lineSelection.format.setBackground(ksword_theme::primaryBlueSubtleColor());
        extraSelections.push_back(lineSelection);

        const QString kAllText = toPlainText();
        if (!kAllText.isEmpty())
        {
            int bracketPos = -1;
            QChar bracketCh;
            const int kCursorPos = textCursor().position();

            if (kCursorPos > 0 && (isOpenBracket(kAllText.at(kCursorPos - 1)) || isCloseBracket(kAllText.at(kCursorPos - 1))))
            {
                bracketPos = kCursorPos - 1;
                bracketCh = kAllText.at(bracketPos);
            }
            else if (kCursorPos < kAllText.size() && (isOpenBracket(kAllText.at(kCursorPos)) || isCloseBracket(kAllText.at(kCursorPos))))
            {
                bracketPos = kCursorPos;
                bracketCh = kAllText.at(bracketPos);
            }

            if (bracketPos >= 0)
            {
                int pairPos = -1;
                const QChar kPairCh = pairBracket(bracketCh);
                if (isOpenBracket(bracketCh))
                {
                    int depth = 0;
                    for (int i = bracketPos; i < kAllText.size(); ++i)
                    {
                        if (kAllText.at(i) == bracketCh) ++depth;
                        if (kAllText.at(i) == kPairCh) --depth;
                        if (depth == 0)
                        {
                            pairPos = i;
                            break;
                        }
                    }
                }
                else
                {
                    int depth = 0;
                    for (int i = bracketPos; i >= 0; --i)
                    {
                        if (kAllText.at(i) == bracketCh) ++depth;
                        if (kAllText.at(i) == kPairCh) --depth;
                        if (depth == 0)
                        {
                            pairPos = i;
                            break;
                        }
                    }
                }

                auto appendBracketSelection = [this, &extraSelections](int pos, const QColor& bg)
                    {
                        QTextEdit::ExtraSelection sel;
                        sel.cursor = textCursor();
                        sel.cursor.setPosition(pos);
                        sel.cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
                        // The background color may be the selection blue or the error red used for mismatched parentheses;
                        // Foreground must be calculated based on the actual background color; do not use the parameter-less version calibrated for accent colors.
                        sel.format.setForeground(ksword_theme::onAccentColor(bg));
                        sel.format.setBackground(bg);
                        extraSelections.push_back(sel);
                    };

                const QColor kMatchedBg = ksword_theme::editorSelectionColor();
                appendBracketSelection(bracketPos, pairPos >= 0 ? kMatchedBg : ksword_theme::errorColor());
                if (pairPos >= 0)
                {
                    appendBracketSelection(pairPos, kMatchedBg);
                }
            }
        }

        setExtraSelections(extraSelections);
    }

private:
    // m_lineNumberArea: Line number area.
    QWidget* lineNumberArea_ = nullptr;

    // m_bracketHighlighter: Bracket highlighter.
    BracketHighlighter* bracketHighlighter_ = nullptr;

    friend class LineNumberArea;
};

QSize LineNumberArea::sizeHint() const
{
    if (owner_ == nullptr)
    {
        return QSize(0, 0);
    }
    return QSize(owner_->lineNumberAreaWidth(), 0);
}

LineNumberArea::LineNumberArea(CodeTextEdit* owner)
    : QWidget(owner)
    , owner_(owner)
{
}

void LineNumberArea::paintEvent(QPaintEvent* event)
{
    if (owner_ != nullptr)
    {
        owner_->paintLineNumberArea(event);
    }
}

CodeEditorWidget::CodeEditorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    applyThemeStyle();
    refreshReadOnlyUiState();
    updateStatusText();
}

CodeEditorWidget::~CodeEditorWidget()
{
    // Destruction guard:
    // - Input: Qt parent-child destruction chain triggers destruction.
    // - Processing: Mark as destroying first, then disconnect the state refresh signals sent from the editor to this component;
    // - Return: None. Child controls are still reclaimed by Qt's parent-child mechanism.
    destroying_ = true;
    if (editor_ != nullptr)
    {
        QObject::disconnect(editor_, nullptr, this, nullptr);
    }
}

QString CodeEditorWidget::text() const
{
    return (editor_ == nullptr) ? QString() : editor_->toPlainText();
}

void CodeEditorWidget::setText(const QString& plainText)
{
    if (readOnlyMode_)
    {
        setLocalizedText(plainText);
        return;
    }

    setRawText(plainText);
}

void CodeEditorWidget::setRawText(const QString& plainText)
{
    localizedSourceText_.clear();
    localizedRawSuffix_.clear();
    localizedTextActive_ = false;
    if (editor_ == nullptr)
    {
        return;
    }

    editor_->setPlainText(applyStructuredAutoFormatIfNeeded(plainText));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::setLocalizedText(const QString& sourceText)
{
    localizedSourceText_ = sourceText;
    localizedRawSuffix_.clear();
    localizedTextActive_ = true;
    if (editor_ == nullptr)
    {
        return;
    }

    editor_->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(localizedSourceText_) + localizedRawSuffix_));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::setLocalizedTextWithRawSuffix(
    const QString& sourceText,
    const QString& rawSuffix)
{
    localizedSourceText_ = sourceText;
    localizedRawSuffix_ = rawSuffix;
    localizedTextActive_ = true;
    if (editor_ == nullptr)
    {
        return;
    }

    editor_->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(localizedSourceText_) + localizedRawSuffix_));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange ||
        !localizedTextActive_ || editor_ == nullptr)
    {
        return;
    }

    const int kVerticalScrollValue = editor_->verticalScrollBar()->value();
    const int kHorizontalScrollValue = editor_->horizontalScrollBar()->value();
    editor_->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(localizedSourceText_) + localizedRawSuffix_));
    editor_->verticalScrollBar()->setValue(kVerticalScrollValue);
    editor_->horizontalScrollBar()->setValue(kHorizontalScrollValue);
    updateStatusText();
}

QString CodeEditorWidget::currentFilePath() const
{
    return currentFilePath_;
}

void CodeEditorWidget::setCurrentFilePath(const QString& filePath)
{
    currentFilePath_ = filePath;
    updateStatusText();
}

void CodeEditorWidget::setReadOnly(const bool readOnly)
{
    if (readOnlyMode_ == readOnly)
    {
        return;
    }

    readOnlyMode_ = readOnly;
    refreshReadOnlyUiState();
    updateStatusText();
}

bool CodeEditorWidget::isReadOnly() const
{
    return readOnlyMode_;
}

void CodeEditorWidget::setStructuredReportViewEnabled(const bool enabled)
{
    if (structuredViewEnabled_ == enabled)
    {
        return;
    }

    structuredViewEnabled_ = enabled;
    updateStructuredReportView();
}

QString CodeEditorWidget::currentEncodingDisplayText() const
{
    return fileSessionAvailable_
        ? buildEncodingDisplayText(fileEncoding_, fileHasBom_)
        : QStringLiteral("未知");
}

bool CodeEditorWidget::openLocalFile(const QString& filePath)
{
    return loadLocalFile(filePath, false, QStringConverter::Utf8);
}

bool CodeEditorWidget::openLocalFileWithEncoding(const QString& filePath, const QStringConverter::Encoding encoding)
{
    return loadLocalFile(filePath, true, encoding);
}

bool CodeEditorWidget::reopenCurrentFileWithEncoding(const QStringConverter::Encoding encoding)
{
    if (currentFilePath_.trimmed().isEmpty())
    {
        statusLabel_->setText(QStringLiteral("重开失败：当前无文件路径。"));
        return false;
    }

    return loadLocalFile(currentFilePath_, true, encoding);
}

void CodeEditorWidget::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(6);

    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(4);

    // buildButton：
    // - Unify tool button construction.
    // - All button icons are fixed SVG icons from the qrc icon library.
    auto buildButton = [this](const QString& iconPath, const QString& tip) -> QToolButton*
        {
            QToolButton* button = new QToolButton(toolbarWidget_);
            button->setIcon(buildToolbarSvgIcon(iconPath));
            button->setIconSize(QSize(22, 22));
            button->setToolTip(tip);
            button->setAutoRaise(true);
            button->setFixedSize(24, 24);
            return button;
        };

    // Toolbar icon semantic mapping:
    // - Correspond one-to-one with the functionality to avoid misleading use of MainLogo.
    newButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_new.svg"), QStringLiteral("新建 Ctrl+N"));
    openButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_open.svg"), QStringLiteral("打开 Ctrl+O"));
    saveButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_save.svg"), QStringLiteral("保存 Ctrl+S"));
    saveAsButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_save_as.svg"), QStringLiteral("另存为 Ctrl+Shift+S"));
    undoButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_undo.svg"), QStringLiteral("撤销 Ctrl+Z"));
    redoButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_redo.svg"), QStringLiteral("重做 Ctrl+Y"));
    cutButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_cut.svg"), QStringLiteral("剪切 Ctrl+X"));
    copyButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_copy.svg"), QStringLiteral("复制 Ctrl+C"));
    pasteButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_paste.svg"), QStringLiteral("粘贴 Ctrl+V"));
    findButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_find.svg"), QStringLiteral("查找 Ctrl+F"));
    replaceButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_replace.svg"), QStringLiteral("替换 Ctrl+H"));
    gotoButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_goto.svg"), QStringLiteral("跳转行 Ctrl+G"));
    wrapButton_ = buildButton(QStringLiteral(":/Icon/codeeditor_wrap.svg"), QStringLiteral("切换自动换行"));

    toolbarLayout_->addWidget(newButton_);
    toolbarLayout_->addWidget(openButton_);
    toolbarLayout_->addWidget(saveButton_);
    toolbarLayout_->addWidget(saveAsButton_);
    toolbarLayout_->addSpacing(4);
    toolbarLayout_->addWidget(undoButton_);
    toolbarLayout_->addWidget(redoButton_);
    toolbarLayout_->addWidget(cutButton_);
    toolbarLayout_->addWidget(copyButton_);
    toolbarLayout_->addWidget(pasteButton_);
    toolbarLayout_->addSpacing(4);
    toolbarLayout_->addWidget(findButton_);
    toolbarLayout_->addWidget(replaceButton_);
    toolbarLayout_->addWidget(gotoButton_);
    toolbarLayout_->addWidget(wrapButton_);
    toolbarLayout_->addStretch(1);
    rootLayout_->addWidget(toolbarWidget_);

    findPanel_ = new QWidget(this);
    findLayout_ = new QHBoxLayout(findPanel_);
    findLayout_->setContentsMargins(0, 0, 0, 0);
    findLayout_->setSpacing(4);

    findEdit_ = new QLineEdit(findPanel_);
    findEdit_->setPlaceholderText(QStringLiteral("查找"));
    replaceEdit_ = new QLineEdit(findPanel_);
    replaceEdit_->setPlaceholderText(QStringLiteral("替换为"));

    findPrevButton_ = new QToolButton(findPanel_);
    findPrevButton_->setText(QStringLiteral("↑"));
    findPrevButton_->setToolTip(QStringLiteral("向上查找上一个匹配项"));
    findNextButton_ = new QToolButton(findPanel_);
    findNextButton_->setText(QStringLiteral("↓"));
    findNextButton_->setToolTip(QStringLiteral("向下查找下一个匹配项"));
    replaceOneButton_ = new QToolButton(findPanel_);
    replaceOneButton_->setText(QStringLiteral("替换"));
    replaceOneButton_->setToolTip(QStringLiteral("替换当前这一处匹配，并跳到下一处"));
    replaceAllButton_ = new QToolButton(findPanel_);
    replaceAllButton_->setText(QStringLiteral("全部"));
    replaceAllButton_->setToolTip(QStringLiteral("一次性替换文中所有匹配项"));
    findCloseButton_ = new QToolButton(findPanel_);
    findCloseButton_->setText(QStringLiteral("关闭"));
    findCloseButton_->setToolTip(QStringLiteral("关闭查找替换栏"));

    findLayout_->addWidget(findEdit_, 1);
    findLayout_->addWidget(replaceEdit_, 1);
    findLayout_->addWidget(findPrevButton_);
    findLayout_->addWidget(findNextButton_);
    findLayout_->addWidget(replaceOneButton_);
    findLayout_->addWidget(replaceAllButton_);
    findLayout_->addWidget(findCloseButton_);
    findPanel_->setVisible(false);
    rootLayout_->addWidget(findPanel_);

    gotoPanel_ = new QWidget(this);
    gotoLayout_ = new QHBoxLayout(gotoPanel_);
    gotoLayout_->setContentsMargins(0, 0, 0, 0);
    gotoLayout_->setSpacing(4);
    gotoLineEdit_ = new QLineEdit(gotoPanel_);
    gotoLineEdit_->setPlaceholderText(QStringLiteral("行号(从1开始)"));
    gotoApplyButton_ = new QToolButton(gotoPanel_);
    gotoApplyButton_->setText(QStringLiteral("执行"));
    gotoApplyButton_->setToolTip(QStringLiteral("跳转到左侧输入的行号"));
    gotoCloseButton_ = new QToolButton(gotoPanel_);
    gotoCloseButton_->setText(QStringLiteral("关闭"));
    gotoCloseButton_->setToolTip(QStringLiteral("关闭跳转行栏"));
    gotoLayout_->addWidget(new QLabel(QStringLiteral("跳转行:"), gotoPanel_));
    gotoLayout_->addWidget(gotoLineEdit_, 1);
    gotoLayout_->addWidget(gotoApplyButton_);
    gotoLayout_->addWidget(gotoCloseButton_);
    gotoPanel_->setVisible(false);
    rootLayout_->addWidget(gotoPanel_);

    editor_ = new CodeTextEdit(this);
    editor_->setPlaceholderText(QStringLiteral("即时窗口：支持行号、括号匹配、查找替换、跳转行。"));

    // Plain text and structured views overlap at the same position: switching only changes the page, leaving the outer layout and splitter ratios unchanged.
    viewStack_ = new QStackedWidget(this);
    structuredView_ = new ks::ui::ReportStructuredView(viewStack_);
    viewStack_->addWidget(editor_);
    viewStack_->addWidget(structuredView_);
    viewStack_->setCurrentWidget(editor_);
    rootLayout_->addWidget(viewStack_, 1);

    // The switch control floats at the top-right of the content area, rather than being mixed with the row of edit actions at the top:
    // It toggles 'how to view this content', which is not a category with New/Save/Clipboard operations; placing it in the content's own corner makes it easier to find.
    // Use a dropdown instead of buttons: both options are visible at a glance, showing the current state and available transitions immediately. This maintains consistency
    // with the toggle pattern used on the file's regular page. The control is not part of the layout; it is positioned in the corner by positionStructuredSwitch.
    structuredCombo_ = new QComboBox(viewStack_);
    structuredCombo_->addItem(QStringLiteral("结构视图"));
    structuredCombo_->addItem(QStringLiteral("原始文本"));
    structuredCombo_->setCursor(Qt::PointingHandCursor);
    structuredCombo_->setToolTip(
        QStringLiteral("在结构视图与原始文本之间切换：结构视图按字段和表格解析当前报告，原始文本保留完整报告便于全文检索和整段复制"));
    // The floating control overlays the main text and must have an opaque background color and border; otherwise, it becomes unreadable when stacked over property table rows.
    structuredCombo_->setStyleSheet(buildFloatingSwitchStyle());
    // Hidden by default at entry: only revealed by updateStructuredReportView when the content is a truly parseable read-only report.
    structuredCombo_->setVisible(false);
    // m_viewStack: Corner rounding must be reapplied on page switches or size changes; using an event filter is more efficient and less error-prone than connecting to each page individually.
    viewStack_->installEventFilter(this);

    statusLabel_ = new QLabel(QStringLiteral("就绪。"), this);
    rootLayout_->addWidget(statusLabel_);
}

void CodeEditorWidget::initializeConnections()
{
    connect(newButton_, &QToolButton::clicked, this, [this]()
        {
            if (readOnlyMode_)
            {
                return;
            }
            editor_->clear();
            currentFilePath_.clear();
            resetFileSessionMetadata();
            updateStatusText();
        });

    connect(openButton_, &QToolButton::clicked, this, [this]()
        {
            openTextFile();
        });

    connect(saveButton_, &QToolButton::clicked, this, [this]()
        {
            saveTextFile(false);
        });

    connect(saveAsButton_, &QToolButton::clicked, this, [this]()
        {
            saveTextFile(true);
        });

    connect(undoButton_, &QToolButton::clicked, editor_, &QPlainTextEdit::undo);
    connect(redoButton_, &QToolButton::clicked, editor_, &QPlainTextEdit::redo);
    connect(cutButton_, &QToolButton::clicked, editor_, &QPlainTextEdit::cut);
    connect(copyButton_, &QToolButton::clicked, editor_, &QPlainTextEdit::copy);
    connect(pasteButton_, &QToolButton::clicked, editor_, &QPlainTextEdit::paste);

    connect(findButton_, &QToolButton::clicked, this, [this]()
        {
            openFindReplacePanel(false);
        });

    connect(replaceButton_, &QToolButton::clicked, this, [this]()
        {
            openFindReplacePanel(true);
        });

    connect(gotoButton_, &QToolButton::clicked, this, [this]()
        {
            openGotoPanel();
        });

    connect(wrapButton_, &QToolButton::clicked, this, [this]()
        {
            const bool kEnableWrap = (editor_->lineWrapMode() == QPlainTextEdit::NoWrap);
            editor_->setLineWrapMode(kEnableWrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap);
        });

    connect(findPrevButton_, &QToolButton::clicked, this, [this]()
        {
            findByDirection(false);
        });

    connect(findNextButton_, &QToolButton::clicked, this, [this]()
        {
            findByDirection(true);
        });

    connect(replaceOneButton_, &QToolButton::clicked, this, [this]()
        {
            replaceCurrentSelection();
        });

    connect(replaceAllButton_, &QToolButton::clicked, this, [this]()
        {
            const int kReplacedCount = replaceAllMatches();
            statusLabel_->setText(QStringLiteral("替换完成：%1 处。").arg(kReplacedCount));
        });

    connect(findCloseButton_, &QToolButton::clicked, this, [this]()
        {
            findPanel_->setVisible(false);
        });

    connect(findEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            findByDirection(true);
        });

    connect(gotoApplyButton_, &QToolButton::clicked, this, [this]()
        {
            jumpToInputLine();
        });

    connect(gotoCloseButton_, &QToolButton::clicked, this, [this]()
        {
            gotoPanel_->setVisible(false);
        });

    connect(gotoLineEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            jumpToInputLine();
        });

    connect(editor_, &QPlainTextEdit::cursorPositionChanged, this, [this]()
        {
            updateStatusText();
        });

    connect(editor_, &QPlainTextEdit::textChanged, this, [this]()
        {
            updateStatusText();
            updateStructuredReportView();
            emit contentChanged(text());
        });

    connect(structuredCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](const int selectedIndex)
        {
            if (destroying_ || viewStack_ == nullptr || structuredView_ == nullptr)
            {
                return;
            }
            // The index aligns with the standard tab switching logic: 0 = structured view, 1 = raw text.
            const bool kStructuredSelected = selectedIndex == 0;
            // Selection is process-local: this is 'how I want to view this investigation', not a persistent preference.
            gPreferStructuredReportView = kStructuredSelected;
            viewStack_->setCurrentWidget(kStructuredSelected
                ? static_cast<QWidget*>(structuredView_)
                : static_cast<QWidget*>(editor_));
            // After switching pages, the scrollbar may appear or disappear; recalculate the right margin.
            positionStructuredSwitch();
        });

    new QShortcut(QKeySequence::Find, this, [this]()
        {
            openFindReplacePanel(false);
        });

    new QShortcut(QKeySequence::Replace, this, [this]()
        {
            openFindReplacePanel(true);
        });

    new QShortcut(QKeySequence(QStringLiteral("Ctrl+G")), this, [this]()
        {
            openGotoPanel();
        });

    new QShortcut(QKeySequence::FindNext, this, [this]()
        {
            findByDirection(true);
        });

    new QShortcut(QKeySequence::FindPrevious, this, [this]()
        {
            findByDirection(false);
        });

    new QShortcut(QKeySequence::Save, this, [this]()
        {
            saveTextFile(false);
        });

    new QShortcut(QKeySequence::Open, this, [this]()
        {
            openTextFile();
        });

    new QShortcut(QKeySequence::New, this, [this]()
        {
            newButton_->click();
        });
}

void CodeEditorWidget::applyThemeStyle()
{
    const QString kToolStyle = buildToolButtonStyle();
    const QString kInputStyle = buildInputStyle();

    const QList<QToolButton*> kButtonList{
        newButton_,openButton_,saveButton_,saveAsButton_,undoButton_,redoButton_,cutButton_,copyButton_,pasteButton_,
        findButton_,replaceButton_,gotoButton_,wrapButton_,findPrevButton_,findNextButton_,replaceOneButton_,replaceAllButton_,
        findCloseButton_,gotoApplyButton_,gotoCloseButton_
    };
    for (QToolButton* button : kButtonList)
    {
        if (button != nullptr)
        {
            button->setStyleSheet(kToolStyle);
        }
    }

    // The floating switch box is not in the previous set: it overlays the main text and uses a distinct style with its own background color and border.
    if (structuredCombo_ != nullptr)
    {
        structuredCombo_->setStyleSheet(buildFloatingSwitchStyle());
    }

    findEdit_->setStyleSheet(kInputStyle);
    replaceEdit_->setStyleSheet(kInputStyle);
    gotoLineEdit_->setStyleSheet(kInputStyle);
}

void CodeEditorWidget::refreshReadOnlyUiState()
{
    if (editor_ != nullptr)
    {
        editor_->setReadOnly(readOnlyMode_);
    }

    // Write button: disable all in read-only mode.
    if (newButton_ != nullptr) newButton_->setEnabled(!readOnlyMode_);
    if (openButton_ != nullptr) openButton_->setEnabled(!readOnlyMode_);
    if (saveButton_ != nullptr) saveButton_->setEnabled(!readOnlyMode_);
    if (saveAsButton_ != nullptr) saveAsButton_->setEnabled(!readOnlyMode_);
    if (undoButton_ != nullptr) undoButton_->setEnabled(!readOnlyMode_);
    if (redoButton_ != nullptr) redoButton_->setEnabled(!readOnlyMode_);
    if (cutButton_ != nullptr) cutButton_->setEnabled(!readOnlyMode_);
    if (pasteButton_ != nullptr) pasteButton_->setEnabled(!readOnlyMode_);
    if (replaceButton_ != nullptr) replaceButton_->setEnabled(!readOnlyMode_);
    if (replaceOneButton_ != nullptr) replaceOneButton_->setEnabled(!readOnlyMode_);
    if (replaceAllButton_ != nullptr) replaceAllButton_->setEnabled(!readOnlyMode_);

    // In read-only mode, hide the replace input while retaining search and jump capabilities.
    if (readOnlyMode_)
    {
        replaceEdit_->setVisible(false);
        replaceOneButton_->setVisible(false);
        replaceAllButton_->setVisible(false);
    }

    // The page is often set to read-only after text is written; add a check here to ensure the structured view entry is not missed.
    updateStructuredReportView();
}

bool CodeEditorWidget::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (!destroying_ &&
        watchedObject == viewStack_ &&
        eventObject != nullptr &&
        (eventObject->type() == QEvent::Resize || eventObject->type() == QEvent::Show))
    {
        positionStructuredSwitch();
    }
    return QWidget::eventFilter(watchedObject, eventObject);
}

void CodeEditorWidget::positionStructuredSwitch()
{
    if (destroying_ || structuredCombo_ == nullptr || viewStack_ == nullptr)
    {
        return;
    }

    // The right margin must avoid the currently visible vertical scrollbar: overlapping it would turn the scrollbar into a false-click area.
    int rightMargin = 12;
    const QWidget* currentPage = viewStack_->currentWidget();
    if (currentPage == editor_ && editor_ != nullptr &&
        editor_->verticalScrollBar() != nullptr &&
        editor_->verticalScrollBar()->isVisible())
    {
        rightMargin += editor_->verticalScrollBar()->width();
    }
    else if (currentPage == structuredView_ && structuredView_ != nullptr)
    {
        rightMargin += structuredView_->verticalScrollBarWidth();
    }

    const QSize kSwitchSize = structuredCombo_->sizeHint();
    structuredCombo_->setGeometry(
        viewStack_->width() - kSwitchSize.width() - rightMargin,
        10,
        kSwitchSize.width(),
        kSwitchSize.height());
    structuredCombo_->raise();
}

void CodeEditorWidget::updateStructuredReportView()
{
    if (destroying_ ||
        editor_ == nullptr ||
        viewStack_ == nullptr ||
        structuredView_ == nullptr ||
        structuredCombo_ == nullptr)
    {
        return;
    }

    // Parse only read-only reports: files being edited by the user, raw logs, and byte views remain as plain text.
    const QString kCurrentText = editor_->toPlainText();
    const bool kEligible =
        structuredViewEnabled_ && readOnlyMode_ && !kCurrentText.trimmed().isEmpty();
    const bool kStructured = kEligible && structuredView_->setReportText(kCurrentText);

    structuredCombo_->setVisible(kStructured);
    if (!kStructured)
    {
        viewStack_->setCurrentWidget(editor_);
        return;
    }

    // This restores the view based on program memory, not user selection; signals are blocked to prevent writing the state back to global preferences.
    const QSignalBlocker kSwitchSignalBlocker(structuredCombo_);
    structuredCombo_->setCurrentIndex(gPreferStructuredReportView ? 0 : 1);
    viewStack_->setCurrentWidget(gPreferStructuredReportView
        ? static_cast<QWidget*>(structuredView_)
        : static_cast<QWidget*>(editor_));
    positionStructuredSwitch();
}

void CodeEditorWidget::openFindReplacePanel(const bool replaceEnabled)
{
    const bool kEffectiveReplaceEnabled = replaceEnabled && !readOnlyMode_;
    replaceEnabled_ = kEffectiveReplaceEnabled;
    findPanel_->setVisible(true);
    gotoPanel_->setVisible(false);
    replaceEdit_->setVisible(kEffectiveReplaceEnabled);
    replaceOneButton_->setVisible(kEffectiveReplaceEnabled);
    replaceAllButton_->setVisible(kEffectiveReplaceEnabled);
    findEdit_->setFocus(Qt::ShortcutFocusReason);
    findEdit_->selectAll();
}

void CodeEditorWidget::openGotoPanel()
{
    findPanel_->setVisible(false);
    gotoPanel_->setVisible(true);
    gotoLineEdit_->setFocus(Qt::ShortcutFocusReason);
    gotoLineEdit_->selectAll();
}

void CodeEditorWidget::closeInlinePanels()
{
    findPanel_->setVisible(false);
    gotoPanel_->setVisible(false);
}

void CodeEditorWidget::updateStatusText()
{
    // Exit guard:
    // - During mainWindow destruction, QPlainTextEdit may still emit cursor/textChanged signals.
    // - At this point, m_editor or m_statusLabel has already entered the Qt sub-object destruction chain; continuing to access cursor/setText will trigger a breakpoint exception.
    // - Skip immediately during destruction or if critical child controls are null; behavior remains unchanged during normal operation.
    if (destroying_ || editor_ == nullptr || statusLabel_ == nullptr)
    {
        return;
    }

    const QTextCursor kCursor = editor_->textCursor();
    const QString kFileName = currentFilePath_.trimmed().isEmpty() ? QStringLiteral("<未命名>") : currentFilePath_;
    statusLabel_->setText(QStringLiteral("行:%1 列:%2 字符:%3 文件:%4 模式:%5 编码:%6")
        .arg(kCursor.blockNumber() + 1)
        .arg(kCursor.positionInBlock() + 1)
        .arg(editor_->toPlainText().size())
        .arg(kFileName)
        .arg(readOnlyMode_ ? QStringLiteral("只读") : QStringLiteral("可编辑"))
        .arg(currentEncodingDisplayText()));
}

bool CodeEditorWidget::findByDirection(const bool forward)
{
    const QString kKeyText = findEdit_->text();
    if (kKeyText.isEmpty())
    {
        statusLabel_->setText(QStringLiteral("查找失败：请输入查找内容。"));
        return false;
    }

    QTextDocument::FindFlags flags;
    if (!forward) flags |= QTextDocument::FindBackward;

    bool found = editor_->find(kKeyText, flags);
    if (!found)
    {
        QTextCursor cursor = editor_->textCursor();
        cursor.movePosition(forward ? QTextCursor::Start : QTextCursor::End);
        editor_->setTextCursor(cursor);
        found = editor_->find(kKeyText, flags);
    }

    statusLabel_->setText(found
        ? QStringLiteral("查找成功：%1").arg(kKeyText)
        : QStringLiteral("查找结束：未找到 %1").arg(kKeyText));
    return found;
}

void CodeEditorWidget::replaceCurrentSelection()
{
    if (readOnlyMode_)
    {
        return;
    }

    const QString kFindText = findEdit_->text();
    if (kFindText.isEmpty())
    {
        statusLabel_->setText(QStringLiteral("替换失败：查找文本为空。"));
        return;
    }

    QTextCursor cursor = editor_->textCursor();
    if (!cursor.hasSelection() || cursor.selectedText() != kFindText)
    {
        if (!findByDirection(true))
        {
            return;
        }
        cursor = editor_->textCursor();
    }

    cursor.insertText(replaceEdit_->text());
    editor_->setTextCursor(cursor);
    statusLabel_->setText(QStringLiteral("已替换当前命中。"));
    findByDirection(true);
}

int CodeEditorWidget::replaceAllMatches()
{
    if (readOnlyMode_)
    {
        return 0;
    }

    const QString kFindText = findEdit_->text();
    if (kFindText.isEmpty())
    {
        return 0;
    }

    const QString kReplaceText = replaceEdit_->text();
    QTextCursor backupCursor = editor_->textCursor();
    QTextCursor headCursor = editor_->textCursor();
    headCursor.movePosition(QTextCursor::Start);
    editor_->setTextCursor(headCursor);

    int hitCount = 0;
    while (editor_->find(kFindText))
    {
        QTextCursor hitCursor = editor_->textCursor();
        hitCursor.insertText(kReplaceText);
        ++hitCount;
    }

    editor_->setTextCursor(backupCursor);
    return hitCount;
}

void CodeEditorWidget::jumpToInputLine()
{
    bool parseOk = false;
    const int kLineNumber = gotoLineEdit_->text().trimmed().toInt(&parseOk, 10);
    if (!parseOk)
    {
        statusLabel_->setText(QStringLiteral("跳转失败：行号格式无效。"));
        return;
    }

    if (!editor_->gotoLine(kLineNumber))
    {
        statusLabel_->setText(QStringLiteral("跳转失败：行号越界。"));
        return;
    }

    gotoPanel_->setVisible(false);
    statusLabel_->setText(QStringLiteral("已跳转到第 %1 行。").arg(kLineNumber));
}

void CodeEditorWidget::openTextFile()
{
    if (readOnlyMode_)
    {
        return;
    }

    const QString kFilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("打开文本"),
        QString(),
        QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));

    if (kFilePath.trimmed().isEmpty())
    {
        return;
    }

    openLocalFile(kFilePath);
}

bool CodeEditorWidget::loadLocalFile(
    const QString& filePath,
    const bool forceEncoding,
    const QStringConverter::Encoding forcedEncoding)
{
    const QString kNormalizedPath = filePath.trimmed();
    if (kNormalizedPath.isEmpty())
    {
        statusLabel_->setText(QStringLiteral("打开失败：文件路径为空。"));
        return false;
    }

    QFile inputFile(kNormalizedPath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        statusLabel_->setText(QStringLiteral("打开失败：无法读取文件。"));
        return false;
    }

    const QByteArray kFileBytes = inputFile.readAll();
    inputFile.close();

    const FileDecodeResult kDecodeResult = forceEncoding
        ? decodeTextFileBytesForced(kFileBytes, forcedEncoding)
        : decodeTextFileBytesAuto(kFileBytes);

    if (!kDecodeResult.success)
    {
        statusLabel_->setText(QStringLiteral("打开失败：解码失败。"));
        return false;
    }

    QString detectedKind;
    const QString kDisplayText = applyStructuredAutoFormatIfNeeded(kDecodeResult.text, &detectedKind);
    editor_->setPlainText(kDisplayText);

    currentFilePath_ = kNormalizedPath;
    fileEncoding_ = kDecodeResult.encoding;
    fileHasBom_ = kDecodeResult.hasBom;
    fileLineEnding_ = kDecodeResult.lineEndingText;
    fileSessionAvailable_ = true;

    const QString kAutoFormatHint = detectedKind.isEmpty()
        ? QString()
        : QStringLiteral("，已自动格式化%1").arg(detectedKind);
    statusLabel_->setText(QStringLiteral("打开成功：%1（%2%3）")
        .arg(kNormalizedPath)
        .arg(currentEncodingDisplayText())
        .arg(kAutoFormatHint));
    return true;
}

void CodeEditorWidget::saveTextFile(const bool forceSaveAs)
{
    if (readOnlyMode_)
    {
        return;
    }

    QString targetPath = currentFilePath_;
    if (forceSaveAs || targetPath.trimmed().isEmpty())
    {
        targetPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("保存文本"),
            targetPath.trimmed().isEmpty() ? QStringLiteral("immediate.txt") : targetPath,
            QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));
    }

    if (targetPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(targetPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        statusLabel_->setText(QStringLiteral("保存失败：无法写入文件。"));
        return;
    }

    const QStringConverter::Encoding kTargetEncoding = fileSessionAvailable_
        ? fileEncoding_
        : QStringConverter::Utf8;
    const bool kTargetHasBom = fileSessionAvailable_ ? fileHasBom_ : false;
    const QString kTargetLineEnding = fileLineEnding_.isEmpty()
        ? detectDominantLineEnding(editor_->toPlainText())
        : fileLineEnding_;
    const QString kNormalizedText = normalizeLineEndingForSaving(editor_->toPlainText(), kTargetLineEnding);

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(kTargetEncoding);
    outputStream.setGenerateByteOrderMark(kTargetHasBom);
    outputStream << kNormalizedText;
    outputStream.flush();
    outputFile.close();

    currentFilePath_ = targetPath;
    fileEncoding_ = kTargetEncoding;
    fileHasBom_ = kTargetHasBom;
    fileLineEnding_ = kTargetLineEnding;
    fileSessionAvailable_ = true;
    updateStatusText();
    statusLabel_->setText(QStringLiteral("保存成功：%1（%2）").arg(targetPath, currentEncodingDisplayText()));
}

void CodeEditorWidget::resetFileSessionMetadata()
{
    fileEncoding_ = QStringConverter::Utf8;
    fileHasBom_ = false;
    fileLineEnding_ = QStringLiteral("\n");
    fileSessionAvailable_ = false;
}

QString CodeEditorWidget::applyStructuredAutoFormatIfNeeded(const QString& inputText, QString* detectedKindOut) const
{
    return autoFormatStructuredText(inputText, detectedKindOut);
}
