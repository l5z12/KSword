#include "CodeTextEdit.h"

// ============================================================
// CodeTextEdit.cpp
// Purpose:
// - Implement line number rendering, bracket matching, and highlight merging for CodeTextEdit;
// - Extract text control details from CodeEditorWidget.cpp to reduce single-file size;
// - Maintain visual styles consistent with the theme system.
// ============================================================

#include "../Theme.h"

#include <QFontDatabase>
#include <QFrame>
#include <QPaintEvent>
#include <QPainter>
#include <QResizeEvent>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextDocument>
#include <QTimer>

#include <algorithm>

namespace
{
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
    // - Returns the paired character for the bracket.
    QChar pairBracket(const QChar ch)
    {
        if (ch == QChar('(')) return QChar(')');
        if (ch == QChar('[')) return QChar(']');
        if (ch == QChar('{')) return QChar('}');
        if (ch == QChar(')')) return QChar('(');
        if (ch == QChar(']')) return QChar('[');
        if (ch == QChar('}')) return QChar('{');
        return QChar();
    }
}

class BracketHighlighter final : public QSyntaxHighlighter
{
public:
    // Constructor: binds to the target document.
    explicit BracketHighlighter(QTextDocument* documentPointer)
        : QSyntaxHighlighter(documentPointer)
    {
    }

protected:
    // highlightBlock：
    // - Set colors based on bracket type to improve structural readability.
    void highlightBlock(const QString& textValue) override
    {
        QTextCharFormat roundFormat;
        roundFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, 22, -4));

        QTextCharFormat squareFormat;
        squareFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kGreen, 42, 16));

        QTextCharFormat braceFormat;
        braceFormat.setForeground(ksword_theme::accentColor(ksword_theme::AccentRole::kOrange, 38, 12));

        for (int index = 0; index < textValue.size(); ++index)
        {
            const QChar kCurrentChar = textValue.at(index);
            if (kCurrentChar == QChar('(') || kCurrentChar == QChar(')'))
            {
                setFormat(index, 1, roundFormat);
                continue;
            }
            if (kCurrentChar == QChar('[') || kCurrentChar == QChar(']'))
            {
                setFormat(index, 1, squareFormat);
                continue;
            }
            if (kCurrentChar == QChar('{') || kCurrentChar == QChar('}'))
            {
                setFormat(index, 1, braceFormat);
            }
        }
    }
};

class LineNumberArea final : public QWidget
{
public:
    // Constructor: saves the main editor pointer.
    explicit LineNumberArea(CodeTextEdit* ownerPointer)
        : QWidget(ownerPointer)
        , owner_(ownerPointer)
    {
    }

    // sizeHint: returns the suggested width of the line number area.
    QSize sizeHint() const override
    {
        if (owner_ == nullptr)
        {
            return QSize(0, 0);
        }
        return QSize(owner_->lineNumberAreaWidth(), 0);
    }

protected:
    // paintEvent: forwards to the main editor for unified painting.
    void paintEvent(QPaintEvent* eventPointer) override
    {
        if (owner_ != nullptr)
        {
            owner_->paintLineNumberArea(eventPointer);
        }
    }

private:
    // m_owner: Pointer to the main editor.
    CodeTextEdit* owner_ = nullptr;
};

CodeTextEdit::CodeTextEdit(QWidget* parent)
    : QPlainTextEdit(parent)
{
    QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    // When the system monospace font lacks Chinese glyphs, Windows falls back to SimSun; explicitly specify Microsoft YaHei for Chinese text.
    fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
    fixedFont.setPointSize(std::max(12, fixedFont.pointSize()));
    setFont(fixedFont);
    setTabStopDistance(QFontMetricsF(fixedFont).horizontalAdvance(QChar(' ')) * 4.0);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFrameShape(QFrame::NoFrame);

    lineNumberArea_ = new LineNumberArea(this);
    bracketHighlighter_ = new BracketHighlighter(document());

    extraSelectionTimer_ = new QTimer(this);
    extraSelectionTimer_->setSingleShot(true);
    extraSelectionTimer_->setInterval(18);
    connect(extraSelectionTimer_, &QTimer::timeout, this, [this]()
        {
            refreshExtraSelections();
        });

    connect(this, &QPlainTextEdit::blockCountChanged, this, [this](int)
        {
            setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
        });

    connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, const int deltaY)
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
            scheduleRefreshExtraSelections();
        });

    connect(this, &QPlainTextEdit::textChanged, this, [this]()
        {
            scheduleRefreshExtraSelections();
        });

    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
    scheduleRefreshExtraSelections();
}

CodeTextEdit::~CodeTextEdit()
{
    delete bracketHighlighter_;
    bracketHighlighter_ = nullptr;
}

int CodeTextEdit::lineNumberAreaWidth() const
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

void CodeTextEdit::paintLineNumberArea(QPaintEvent* event)
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

bool CodeTextEdit::gotoLine(const int oneBasedLine)
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

void CodeTextEdit::setExternalExtraSelections(const QList<QTextEdit::ExtraSelection>& selections)
{
    externalExtraSelections_ = selections;
    scheduleRefreshExtraSelections();
}

void CodeTextEdit::resizeEvent(QResizeEvent* event)
{
    QPlainTextEdit::resizeEvent(event);
    const QRect kRect = contentsRect();
    lineNumberArea_->setGeometry(kRect.left(), kRect.top(), lineNumberAreaWidth(), kRect.height());
}

void CodeTextEdit::scheduleRefreshExtraSelections()
{
    if (extraSelectionTimer_ != nullptr)
    {
        extraSelectionTimer_->start();
    }
}

int CodeTextEdit::findPairInSameBlock(const int bracketPos, const QChar bracketCh) const
{
    const QTextBlock kTextBlock = document()->findBlock(bracketPos);
    if (!kTextBlock.isValid())
    {
        return -1;
    }

    const QString kBlockText = kTextBlock.text();
    const int kLocalPos = bracketPos - kTextBlock.position();
    if (kLocalPos < 0 || kLocalPos >= kBlockText.size())
    {
        return -1;
    }

    const QChar kPairCh = pairBracket(bracketCh);
    if (isOpenBracket(bracketCh))
    {
        int depth = 0;
        for (int index = kLocalPos; index < kBlockText.size(); ++index)
        {
            if (kBlockText.at(index) == bracketCh) ++depth;
            if (kBlockText.at(index) == kPairCh) --depth;
            if (depth == 0)
            {
                return kTextBlock.position() + index;
            }
        }
        return -1;
    }

    int depth = 0;
    for (int index = kLocalPos; index >= 0; --index)
    {
        if (kBlockText.at(index) == bracketCh) ++depth;
        if (kBlockText.at(index) == kPairCh) --depth;
        if (depth == 0)
        {
            return kTextBlock.position() + index;
        }
    }
    return -1;
}

int CodeTextEdit::findPairWithLimitedScan(const int bracketPos, const QChar bracketCh, const int maxScanCount) const
{
    const QChar kPairCh = pairBracket(bracketCh);
    const int kTotalChars = std::max(0, document()->characterCount() - 1);
    if (kTotalChars <= 0 || bracketPos < 0 || bracketPos >= kTotalChars)
    {
        return -1;
    }

    const int kStep = isOpenBracket(bracketCh) ? 1 : -1;
    int depth = 0;
    int scannedChars = 0;
    for (int index = bracketPos;
        index >= 0 && index < kTotalChars && scannedChars < maxScanCount;
        index += kStep, ++scannedChars)
    {
        const QChar kCurrentChar = document()->characterAt(index);
        if (kCurrentChar == bracketCh) ++depth;
        if (kCurrentChar == kPairCh) --depth;
        if (depth == 0)
        {
            return index;
        }
    }
    return -1;
}

void CodeTextEdit::refreshExtraSelections()
{
    QList<QTextEdit::ExtraSelection> extraSelections = externalExtraSelections_;

    QTextEdit::ExtraSelection lineSelection;
    lineSelection.cursor = textCursor();
    lineSelection.cursor.clearSelection();
    lineSelection.format.setProperty(QTextFormat::FullWidthSelection, true);
    lineSelection.format.setBackground(ksword_theme::primaryBlueSubtleColor());
    extraSelections.push_back(lineSelection);

    const int kTotalChars = std::max(0, document()->characterCount() - 1);
    const int kCursorPos = textCursor().position();
    int bracketPos = -1;
    QChar bracketCh;
    if (kCursorPos > 0)
    {
        const QChar kPrevChar = document()->characterAt(kCursorPos - 1);
        if (isOpenBracket(kPrevChar) || isCloseBracket(kPrevChar))
        {
            bracketPos = kCursorPos - 1;
            bracketCh = kPrevChar;
        }
    }
    if (bracketPos < 0 && kCursorPos < kTotalChars)
    {
        const QChar kCurrentChar = document()->characterAt(kCursorPos);
        if (isOpenBracket(kCurrentChar) || isCloseBracket(kCurrentChar))
        {
            bracketPos = kCursorPos;
            bracketCh = kCurrentChar;
        }
    }

    if (bracketPos >= 0)
    {
        int pairPos = findPairInSameBlock(bracketPos, bracketCh);
        if (pairPos < 0)
        {
            pairPos = findPairWithLimitedScan(bracketPos, bracketCh, 200000);
        }

        auto appendBracketSelection = [this, &extraSelections](const int pos, const QColor& bg)
            {
                QTextEdit::ExtraSelection selection;
                selection.cursor = textCursor();
                selection.cursor.setPosition(pos);
                selection.cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
                // The background color may be the selection blue or the error red used for mismatched parentheses;
                // Foreground must be calculated based on the actual background color; do not use the parameter-less version calibrated for accent colors.
                selection.format.setForeground(ksword_theme::onAccentColor(bg));
                selection.format.setBackground(bg);
                extraSelections.push_back(selection);
            };

        const QColor kMatchedBg = ksword_theme::editorSelectionColor();
        appendBracketSelection(bracketPos, pairPos >= 0 ? kMatchedBg : ksword_theme::errorColor());
        if (pairPos >= 0)
        {
            appendBracketSelection(pairPos, kMatchedBg);
        }
    }

    setExtraSelections(extraSelections);
}
