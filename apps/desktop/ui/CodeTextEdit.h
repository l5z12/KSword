#pragma once

// ============================================================
// CodeTextEdit.h
// Purpose:
// - Provide the core text control for CodeEditorWidget;
// - Integrates line number display, current line highlighting, bracket matching, and external highlight merging capabilities.
// - Expose line-jump and external highlight injection interfaces.
// ============================================================

#include <QList>
#include <QPlainTextEdit>
#include <QTextEdit>

class QPaintEvent;
class QResizeEvent;
class QSyntaxHighlighter;
class QTimer;
class QWidget;

// CodeTextEdit：
// - Unify the code text editor implementation;
// - For composition and reuse by CodeEditorWidget.
class CodeTextEdit final : public QPlainTextEdit
{
public:
    // Constructor:
    // - parent: parent widget, may be null;
    explicit CodeTextEdit(QWidget* parent = nullptr);

    // Destructor:
    // - Release internal bracket syntax highlighting objects.
    ~CodeTextEdit() override;

    // lineNumberAreaWidth：
    // - Dynamically calculate the line number area width based on the current line number.
    int lineNumberAreaWidth() const;

    // paintLineNumberArea：
    // - Render the line number area content.
    // Parameter event: line number area paint event.
    void paintLineNumberArea(QPaintEvent* event);

    // gotoLine：
    // - Jump to the specified 1-based line number and center the display.
    // Parameter oneBasedLine: The target line number (1-based).
    // Returns: true if the jump was successful; false if out of bounds or invalid.
    bool gotoLine(int oneBasedLine);

    // setExternalExtraSelections：
    // - Inject outer hit highlighting (e.g., Find All matches);
    // - Merges with the current line/bracket highlighting for display.
    // Input parameter selections: the set of extra highlights.
    void setExternalExtraSelections(const QList<QTextEdit::ExtraSelection>& selections);

protected:
    // resizeEvent：
    // - Synchronize the line number area geometry when the editor area size changes.
    void resizeEvent(QResizeEvent* event) override;

private:
    // scheduleRefreshExtraSelections：
    // - Throttle highlight refresh triggers.
    void scheduleRefreshExtraSelections();

    // findPairInSameBlock：
    // - Prioritize finding bracket pair positions within the current text block.
    int findPairInSameBlock(int bracketPos, QChar bracketCh) const;

    // findPairWithLimitedScan：
    // - Perform a limited-scan search for matching positions across the entire document.
    int findPairWithLimitedScan(int bracketPos, QChar bracketCh, int maxScanCount) const;

    // refreshExtraSelections：
    // - Refresh current line highlighting, bracket highlighting, and external hit highlighting.
    void refreshExtraSelections();

private:
    // m_lineNumberArea: Line number area control.
    QWidget* lineNumberArea_ = nullptr;

    // m_bracketHighlighter: Bracket highlighter object.
    QSyntaxHighlighter* bracketHighlighter_ = nullptr;

    // m_extraSelectionTimer: Highlight refresh throttling timer.
    QTimer* extraSelectionTimer_ = nullptr;

    // m_externalExtraSelections: Set of extra highlights injected from the outside.
    QList<QTextEdit::ExtraSelection> externalExtraSelections_;

    friend class LineNumberArea;
};
