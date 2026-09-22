#include "TextSearchReplaceSupport.h"

// ============================================================
// TextSearchReplaceSupport.cpp
// Notes:
// 1) The panel floats with the text box as its parent, excluding it from the host
//    layout, thus avoiding disruption of the diverse existing layouts across pages;
// 2) Unified search uses QTextDocument::find; regex and plain text differ only in input parameters.
// 3) Wraps 'replace all' in a single edit block to ensure a single undo action reverts the operation.
// ============================================================

#include <QAbstractScrollArea>
#include <QApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QString>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextEdit>
#include <QToolButton>
#include <QWidget>

namespace
{
    // kSearchBarProperty purpose: Marks the text box with the created search panel to avoid duplicate creation.
    constexpr const char* kSearchBarProperty = "kswordTextSearchBar";

    // kMaxCountedMatches:
    // - Matching count requires a full-text scan; very large texts will cause noticeable lag;
    // - Stop precise counting beyond this limit and display an approximate value with a '+' instead.
    constexpr int kMaxCountedMatches = 5000;

    // EditorAccess:
    // - QPlainTextEdit and QTextEdit share no common text operation base class; a thin
    //   adapter layer is added here so that find-and-replace logic is written only once.
    struct EditorAccess
    {
        QPlainTextEdit* plainEditor = nullptr;
        QTextEdit* richEditor = nullptr;

        bool isValid() const
        {
            return plainEditor != nullptr || richEditor != nullptr;
        }

        QWidget* widget() const
        {
            return plainEditor != nullptr
                ? static_cast<QWidget*>(plainEditor)
                : static_cast<QWidget*>(richEditor);
        }

        QTextDocument* document() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->document();
            }
            return richEditor != nullptr ? richEditor->document() : nullptr;
        }

        QTextCursor textCursor() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->textCursor();
            }
            return richEditor != nullptr ? richEditor->textCursor() : QTextCursor();
        }

        void setTextCursor(const QTextCursor& cursorValue) const
        {
            if (plainEditor != nullptr)
            {
                plainEditor->setTextCursor(cursorValue);
                plainEditor->ensureCursorVisible();
                return;
            }
            if (richEditor != nullptr)
            {
                richEditor->setTextCursor(cursorValue);
                richEditor->ensureCursorVisible();
            }
        }

        bool isReadOnly() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->isReadOnly();
            }
            return richEditor != nullptr ? richEditor->isReadOnly() : true;
        }

        QWidget* viewport() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->viewport();
            }
            return richEditor != nullptr ? richEditor->viewport() : nullptr;
        }
    };

    // resolveEditor purpose: Resolves any control into a searchable text box view.
    EditorAccess resolveEditor(QWidget* widgetValue)
    {
        EditorAccess accessValue{};
        if (widgetValue == nullptr)
        {
            return accessValue;
        }
        // Focus often lands on the viewport; here, traverse up one level to find the actual editor.
        QWidget* candidate = widgetValue;
        if (QWidget* parentWidget = widgetValue->parentWidget();
            parentWidget != nullptr
            && qobject_cast<QAbstractScrollArea*>(parentWidget) != nullptr
            && qobject_cast<QAbstractScrollArea*>(parentWidget)->viewport() == widgetValue)
        {
            candidate = parentWidget;
        }

        accessValue.plainEditor = qobject_cast<QPlainTextEdit*>(candidate);
        if (accessValue.plainEditor == nullptr)
        {
            accessValue.richEditor = qobject_cast<QTextEdit*>(candidate);
        }
        return accessValue;
    }

    // hasOwnFindPanel:
    // - Code editors and hex editors have built-in find panels; the global panel must yield.
    // - Match upwards by class name to avoid dragging the header files of these two modules into this file.
    bool hasOwnFindPanel(const QWidget* editorWidget)
    {
        const QObject* currentObject = editorWidget;
        while (currentObject != nullptr)
        {
            const QString kClassName =
                QString::fromLatin1(currentObject->metaObject()->className());
            if (kClassName.contains(QStringLiteral("CodeEditorWidget"))
                || kClassName.contains(QStringLiteral("HexEditorWidget"))
                || kClassName.contains(QStringLiteral("CodeTextEdit")))
            {
                return true;
            }
            currentObject = currentObject->parent();
        }
        return false;
    }

    // expandBackreferences:
    // - During regex replacement, expand \1..\9 to corresponding capture groups; restore \\ to a single backslash.
    // - In non-regex mode, the replacement text is used literally and does not go through this path.
    QString expandBackreferences(
        const QString& replacementText,
        const QRegularExpressionMatch& matchValue)
    {
        QString resultText;
        resultText.reserve(replacementText.size());
        for (qsizetype i = 0; i < replacementText.size(); ++i)
        {
            const QChar kCurrentChar = replacementText.at(i);
            if (kCurrentChar != QLatin1Char('\\') || i + 1 >= replacementText.size())
            {
                resultText.append(kCurrentChar);
                continue;
            }

            const QChar kNextChar = replacementText.at(i + 1);
            if (kNextChar == QLatin1Char('\\'))
            {
                resultText.append(QLatin1Char('\\'));
                ++i;
                continue;
            }
            if (kNextChar.isDigit())
            {
                const int kGroupIndex = kNextChar.digitValue();
                if (kGroupIndex <= matchValue.lastCapturedIndex())
                {
                    resultText.append(matchValue.captured(kGroupIndex));
                }
                ++i;
                continue;
            }
            resultText.append(kCurrentChar);
        }
        return resultText;
    }

    // TextSearchBar:
    // - Search and replace bar floating above the text box;
    // - Q_OBJECT is not used; all connections use lambdas, so moc is not required during build.
    class TextSearchBar final : public QWidget
    {
    public:
        explicit TextSearchBar(const EditorAccess& accessValue)
            : QWidget(accessValue.widget())
            , access_(accessValue)
        {
            setObjectName(QStringLiteral("KswordTextSearchBar"));
            setAutoFillBackground(true);

            QHBoxLayout* rootLayout = new QHBoxLayout(this);
            rootLayout->setContentsMargins(6, 4, 6, 4);
            rootLayout->setSpacing(4);

            findEdit_ = new QLineEdit(this);
            findEdit_->setPlaceholderText(QStringLiteral("查找"));
            findEdit_->setClearButtonEnabled(true);
            findEdit_->setMinimumWidth(160);

            prevButton_ = new QToolButton(this);
            prevButton_->setText(QStringLiteral("↑"));
            prevButton_->setToolTip(QStringLiteral("查找上一个匹配项 (Shift+Enter)"));

            nextButton_ = new QToolButton(this);
            nextButton_->setText(QStringLiteral("↓"));
            nextButton_->setToolTip(QStringLiteral("查找下一个匹配项 (Enter)"));

            regexButton_ = new QToolButton(this);
            regexButton_->setText(QStringLiteral(".*"));
            regexButton_->setCheckable(true);
            regexButton_->setToolTip(
                QStringLiteral("按正则表达式匹配；替换文本中可用 \\1..\\9 引用捕获组"));

            caseButton_ = new QToolButton(this);
            caseButton_->setText(QStringLiteral("Aa"));
            caseButton_->setCheckable(true);
            caseButton_->setToolTip(QStringLiteral("区分大小写"));

            statusLabel_ = new QLabel(this);
            statusLabel_->setMinimumWidth(72);
            statusLabel_->setAlignment(Qt::AlignCenter);

            replaceEdit_ = new QLineEdit(this);
            replaceEdit_->setPlaceholderText(QStringLiteral("替换为"));
            replaceEdit_->setClearButtonEnabled(true);
            replaceEdit_->setMinimumWidth(140);

            replaceOneButton_ = new QToolButton(this);
            replaceOneButton_->setText(QStringLiteral("替换"));
            replaceOneButton_->setToolTip(QStringLiteral("替换当前匹配项并跳到下一处"));

            replaceAllButton_ = new QToolButton(this);
            replaceAllButton_->setText(QStringLiteral("全部替换"));
            replaceAllButton_->setToolTip(QStringLiteral("替换文本中全部匹配项，可一次撤销"));

            closeButton_ = new QToolButton(this);
            closeButton_->setText(QStringLiteral("×"));
            closeButton_->setToolTip(QStringLiteral("关闭查找栏 (Esc)"));

            rootLayout->addWidget(findEdit_, 1);
            rootLayout->addWidget(prevButton_, 0);
            rootLayout->addWidget(nextButton_, 0);
            rootLayout->addWidget(regexButton_, 0);
            rootLayout->addWidget(caseButton_, 0);
            rootLayout->addWidget(statusLabel_, 0);
            rootLayout->addWidget(replaceEdit_, 1);
            rootLayout->addWidget(replaceOneButton_, 0);
            rootLayout->addWidget(replaceAllButton_, 0);
            rootLayout->addWidget(closeButton_, 0);

            // Read-only text boxes have no meaning for replacement; hide this group of controls directly.
            const bool kReadOnly = access_.isReadOnly();
            replaceEdit_->setVisible(!kReadOnly);
            replaceOneButton_->setVisible(!kReadOnly);
            replaceAllButton_->setVisible(!kReadOnly);

            connect(findEdit_, &QLineEdit::textChanged, this, [this]() {
                refreshMatchStatus();
            });
            connect(findEdit_, &QLineEdit::returnPressed, this, [this]() {
                findStep(true, true);
            });
            connect(replaceEdit_, &QLineEdit::returnPressed, this, [this]() {
                replaceCurrent();
            });
            connect(nextButton_, &QToolButton::clicked, this, [this]() {
                findStep(true, true);
            });
            connect(prevButton_, &QToolButton::clicked, this, [this]() {
                findStep(false, true);
            });
            connect(regexButton_, &QToolButton::toggled, this, [this](bool) {
                refreshMatchStatus();
            });
            connect(caseButton_, &QToolButton::toggled, this, [this](bool) {
                refreshMatchStatus();
            });
            connect(replaceOneButton_, &QToolButton::clicked, this, [this]() {
                replaceCurrent();
            });
            connect(replaceAllButton_, &QToolButton::clicked, this, [this]() {
                replaceAll();
            });
            connect(closeButton_, &QToolButton::clicked, this, [this]() {
                closeBar();
            });

            findEdit_->installEventFilter(this);
            replaceEdit_->installEventFilter(this);
            if (QWidget* hostWidget = access_.widget(); hostWidget != nullptr)
            {
                hostWidget->installEventFilter(this);
            }

            updateGeometryToHost();
        }

        // activate purpose: display the search bar and set focus to the corresponding input field.
        void activate(const bool focusReplaceField)
        {
            // When text is selected, use it directly as the search term to avoid manual copying.
            const QTextCursor kCursorValue = access_.textCursor();
            if (kCursorValue.hasSelection())
            {
                const QString kSelectedText = kCursorValue.selectedText();
                if (!kSelectedText.isEmpty() && !kSelectedText.contains(QChar(0x2029)))
                {
                    findEdit_->setText(kSelectedText);
                }
            }

            show();
            raise();
            updateGeometryToHost();
            refreshMatchStatus();

            if (focusReplaceField && !access_.isReadOnly())
            {
                replaceEdit_->setFocus(Qt::ShortcutFocusReason);
                replaceEdit_->selectAll();
                return;
            }
            findEdit_->setFocus(Qt::ShortcutFocusReason);
            findEdit_->selectAll();
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            if (eventValue->type() == QEvent::Resize
                && watchedObject == access_.widget())
            {
                updateGeometryToHost();
                return false;
            }
            if (eventValue->type() != QEvent::KeyPress)
            {
                return QWidget::eventFilter(watchedObject, eventValue);
            }

            QKeyEvent* keyEvent = static_cast<QKeyEvent*>(eventValue);
            if (keyEvent->key() == Qt::Key_Escape)
            {
                closeBar();
                return true;
            }
            if ((keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
                && watchedObject == findEdit_)
            {
                findStep(!keyEvent->modifiers().testFlag(Qt::ShiftModifier), true);
                return true;
            }
            return QWidget::eventFilter(watchedObject, eventValue);
        }

        void keyPressEvent(QKeyEvent* keyEvent) override
        {
            if (keyEvent->key() == Qt::Key_Escape)
            {
                closeBar();
                return;
            }
            QWidget::keyPressEvent(keyEvent);
        }

    private:
        // closeBar: Hides the search bar and returns focus to the text box.
        void closeBar()
        {
            hide();
            if (QWidget* hostWidget = access_.widget(); hostWidget != nullptr)
            {
                hostWidget->setFocus(Qt::OtherFocusReason);
            }
        }

        // updateGeometryToHost:
        // - Floats attached to the top-right corner of the text box viewport, with width constrained by the viewport width.
        // - The top-right corner obstructs less of the main content than the full banner.
        void updateGeometryToHost()
        {
            QWidget* viewportWidget = access_.viewport();
            if (viewportWidget == nullptr)
            {
                return;
            }
            const int kAvailableWidth = viewportWidget->width();
            const int kDesiredWidth = std::min(kAvailableWidth, sizeHint().width());
            const int kBarHeight = sizeHint().height();
            const QPoint kTopLeftInHost =
                viewportWidget->mapTo(access_.widget(), QPoint(0, 0));
            setGeometry(
                kTopLeftInHost.x() + std::max(0, kAvailableWidth - kDesiredWidth),
                kTopLeftInHost.y(),
                kDesiredWidth,
                kBarHeight);
        }

        // buildRegex: Assembles the regex based on current switches; in non-regex mode, escapes the search term as a literal.
        QRegularExpression buildRegex(bool& validOut) const
        {
            validOut = false;
            const QString kPatternText = regexButton_->isChecked()
                ? findEdit_->text()
                : QRegularExpression::escape(findEdit_->text());
            QRegularExpression::PatternOptions options =
                QRegularExpression::NoPatternOption;
            if (!caseButton_->isChecked())
            {
                options |= QRegularExpression::CaseInsensitiveOption;
            }
            QRegularExpression regexValue(kPatternText, options);
            validOut = regexValue.isValid();
            return regexValue;
        }

        // findStep:
        // - Search for the next match from the current cursor in the specified direction;
        // - Wrap around once after reaching the end; if still not found, stay in place.
        bool findStep(const bool forward, const bool reportStatus)
        {
            QTextDocument* documentValue = access_.document();
            if (documentValue == nullptr || findEdit_->text().isEmpty())
            {
                if (reportStatus)
                {
                    refreshMatchStatus();
                }
                return false;
            }

            bool regexValid = false;
            const QRegularExpression kRegexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                statusLabel_->setText(QStringLiteral("正则无效"));
                return false;
            }

            QTextDocument::FindFlags findFlags;
            if (!forward)
            {
                findFlags |= QTextDocument::FindBackward;
            }
            if (caseButton_->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            QTextCursor foundCursor =
                documentValue->find(kRegexValue, access_.textCursor(), findFlags);
            if (foundCursor.isNull())
            {
                // Wrap: restart from the beginning when moving down, restart from the end when moving up.
                QTextCursor wrapCursor(documentValue);
                if (!forward)
                {
                    wrapCursor.movePosition(QTextCursor::End);
                }
                foundCursor = documentValue->find(kRegexValue, wrapCursor, findFlags);
            }
            if (foundCursor.isNull())
            {
                if (reportStatus)
                {
                    statusLabel_->setText(QStringLiteral("无匹配"));
                }
                return false;
            }

            access_.setTextCursor(foundCursor);
            if (reportStatus)
            {
                refreshMatchStatus();
            }
            return true;
        }

        // refreshMatchStatus: Counts the total matches and displays them; if the limit is exceeded, only an approximate value is shown.
        void refreshMatchStatus()
        {
            QTextDocument* documentValue = access_.document();
            if (documentValue == nullptr || findEdit_->text().isEmpty())
            {
                statusLabel_->clear();
                return;
            }

            bool regexValid = false;
            const QRegularExpression kRegexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                statusLabel_->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextDocument::FindFlags findFlags;
            if (caseButton_->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            int matchCount = 0;
            QTextCursor scanCursor(documentValue);
            while (matchCount < kMaxCountedMatches)
            {
                scanCursor = documentValue->find(kRegexValue, scanCursor, findFlags);
                if (scanCursor.isNull())
                {
                    break;
                }
                ++matchCount;
                // Empty matches (e.g., a*) do not advance the cursor; manual advancement by one position is required to avoid an infinite loop.
                if (scanCursor.selectionStart() == scanCursor.selectionEnd())
                {
                    if (scanCursor.atEnd())
                    {
                        break;
                    }
                    scanCursor.movePosition(QTextCursor::NextCharacter);
                }
            }

            statusLabel_->setText(
                matchCount >= kMaxCountedMatches
                ? QStringLiteral("%1+ 项").arg(kMaxCountedMatches)
                : QStringLiteral("%1 项").arg(matchCount));
        }

        // replaceCurrent:
        // - If the current selection exactly matches the search condition, replace it; otherwise, jump to the next occurrence.
        // - Automatically advances after replacement for continuous clicking.
        void replaceCurrent()
        {
            if (access_.isReadOnly() || findEdit_->text().isEmpty())
            {
                return;
            }
            bool regexValid = false;
            const QRegularExpression kRegexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                statusLabel_->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextCursor cursorValue = access_.textCursor();
            if (cursorValue.hasSelection())
            {
                const QRegularExpressionMatch kMatchValue =
                    kRegexValue.match(cursorValue.selectedText());
                const bool kWholeSelectionMatched =
                    kMatchValue.hasMatch()
                    && kMatchValue.capturedStart() == 0
                    && kMatchValue.capturedLength() == cursorValue.selectedText().size();
                if (kWholeSelectionMatched)
                {
                    cursorValue.insertText(
                        regexButton_->isChecked()
                        ? expandBackreferences(replaceEdit_->text(), kMatchValue)
                        : replaceEdit_->text());
                    access_.setTextCursor(cursorValue);
                }
            }
            findStep(true, true);
        }

        // replaceAll: Performs a full-document replacement with all changes merged into a single undo step.
        void replaceAll()
        {
            QTextDocument* documentValue = access_.document();
            if (documentValue == nullptr
                || access_.isReadOnly()
                || findEdit_->text().isEmpty())
            {
                return;
            }
            bool regexValid = false;
            const QRegularExpression kRegexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                statusLabel_->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextDocument::FindFlags findFlags;
            if (caseButton_->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            int replacedCount = 0;
            QTextCursor editCursor(documentValue);
            editCursor.beginEditBlock();
            QTextCursor scanCursor(documentValue);
            while (true)
            {
                scanCursor = documentValue->find(kRegexValue, scanCursor, findFlags);
                if (scanCursor.isNull())
                {
                    break;
                }

                const QString kMatchedText = scanCursor.selectedText();
                QString replacementText = replaceEdit_->text();
                if (regexButton_->isChecked())
                {
                    const QRegularExpressionMatch kMatchValue = kRegexValue.match(kMatchedText);
                    if (kMatchValue.hasMatch())
                    {
                        replacementText = expandBackreferences(replacementText, kMatchValue);
                    }
                }

                if (kMatchedText.isEmpty())
                {
                    // Empty matches do not consume characters; inserting directly would cause an infinite loop at the same position, so skip one character.
                    if (scanCursor.atEnd())
                    {
                        break;
                    }
                    scanCursor.movePosition(QTextCursor::NextCharacter);
                    continue;
                }

                scanCursor.insertText(replacementText);
                ++replacedCount;
            }
            editCursor.endEditBlock();

            statusLabel_->setText(QStringLiteral("已替换 %1 处").arg(replacedCount));
        }

        EditorAccess access_{};              // Target text box adapter.
        QLineEdit* findEdit_ = nullptr;      // Find input box.
        QLineEdit* replaceEdit_ = nullptr;   // Replace input field.
        QToolButton* prevButton_ = nullptr;  // Previous match.
        QToolButton* nextButton_ = nullptr;  // Next match.
        QToolButton* regexButton_ = nullptr; // Regex toggle.
        QToolButton* caseButton_ = nullptr;  // Case sensitivity toggle.
        QToolButton* replaceOneButton_ = nullptr; // Replace current.
        QToolButton* replaceAllButton_ = nullptr; // Replace all.
        QToolButton* closeButton_ = nullptr; // Close the search bar.
        QLabel* statusLabel_ = nullptr;      // Match count / error message.
    };

    // ensureSearchBar purpose: Retrieve the existing search bar on the text box; create one if it does not exist.
    TextSearchBar* ensureSearchBar(const EditorAccess& accessValue)
    {
        QWidget* hostWidget = accessValue.widget();
        if (hostWidget == nullptr)
        {
            return nullptr;
        }

        // TextSearchBar intentionally lacks Q_OBJECT (to avoid moc in the build), so qobject_cast cannot be used.
        // This property is written only by this file, and the panel is a child control
        // of the text box that is destroyed along with it, so the downcast here is safe.
        const QVariant kStoredBar = hostWidget->property(kSearchBarProperty);
        if (kStoredBar.isValid())
        {
            if (QObject* storedObject = kStoredBar.value<QObject*>();
                storedObject != nullptr)
            {
                return static_cast<TextSearchBar*>(storedObject);
            }
        }

        TextSearchBar* barWidget = new TextSearchBar(accessValue);
        hostWidget->setProperty(
            kSearchBarProperty,
            QVariant::fromValue(static_cast<QObject*>(barWidget)));
        return barWidget;
    }

    // GlobalTextSearchFilter:
    // - Listens for global application key presses, converting Ctrl+F / Ctrl+H into the search panel.
    // - Intercept only when focus is definitely on a multi-line text box; allow all other scenarios.
    class GlobalTextSearchFilter final : public QObject
    {
    public:
        explicit GlobalTextSearchFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            const QEvent::Type kEventType = eventValue->type();
            if (kEventType != QEvent::KeyPress && kEventType != QEvent::ShortcutOverride)
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }

            QKeyEvent* keyEvent = static_cast<QKeyEvent*>(eventValue);
            if (!keyEvent->modifiers().testFlag(Qt::ControlModifier))
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }
            const bool kWantFind = keyEvent->key() == Qt::Key_F;
            const bool kWantReplace = keyEvent->key() == Qt::Key_H;
            if (!kWantFind && !kWantReplace)
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }

            QWidget* focusWidget = QApplication::focusWidget();
            if (!ks::ui::openTextSearchPanelFor(focusWidget, kWantReplace))
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }
            eventValue->accept();
            return true;
        }
    };

    QPointer<GlobalTextSearchFilter> gGlobalFilter; // Global filter instance, installed only once.
}

bool ks::ui::openTextSearchPanelFor(QWidget* editorWidget, const bool focusReplaceField)
{
    const EditorAccess kAccessValue = resolveEditor(editorWidget);
    if (!kAccessValue.isValid())
    {
        return false;
    }
    if (hasOwnFindPanel(kAccessValue.widget()))
    {
        return false;
    }

    TextSearchBar* barWidget = ensureSearchBar(kAccessValue);
    if (barWidget == nullptr)
    {
        return false;
    }
    barWidget->activate(focusReplaceField);
    return true;
}

void ks::ui::installGlobalTextSearchReplaceSupport(QApplication* appInstance)
{
    if (appInstance == nullptr || !gGlobalFilter.isNull())
    {
        return;
    }
    gGlobalFilter = new GlobalTextSearchFilter(appInstance);
    appInstance->installEventFilter(gGlobalFilter);
}
