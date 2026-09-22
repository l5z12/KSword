#include "GlobalUiSearch.h"

#include "TableSearchSupport.h"

#include "../include/ads/DockWidget.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractButton>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QProgressBar>
#include <QScrollArea>
#include <QSet>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QStyleOption>
#include <QStyledItemDelegate>
#include <QTabBar>
#include <QTabWidget>
#include <QTableView>
#include <QTextDocument>
#include <QTextDocumentFragment>
#include <QTextOption>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>

namespace
{
    // g_activeSearchController: The active title bar search controller for the main window.
    QPointer<ks::ui::GlobalUiSearchController> gActiveSearchController;

    // Search and display parameters:
    // - kSearchDebounceIntervalMs: Input debounce interval.
    // - kMaxHitsPerDock: maximum hits a single Dock is allowed to contribute, preventing screen flooding on a single page.
    // - kMaxTotalHits: upper limit on total result count;
    // - kMaxVisibleResultRows: Maximum number of rows fully displayed in the popup at once (excess rows require scrolling).
    // - kResultItemHeight: Fixed height for result rows (two lines: matched text + page path).
    // - kSnippetMaxLength: Maximum character count for displaying matched text snippets.
    // - kSnippetMatchLeadin: Number of characters preserved before the match position during snippet extraction.
    // - kComboBoxItemScanLimit: upper limit on the number of dropdown items participating in indexing.
    // - kHeaderColumnScanLimit: The upper limit on the number of header columns participating in indexing.
    // - kFlashDelayMs: layout stability wait time between Dock state change and highlighting activation
    // - kProgressContentHeight: content height of the progress row during scanning.
    // - kResultHtmlRole: custom data role for rich text content of list items.
    constexpr int kSearchDebounceIntervalMs = 220;
    constexpr int kMaxHitsPerDock = 24;
    constexpr int kMaxTotalHits = 96;
    constexpr int kMaxVisibleResultRows = 8;
    constexpr int kResultItemHeight = 46;
    constexpr int kSnippetMaxLength = 60;
    constexpr int kSnippetMatchLeadin = 18;
    constexpr int kComboBoxItemScanLimit = 60;
    constexpr int kHeaderColumnScanLimit = 80;
    constexpr int kFlashDelayMs = 140;
    constexpr int kProgressContentHeight = 44;
    constexpr int kSearchOptionsRowHeight = 36;
    constexpr int kResultHtmlRole = Qt::UserRole + 41;

    // normalizeUiText：
    // - Purpose: Compress raw control text into plain text suitable for matching and single-line display.
    // - Processing: Convert rich text to plain text, merge newlines/tabs into spaces, and trim leading/trailing whitespace.
    // - Input rawText: raw text read by the control;
    // Output: normalized single-line text.
    QString normalizeUiText(QString rawText)
    {
        if (rawText.contains(QLatin1Char('<')) && Qt::mightBeRichText(rawText))
        {
            rawText = QTextDocumentFragment::fromHtml(rawText).toPlainText();
        }
        rawText.replace(QLatin1Char('\n'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\r'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\t'), QLatin1Char(' '));
        return rawText.simplified();
    }

    // stripMnemonicMarkers：
    // - Purpose: Remove '&' mnemonic markers from button/tab text ('&&' is preserved as a single '&');
    // - Input sourceText: text that may contain mnemonic markers;
    // - Out: Text for display.
    QString stripMnemonicMarkers(const QString& sourceText)
    {
        QString strippedText;
        strippedText.reserve(sourceText.size());
        for (int charIndex = 0; charIndex < sourceText.size(); ++charIndex)
        {
            const QChar kCurrentChar = sourceText.at(charIndex);
            if (kCurrentChar == QLatin1Char('&'))
            {
                if (charIndex + 1 < sourceText.size() && sourceText.at(charIndex + 1) == QLatin1Char('&'))
                {
                    strippedText.append(QLatin1Char('&'));
                    ++charIndex;
                }
                continue;
            }
            strippedText.append(kCurrentChar);
        }
        return strippedText;
    }

    // isWidgetChainRevealable：
    // - Purpose: Determine if the target widget can be genuinely displayed via 'tab switching'.
    // - Rule: Traverse upward to the parent Dock; any ancestor that is explicitly hidden and whose
    //   parent is not a QStackedWidget (used for tab navigation hiding) is considered unrevealable.
    // - Input targetWidget: candidate matched widget.
    // Output: true=visible after activating the result, false=never visible (not included).
    bool isWidgetChainRevealable(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                return true;
            }
            if (cursorWidget->isHidden()
                && qobject_cast<QStackedWidget*>(cursorWidget->parentWidget()) == nullptr)
            {
                return false;
            }
        }
        return true;
    }

    // resolveMatchRank：
    // - Purpose: Calculate match ranking weight;
    // - Rules: 0 = exact match (case-insensitive), 1 = prefix match, 2 = substring match;
    // - Parameters: normalizedText (matched text), queryText (query), matchIndex (index of the first match).
    int resolveMatchRank(const QString& normalizedText, const QString& queryText, const int matchIndex)
    {
        if (normalizedText.compare(queryText, Qt::CaseInsensitive) == 0)
        {
            return 0;
        }
        return matchIndex == 0 ? 1 : 2;
    }

    // tableViewForWidget: Resolve the owning table by traversing the parent chain from the event target.
    QTableView* tableViewForWidget(QWidget* sourceWidget)
    {
        for (QWidget* cursorWidget = sourceWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (QTableView* tableView = qobject_cast<QTableView*>(cursorWidget))
            {
                return tableView;
            }
        }
        return nullptr;
    }

    // dockWidgetForWidget: Resolve the associated ADS Dock from the widget's parent chain.
    ads::CDockWidget* dockWidgetForWidget(QWidget* sourceWidget)
    {
        for (QWidget* cursorWidget = sourceWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (ads::CDockWidget* dockWidget = qobject_cast<ads::CDockWidget*>(cursorWidget))
            {
                return dockWidget;
            }
        }
        return nullptr;
    }

    // buildPagePathText：
    // - Purpose: Generates a page path in the format "Dock Title › Internal Tab › Group Box".
    // - Processing: Collect page names from QTabWidget/QStackedWidget and QGroupBox titles by traversing up from the
    //   target control (excluding the target's own title to avoid duplication), then concatenate from outer to inner.
    // - Input parameters: dockWidget (parent Dock), dockTitleText (Dock title), targetWidget (matched control).
    // - Out: Page path text.
    QString buildPagePathText(
        const ads::CDockWidget* dockWidget,
        const QString& dockTitleText,
        QWidget* targetWidget)
    {
        QStringList innerPathParts;
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == dockWidget)
            {
                break;
            }

            QWidget* parentWidget = cursorWidget->parentWidget();
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int kTabIndex = tabWidget->indexOf(cursorWidget);
                    if (kTabIndex >= 0)
                    {
                        const QString kTabText =
                            normalizeUiText(stripMnemonicMarkers(tabWidget->tabText(kTabIndex)));
                        if (!kTabText.isEmpty())
                        {
                            innerPathParts.prepend(kTabText);
                        }
                    }
                }
            }

            if (cursorWidget != targetWidget)
            {
                if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(cursorWidget))
                {
                    const QString kGroupTitleText = normalizeUiText(groupBox->title());
                    if (!kGroupTitleText.isEmpty())
                    {
                        innerPathParts.prepend(kGroupTitleText);
                    }
                }
            }
        }

        QStringList fullPathParts;
        fullPathParts << dockTitleText;
        fullPathParts << innerPathParts;
        fullPathParts.removeAll(QString());
        return fullPathParts.join(QStringLiteral(" › "));
    }

    // collectDockSearchHits：
    // - Purpose: Perform keyword matching within the control tree of a single Dock and append matches.
    // - Index sources: QLabel text, button text, group box titles, QTabWidget tabs,
    //   combo box entries, input box placeholders, and table/tree view horizontal headers.
    // - Input: dockWidget (target Dock); queryText (query); outHitList (hit output).
    // - Output: No return value; hits are appended to outHitList (subject to a per-page limit).
    void collectDockSearchHits(
        ads::CDockWidget* dockWidget,
        const QString& queryText,
        QVector<ks::ui::UiSearchHit>& outHitList,
        const bool visiblePageOnly)
    {
        QWidget* contentWidget = dockWidget->widget();
        if (contentWidget == nullptr)
        {
            return;
        }

        const QString kDockTitleText = normalizeUiText(dockWidget->windowTitle());
        QSet<QString> dedupKeySet;
        int dockHitCount = 0;

        const auto kTryAppendHit = [&](QWidget* targetWidget, const QString& rawText)
        {
            if (dockHitCount >= kMaxHitsPerDock || targetWidget == nullptr)
            {
                return;
            }
            const QString kNormalizedText = normalizeUiText(rawText);
            if (kNormalizedText.isEmpty())
            {
                return;
            }
            const int kMatchIndex = kNormalizedText.indexOf(queryText, 0, Qt::CaseInsensitive);
            if (kMatchIndex < 0)
            {
                return;
            }
            if (!isWidgetChainRevealable(targetWidget))
            {
                return;
            }
            const QString kDedupKey =
                QString::number(reinterpret_cast<quintptr>(targetWidget), 16)
                + QLatin1Char('\x1f')
                + kNormalizedText;
            if (dedupKeySet.contains(kDedupKey))
            {
                return;
            }
            dedupKeySet.insert(kDedupKey);

            ks::ui::UiSearchHit hitEntry;
            hitEntry.pageDockWidget = dockWidget;
            hitEntry.targetWidget = targetWidget;
            hitEntry.matchedText = kNormalizedText;
            hitEntry.pagePathText = buildPagePathText(dockWidget, kDockTitleText, targetWidget);
            hitEntry.matchRank = resolveMatchRank(kNormalizedText, queryText, kMatchIndex);
            outHitList.push_back(hitEntry);
            ++dockHitCount;
        };

        // tryAppendTableMatches: Converts model cell hits into unified search results.
        const auto kTryAppendTableMatches = [&](QTableView* tableView)
        {
            if (tableView == nullptr || dockHitCount >= kMaxHitsPerDock)
            {
                return;
            }
            const int kRemainingHitCount = kMaxHitsPerDock - dockHitCount;
            const QVector<ks::ui::TableCellSearchMatch> kTableMatchList =
                ks::ui::collectTableCellSearchMatches(
                    tableView,
                    queryText,
                    kRemainingHitCount);
            for (const ks::ui::TableCellSearchMatch& tableMatch : kTableMatchList)
            {
                ks::ui::UiSearchHit hitEntry;
                hitEntry.pageDockWidget = dockWidget;
                hitEntry.targetWidget = tableView;
                hitEntry.targetTableView = tableView;
                hitEntry.targetModelIndex = tableMatch.modelIndex;
                hitEntry.matchedText = tableMatch.matchedText;
                hitEntry.pagePathText = buildPagePathText(
                    dockWidget,
                    kDockTitleText,
                    tableView)
                    + QStringLiteral(" › ")
                    + tableMatch.locationText;
                hitEntry.matchRank = tableMatch.matchRank;
                outHitList.push_back(hitEntry);
                ++dockHitCount;
            }
        };

        QList<QWidget*> candidateWidgetList = contentWidget->findChildren<QWidget*>();
        candidateWidgetList.prepend(contentWidget);
        for (QWidget* candidateWidget : candidateWidgetList)
        {
            if (candidateWidget == nullptr || candidateWidget->isWindow())
            {
                // Independent top-level windows (dropdown popups, embedded dialogs, etc.) do not belong to page content.
                continue;
            }
            if (visiblePageOnly && !candidateWidget->isVisibleTo(contentWidget))
            {
                // "Current page" indexes only currently revealed Tab/Stack pages, not internal tabs.
                continue;
            }

            if (QLabel* labelWidget = qobject_cast<QLabel*>(candidateWidget))
            {
                kTryAppendHit(labelWidget, labelWidget->text());
            }
            else if (QAbstractButton* buttonWidget = qobject_cast<QAbstractButton*>(candidateWidget))
            {
                kTryAppendHit(buttonWidget, stripMnemonicMarkers(buttonWidget->text()));
            }
            else if (QGroupBox* groupBoxWidget = qobject_cast<QGroupBox*>(candidateWidget))
            {
                kTryAppendHit(groupBoxWidget, groupBoxWidget->title());
            }
            else if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(candidateWidget))
            {
                const int kFirstTabIndex = visiblePageOnly ? tabWidget->currentIndex() : 0;
                const int kEndTabIndex = visiblePageOnly
                    ? std::min(tabWidget->count(), kFirstTabIndex + 1)
                    : tabWidget->count();
                for (int tabIndex = std::max(0, kFirstTabIndex);
                     tabIndex < kEndTabIndex;
                     ++tabIndex)
                {
                    kTryAppendHit(
                        tabWidget->widget(tabIndex),
                        stripMnemonicMarkers(tabWidget->tabText(tabIndex)));
                }
            }
            else if (QComboBox* comboBoxWidget = qobject_cast<QComboBox*>(candidateWidget))
            {
                if (comboBoxWidget->count() <= kComboBoxItemScanLimit)
                {
                    for (int itemIndex = 0; itemIndex < comboBoxWidget->count(); ++itemIndex)
                    {
                        kTryAppendHit(comboBoxWidget, comboBoxWidget->itemText(itemIndex));
                    }
                }
            }
            else if (QLineEdit* lineEditWidget = qobject_cast<QLineEdit*>(candidateWidget))
            {
                kTryAppendHit(lineEditWidget, lineEditWidget->placeholderText());
            }
            else if (QAbstractItemView* itemViewWidget = qobject_cast<QAbstractItemView*>(candidateWidget))
            {
                // Generic view index column header; table views also append navigable cell hits.
                const bool kHasHorizontalHeader =
                    qobject_cast<QTableView*>(itemViewWidget) != nullptr
                    || qobject_cast<QTreeView*>(itemViewWidget) != nullptr;
                QAbstractItemModel* itemModel = itemViewWidget->model();
                if (kHasHorizontalHeader && itemModel != nullptr)
                {
                    const int kColumnCount = std::min(itemModel->columnCount(), kHeaderColumnScanLimit);
                    for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
                    {
                        kTryAppendHit(
                            itemViewWidget,
                            itemModel->headerData(columnIndex, Qt::Horizontal, Qt::DisplayRole).toString());
                    }
                }
                kTryAppendTableMatches(qobject_cast<QTableView*>(itemViewWidget));
            }

            if (dockHitCount >= kMaxHitsPerDock)
            {
                break;
            }
        }
    }

    // collectDirectTableSearchHits: Scan only explicit target tables for use within the 'current table' scope.
    void collectDirectTableSearchHits(
        QTableView* tableView,
        const QString& queryText,
        QVector<ks::ui::UiSearchHit>& outHitList)
    {
        if (tableView == nullptr)
        {
            return;
        }

        ads::CDockWidget* dockWidget = dockWidgetForWidget(tableView);
        const QString kDockTitleText = dockWidget != nullptr
            ? normalizeUiText(dockWidget->windowTitle())
            : normalizeUiText(tableView->window()->windowTitle());
        const QVector<ks::ui::TableCellSearchMatch> kTableMatchList =
            ks::ui::collectTableCellSearchMatches(
                tableView,
                queryText,
                kMaxTotalHits);
        for (const ks::ui::TableCellSearchMatch& tableMatch : kTableMatchList)
        {
            ks::ui::UiSearchHit hitEntry;
            hitEntry.pageDockWidget = dockWidget;
            hitEntry.targetWidget = tableView;
            hitEntry.targetTableView = tableView;
            hitEntry.targetModelIndex = tableMatch.modelIndex;
            hitEntry.matchedText = tableMatch.matchedText;
            hitEntry.pagePathText = dockWidget != nullptr
                ? buildPagePathText(dockWidget, kDockTitleText, tableView)
                    + QStringLiteral(" › ")
                    + tableMatch.locationText
                : kDockTitleText
                    + QStringLiteral(" › ")
                    + tableMatch.locationText;
            hitEntry.matchRank = tableMatch.matchRank;
            outHitList.push_back(hitEntry);
        }
    }

    // scrollAncestorsToWidget：
    // - Purpose: Scroll all QScrollArea ancestors of the target widget to make the target visible.
    // - Input targetWidget: widget to reveal.
    void scrollAncestorsToWidget(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            if (cursorWidget == targetWidget)
            {
                continue;
            }
            if (QScrollArea* scrollAreaWidget = qobject_cast<QScrollArea*>(cursorWidget))
            {
                scrollAreaWidget->ensureWidgetVisible(targetWidget, 48, 48);
            }
        }
    }

    // revealHitTargetWithinPage：
    // - Purpose: Recursively reveal the target control within the target Dock.
    // - Processing: Traverse upward; when hitting QTabWidget/QStackedWidget pages, switch
    //   to the page containing the target, then scroll the scroll area to the target.
    // - Input targetWidget: hit control.
    void revealHitTargetWithinPage(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (parentWidget == nullptr)
            {
                break;
            }
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int kTabIndex = tabWidget->indexOf(cursorWidget);
                    if (kTabIndex >= 0 && tabWidget->currentIndex() != kTabIndex)
                    {
                        tabWidget->setCurrentIndex(kTabIndex);
                    }
                }
                else
                {
                    const int kStackIndex = stackedWidget->indexOf(cursorWidget);
                    if (kStackIndex >= 0 && stackedWidget->currentIndex() != kStackIndex)
                    {
                        stackedWidget->setCurrentIndex(kStackIndex);
                    }
                }
            }
        }

        scrollAncestorsToWidget(targetWidget);
    }

    // buildSnippetHtml：
    // - Purpose: Truncate matched text into display snippets and apply emphasis color to the matched query substrings.
    // - Parameters: matchedText (full matched text), queryText (query), accentColorHex (accent color hex).
    // - Out: Escaped HTML snippet (including ellipsis marker).
    QString buildSnippetHtml(
        const QString& matchedText,
        const QString& queryText,
        const QString& accentColorHex)
    {
        const int kMatchedLength = static_cast<int>(matchedText.size());
        const int kFirstMatchIndex = static_cast<int>(
            matchedText.indexOf(queryText, 0, Qt::CaseInsensitive));
        QString snippetText = matchedText;
        bool clippedHead = false;
        bool clippedTail = false;
        if (kMatchedLength > kSnippetMaxLength)
        {
            int snippetStart = 0;
            if (kFirstMatchIndex > kSnippetMatchLeadin)
            {
                snippetStart = std::min(
                    kFirstMatchIndex - kSnippetMatchLeadin,
                    kMatchedLength - kSnippetMaxLength);
            }
            snippetText = matchedText.mid(snippetStart, kSnippetMaxLength);
            clippedHead = snippetStart > 0;
            clippedTail = (snippetStart + kSnippetMaxLength) < kMatchedLength;
        }

        QString htmlText;
        int cursorIndex = 0;
        while (cursorIndex <= snippetText.size())
        {
            const int kMatchIndex = queryText.isEmpty()
                ? -1
                : snippetText.indexOf(queryText, cursorIndex, Qt::CaseInsensitive);
            if (kMatchIndex < 0)
            {
                htmlText += snippetText.mid(cursorIndex).toHtmlEscaped();
                break;
            }
            htmlText += snippetText.mid(cursorIndex, kMatchIndex - cursorIndex).toHtmlEscaped();
            htmlText += QStringLiteral("<span style=\"color:%1;font-weight:600;\">").arg(accentColorHex);
            htmlText += snippetText.mid(kMatchIndex, queryText.size()).toHtmlEscaped();
            htmlText += QStringLiteral("</span>");
            cursorIndex = kMatchIndex + queryText.size();
        }

        if (clippedHead)
        {
            htmlText.prepend(QStringLiteral("…"));
        }
        if (clippedTail)
        {
            htmlText.append(QStringLiteral("…"));
        }
        return htmlText;
    }

    // ============================================================
    // SearchResultItemDelegate
    // Notes:
    // - Result row rendering delegate: First row displays matched text (highlighted substring in
    //   bold with emphasis color); second row displays page path (secondary color, smaller font size).
    // - Draws a semi-transparent rounded rectangle with the theme emphasis color for selected/hovered rows.
    // ============================================================
    class SearchResultItemDelegate final : public QStyledItemDelegate
    {
    public:
        using QStyledItemDelegate::QStyledItemDelegate;

        void paint(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);

            const QRect kItemRect = option.rect.adjusted(4, 2, -4, -2);
            const bool kSelectedState = option.state.testFlag(QStyle::State_Selected);
            const bool kHoveredState = option.state.testFlag(QStyle::State_MouseOver);
            if (kSelectedState || kHoveredState)
            {
                QColor rowBackgroundColor = ksword_theme::primaryAccentColor();
                rowBackgroundColor.setAlpha(kSelectedState ? 52 : 26);
                painter->setPen(Qt::NoPen);
                painter->setBrush(rowBackgroundColor);
                painter->drawRoundedRect(kItemRect, 4, 4);
            }

            QTextDocument contentDocument;
            contentDocument.setDefaultFont(option.font);
            QTextOption noWrapOption = contentDocument.defaultTextOption();
            noWrapOption.setWrapMode(QTextOption::NoWrap);
            contentDocument.setDefaultTextOption(noWrapOption);
            contentDocument.setDocumentMargin(0.0);
            contentDocument.setHtml(index.data(kResultHtmlRole).toString());

            painter->translate(kItemRect.left() + 8, kItemRect.top() + 4);
            contentDocument.drawContents(
                painter,
                QRectF(0, 0, kItemRect.width() - 16, kItemRect.height() - 8));
            painter->restore();
        }

        QSize sizeHint(
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            Q_UNUSED(option);
            Q_UNUSED(index);
            return QSize(200, kResultItemHeight);
        }
    };

    // ============================================================
    // SearchHitFlashOverlay
    // Notes:
    // - Temporary highlight overlay on hit controls: rounded border with theme accent color
    //   + light fill, flashes three times in a sine pulse pattern before self-destroying.
    // - Acts as a child control of the target control, scales with it, and fully passes through mouse events.
    // ============================================================
    class SearchHitFlashOverlay final : public QWidget
    {
    public:
        // flashOnWidget：
        // - Purpose: Flash a search highlight on the target control (remove old highlight first).
        // - Input targetWidget: widget to highlight.
        static void flashOnWidget(QWidget* targetWidget)
        {
            if (targetWidget == nullptr)
            {
                return;
            }
            if (QWidget* previousOverlay = targetWidget->findChild<QWidget*>(
                    QStringLiteral("ksSearchHitFlashOverlay"),
                    Qt::FindDirectChildrenOnly))
            {
                previousOverlay->deleteLater();
            }
            auto* overlayWidget = new SearchHitFlashOverlay(targetWidget);
            overlayWidget->show();
            overlayWidget->raise();
        }

        explicit SearchHitFlashOverlay(QWidget* targetWidget)
            : QWidget(targetWidget)
            , targetWidget_(targetWidget)
        {
            setObjectName(QStringLiteral("ksSearchHitFlashOverlay"));
            setAttribute(Qt::WA_TransparentForMouseEvents, true);
            setAttribute(Qt::WA_NoSystemBackground, true);
            setGeometry(targetWidget->rect());
            targetWidget->installEventFilter(this);

            // kFlashPulseCount usage: Total number of pulses; animation value 0..N, fractional part drives the phase of a single pulse.
            constexpr double kFlashPulseCount = 3.0;
            auto* pulseAnimation = new QVariantAnimation(this);
            pulseAnimation->setStartValue(0.0);
            pulseAnimation->setEndValue(kFlashPulseCount);
            pulseAnimation->setDuration(1800);
            connect(pulseAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& animationValue) {
                const double kPhaseValue = animationValue.toDouble();
                const double kPulseFraction = kPhaseValue - std::floor(kPhaseValue);
                // envelopeFactor usage: Overall intensity slightly decays over time, fading out naturally before the end.
                const double kEnvelopeFactor = 1.0 - (kPhaseValue / 3.0) * 0.35;
                pulseIntensity_ = std::sin(kPulseFraction * 3.14159265358979323846) * kEnvelopeFactor;
                update();
            });
            connect(pulseAnimation, &QVariantAnimation::finished, this, [this]() {
                deleteLater();
            });
            pulseAnimation->start();
        }

    protected:
        void paintEvent(QPaintEvent* paintEventPointer) override
        {
            Q_UNUSED(paintEventPointer);
            if (pulseIntensity_ <= 0.0)
            {
                return;
            }

            QPainter overlayPainter(this);
            overlayPainter.setRenderHint(QPainter::Antialiasing, true);

            QColor accentColor = ksword_theme::primaryAccentColor();
            QColor borderColor = accentColor;
            borderColor.setAlpha(static_cast<int>(210.0 * pulseIntensity_));
            QColor fillColor = accentColor;
            fillColor.setAlpha(static_cast<int>(42.0 * pulseIntensity_));

            QPen borderPen(borderColor);
            borderPen.setWidthF(2.0);
            overlayPainter.setPen(borderPen);
            overlayPainter.setBrush(fillColor);
            overlayPainter.drawRoundedRect(
                QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5),
                4.0,
                4.0);
        }

        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == targetWidget_)
            {
                if (eventObject->type() == QEvent::Resize)
                {
                    setGeometry(targetWidget_->rect());
                }
                else if (eventObject->type() == QEvent::Hide
                    || eventObject->type() == QEvent::Destroy)
                {
                    deleteLater();
                }
            }
            return QWidget::eventFilter(watchedObject, eventObject);
        }

    private:
        QPointer<QWidget> targetWidget_;  // m_targetWidget: The highlighted target widget.
        double pulseIntensity_ = 0.0;     // m_pulseIntensity: Current pulse intensity (0..1).
    };

    // widgetBelongsToBranch：
    // - Purpose: Determine if a widget belongs to a specified ancestor branch (including the ancestor itself).
    // - Input widgetObject: the matched widget; expectedAncestor: the expected ancestor.
    // - Out: true if the widget belongs to the branch.
    bool widgetBelongsToBranch(const QWidget* widgetObject, const QWidget* expectedAncestor)
    {
        if (widgetObject == nullptr || expectedAncestor == nullptr)
        {
            return false;
        }
        for (const QWidget* cursorWidget = widgetObject;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == expectedAncestor)
            {
                return true;
            }
        }
        return false;
    }
}

namespace ks::ui
{
    GlobalUiSearchController::GlobalUiSearchController(
        QWidget* popupHostWindow,
        QLineEdit* searchInputEdit,
        QWidget* popupAnchorWidget,
        QObject* parentObject)
        : QObject(parentObject)
        , popupHostWindow_(popupHostWindow)
        , searchInputEdit_(searchInputEdit)
        , popupAnchorWidget_(popupAnchorWidget)
    {
        gActiveSearchController = this;
        searchDebounceTimer_ = new QTimer(this);
        searchDebounceTimer_->setSingleShot(true);
        searchDebounceTimer_->setInterval(kSearchDebounceIntervalMs);
        connect(searchDebounceTimer_, &QTimer::timeout, this, [this]() {
            runSearchNow();
        });

        if (searchInputEdit_ != nullptr)
        {
            searchInputEdit_->installEventFilter(this);
        }
        if (popupHostWindow_ != nullptr)
        {
            popupHostWindow_->installEventFilter(this);
        }
        if (qApp != nullptr)
        {
            // Application-level filtering is only used to dismiss pop-ups when clicking outside; pass through directly when the pop-up is hidden.
            qApp->installEventFilter(this);
        }
        QTimer::singleShot(0, this, [this]() {
            refreshSearchScopeDisplayText();
        });
    }

    GlobalUiSearchController::~GlobalUiSearchController()
    {
        clearSearchResultFilters();
        if (gActiveSearchController == this)
        {
            gActiveSearchController.clear();
        }
    }

    void GlobalUiSearchController::setDockListProvider(DockListProvider dockListProvider)
    {
        dockListProvider_ = std::move(dockListProvider);
    }

    void GlobalUiSearchController::setDockPreparer(DockPreparer dockPreparer)
    {
        dockPreparer_ = std::move(dockPreparer);
    }

    void GlobalUiSearchController::setDockActivator(DockActivator dockActivator)
    {
        dockActivator_ = std::move(dockActivator);
    }

    void GlobalUiSearchController::activateForTable(
        QTableView* tableView,
        const QString& queryText,
        const bool focusTopInput)
    {
        if (tableView == nullptr)
        {
            return;
        }

        targetTableView_ = tableView;
        recentTableView_ = tableView;
        recentPageDockWidget_ = dockWidgetForWidget(tableView);
        setSearchScope(UiSearchScope::kCurrentTable);

        // Page switching or Dock restoration may also cause the title bar input box to regain focus; these focus changes must
        // not be treated as user requests to automatically expand the result popup. Only when the table search entry explicitly
        // requests focus and the input box currently lacks focus should the next FocusIn event be allowed to expand the popup.
        showPopupOnNextSearchInputFocus_ = focusTopInput
            && searchInputEdit_ != nullptr
            && !searchInputEdit_->hasFocus();
        emit requestSearchInputActivation(focusTopInput);

        if (searchInputEdit_ != nullptr && !queryText.isNull())
        {
            if (searchInputEdit_->text() != queryText)
            {
                searchInputEdit_->setText(queryText);
            }
            else
            {
                handleQueryEdited(queryText);
            }
        }
    }

    QString GlobalUiSearchController::searchScopeDisplayText() const
    {
        switch (searchScope_)
        {
        case UiSearchScope::kCurrentPage:
            return ks::i18n::sourceText(QStringLiteral("当前页面"));
        case UiSearchScope::kCurrentTable:
        {
            QTableView* tableView = resolveCurrentTable();
            const QString kTableName = ks::ui::resolveTableSearchDisplayName(tableView);
            return ks::i18n::sourceText(QStringLiteral("当前表格（%1）")).arg(kTableName);
        }
        case UiSearchScope::kGlobal:
        default:
            return ks::i18n::sourceText(QStringLiteral("全局"));
        }
    }

    void GlobalUiSearchController::handleQueryEdited(const QString& queryText)
    {
        pendingQueryText_ = queryText;
        if (!searchModeActive_)
        {
            return;
        }
        if (!isCurrentQueryLongEnough(queryText.trimmed()))
        {
            dismissPopup();
            clearSearchResultFilters();
            currentHitList_.clear();
            if (searchInputEdit_ != nullptr && searchInputEdit_->hasFocus())
            {
                showOptionsOnlyPopup();
            }
            return;
        }
        searchDebounceTimer_->start();
    }

    void GlobalUiSearchController::setSearchInputActive(const bool searchModeActive)
    {
        searchModeActive_ = searchModeActive;
        if (!searchModeActive)
        {
            dismissPopup();
            clearSearchResultFilters();
        }
        else if (isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
        {
            searchDebounceTimer_->start();
        }
        else if (searchInputEdit_ != nullptr && searchInputEdit_->hasFocus())
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::setSearchResultsOnly(const bool checked)
    {
        if (searchResultsOnly_ == checked)
        {
            refreshSearchOptionControls();
            if (searchScope_ == UiSearchScope::kCurrentTable)
            {
            }
            return;
        }

        const bool kPopupWasVisible = popupPanel_ != nullptr && popupPanel_->isVisible();
        dismissPopup();
        clearSearchResultFilters();
        searchResultsOnly_ = checked;
        refreshSearchOptionControls();
        if (searchScope_ == UiSearchScope::kCurrentTable)
        {
        }
        if (searchModeActive_ && isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
        {
            if (kPopupWasVisible)
            {
                runSearchNow();
            }
            else
            {
                searchDebounceTimer_->start();
            }
        }
        else if (kPopupWasVisible)
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::dismissPopup()
    {
        // Incrementing the generation number invalidates all asynchronous shards still in the event queue.
        ++searchGeneration_;
        searchInProgress_ = false;
        if (searchDebounceTimer_ != nullptr)
        {
            searchDebounceTimer_->stop();
        }
        if (popupPanel_ != nullptr && popupPanel_->isVisible())
        {
            popupPanel_->hide();
        }
    }

    bool GlobalUiSearchController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        const QEvent::Type kEventType = eventObject->type();

        if (watchedObject == searchInputEdit_)
        {
            if (kEventType == QEvent::KeyPress && searchModeActive_)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                const bool kPopupVisible = popupPanel_ != nullptr && popupPanel_->isVisible();
                switch (keyEvent->key())
                {
                case Qt::Key_Tab:
                    cycleSearchScope(1);
                    keyEvent->accept();
                    return true;
                case Qt::Key_Backtab:
                    cycleSearchScope(-1);
                    keyEvent->accept();
                    return true;
                case Qt::Key_Down:
                    if (kPopupVisible)
                    {
                        moveSelection(1);
                    }
                    else if (isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Up:
                    if (kPopupVisible)
                    {
                        moveSelection(-1);
                        return true;
                    }
                    break;
                case Qt::Key_Return:
                case Qt::Key_Enter:
                    if (kPopupVisible)
                    {
                        const int kCurrentRow = resultListWidget_ != nullptr
                            ? std::max(0, resultListWidget_->currentRow())
                            : 0;
                        activateHitAtRow(kCurrentRow);
                    }
                    else if (isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Escape:
                    if (kPopupVisible)
                    {
                        dismissPopup();
                        return true;
                    }
                    break;
                default:
                    break;
                }
            }
            else if (searchModeActive_)
            {
                const bool kOpenedByMouse = kEventType == QEvent::MouseButtonPress;
                const bool kOpenedByExplicitTableSearch = kEventType == QEvent::FocusIn
                    && showPopupOnNextSearchInputFocus_;
                if (kEventType == QEvent::FocusIn)
                {
                    showPopupOnNextSearchInputFocus_ = false;
                }
                if (!kOpenedByMouse && !kOpenedByExplicitTableSearch)
                {
                    return false;
                }
                if (isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
                {
                    searchDebounceTimer_->start();
                }
                else
                {
                    QTimer::singleShot(0, this, [this]() {
                        if (searchModeActive_)
                        {
                            showOptionsOnlyPopup();
                        }
                        });
                }
            }
            return false;
        }

        if (kEventType == QEvent::LanguageChange)
        {
            refreshSearchScopeDisplayText();
        }

        if (kEventType == QEvent::FocusIn || kEventType == QEvent::MouseButtonPress)
        {
            QWidget* contextWidget = qobject_cast<QWidget*>(watchedObject);
            if (contextWidget != nullptr)
            {
                if (QTableView* tableView = tableViewForWidget(contextWidget))
                {
                    recentTableView_ = tableView;
                    recentPageDockWidget_ = dockWidgetForWidget(tableView);
                    if (searchScope_ == UiSearchScope::kCurrentTable
                        && targetTableView_ != tableView)
                    {
                        dismissPopup();
                        clearSearchResultFilters();
                        targetTableView_ = tableView;
                        refreshSearchScopeDisplayText();
                        if (searchModeActive_
                            && isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
                        {
                            searchDebounceTimer_->start();
                        }
                    }
                }
                else if (ads::CDockWidget* dockWidget = dockWidgetForWidget(contextWidget))
                {
                    const bool kCurrentPageChanged = searchScope_ == UiSearchScope::kCurrentPage
                        && recentPageDockWidget_ != dockWidget;
                    if (kCurrentPageChanged)
                    {
                        dismissPopup();
                        clearSearchResultFilters();
                    }
                    recentPageDockWidget_ = dockWidget;
                    if (kCurrentPageChanged
                        && searchModeActive_
                        && isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
                    {
                        searchDebounceTimer_->start();
                    }
                }
            }
        }

        if (watchedObject == popupHostWindow_)
        {
            const bool kPopupVisible = popupPanel_ != nullptr && popupPanel_->isVisible();
            if (kPopupVisible && (kEventType == QEvent::Resize || kEventType == QEvent::Move))
            {
                repositionPopupPanel();
            }
            else if (kPopupVisible && kEventType == QEvent::WindowDeactivate)
            {
                dismissPopup();
            }
            return false;
        }

        if (kEventType == QEvent::MouseButtonPress
            && popupPanel_ != nullptr
            && popupPanel_->isVisible())
        {
            QWidget* clickedWidget = qobject_cast<QWidget*>(watchedObject);
            if (clickedWidget != nullptr
                && !widgetBelongsToBranch(clickedWidget, popupPanel_)
                && !widgetBelongsToBranch(clickedWidget, popupAnchorWidget_))
            {
                dismissPopup();
            }
        }

        return false;
    }

    void GlobalUiSearchController::ensurePopupCreated()
    {
        if (popupPanel_ != nullptr || popupHostWindow_ == nullptr)
        {
            return;
        }

        popupPanel_ = new QFrame(popupHostWindow_);
        popupPanel_->setObjectName(QStringLiteral("ksGlobalUiSearchPopup"));
        popupPanel_->setAttribute(Qt::WA_StyledBackground, true);
        popupPanel_->hide();

        auto* panelLayout = new QVBoxLayout(popupPanel_);
        panelLayout->setContentsMargins(4, 4, 4, 4);
        panelLayout->setSpacing(0);

        searchOptionsRow_ = new QWidget(popupPanel_);
        searchOptionsRow_->setFixedHeight(kSearchOptionsRowHeight);
        auto* optionsLayout = new QHBoxLayout(searchOptionsRow_);
        optionsLayout->setContentsMargins(8, 4, 8, 4);
        optionsLayout->setSpacing(8);

        searchScopeLabel_ = new QLabel(searchOptionsRow_);
        searchScopeTabs_ = new QTabBar(searchOptionsRow_);
        searchScopeTabs_->setMinimumWidth(360);
        searchScopeTabs_->setDrawBase(false);
        searchScopeTabs_->setExpanding(true);
        searchScopeTabs_->setUsesScrollButtons(false);
        searchScopeTabs_->setElideMode(Qt::ElideRight);
        searchScopeTabs_->addTab(QString());
        searchScopeTabs_->addTab(QString());
        searchScopeTabs_->addTab(QString());
        searchResultsOnlyCheck_ = new QCheckBox(searchOptionsRow_);

        optionsLayout->addWidget(searchScopeLabel_, 0);
        optionsLayout->addWidget(searchScopeTabs_, 1);
        optionsLayout->addStretch(1);
        optionsLayout->addWidget(searchResultsOnlyCheck_, 0);

        connect(
            searchScopeTabs_,
            &QTabBar::currentChanged,
            this,
            [this](const int tabIndex) {
                if (tabIndex < static_cast<int>(UiSearchScope::kGlobal)
                    || tabIndex > static_cast<int>(UiSearchScope::kCurrentTable))
                {
                    return;
                }
                setSearchScope(static_cast<UiSearchScope>(tabIndex));
            });
        connect(
            searchResultsOnlyCheck_,
            &QCheckBox::toggled,
            this,
            &GlobalUiSearchController::setSearchResultsOnly);

        resultListWidget_ = new QListWidget(popupPanel_);
        resultListWidget_->setObjectName(QStringLiteral("ksGlobalUiSearchResultList"));
        resultListWidget_->setFrameShape(QFrame::NoFrame);
        resultListWidget_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        resultListWidget_->setSelectionMode(QAbstractItemView::SingleSelection);
        resultListWidget_->setUniformItemSizes(true);
        resultListWidget_->setMouseTracking(true);
        resultListWidget_->viewport()->setAttribute(Qt::WA_Hover, true);
        resultListWidget_->setItemDelegate(new SearchResultItemDelegate(resultListWidget_));
        connect(resultListWidget_, &QListWidget::itemClicked, this, [this](QListWidgetItem* listItem) {
            if (resultListWidget_ != nullptr && listItem != nullptr)
            {
                activateHitAtRow(resultListWidget_->row(listItem));
            }
        });
        connect(resultListWidget_, &QListWidget::itemActivated, this, [this](QListWidgetItem* listItem) {
            if (resultListWidget_ != nullptr && listItem != nullptr)
            {
                activateHitAtRow(resultListWidget_->row(listItem));
            }
        });

        emptyHintLabel_ = new QLabel(QStringLiteral("未找到匹配内容"), popupPanel_);
        emptyHintLabel_->setObjectName(QStringLiteral("ksGlobalUiSearchEmptyHint"));
        emptyHintLabel_->setAlignment(Qt::AlignCenter);

        // Progress row: displays "Searching: Dock name (n/N)" + progress bar during asynchronous scanning.
        searchProgressRow_ = new QWidget(popupPanel_);
        searchProgressRow_->setObjectName(QStringLiteral("ksGlobalUiSearchProgressRow"));
        auto* progressLayout = new QVBoxLayout(searchProgressRow_);
        progressLayout->setContentsMargins(10, 6, 10, 8);
        progressLayout->setSpacing(5);

        searchProgressLabel_ = new QLabel(searchProgressRow_);
        searchProgressLabel_->setObjectName(QStringLiteral("ksGlobalUiSearchProgressLabel"));

        searchProgressBar_ = new QProgressBar(searchProgressRow_);
        searchProgressBar_->setObjectName(QStringLiteral("ksGlobalUiSearchProgressBar"));
        searchProgressBar_->setTextVisible(false);
        searchProgressBar_->setFixedHeight(6);

        progressLayout->addWidget(searchProgressLabel_, 0);
        progressLayout->addWidget(searchProgressBar_, 0);
        searchProgressRow_->hide();

        panelLayout->addWidget(searchOptionsRow_, 0);
        panelLayout->addWidget(searchProgressRow_, 0);
        panelLayout->addWidget(resultListWidget_, 1);
        panelLayout->addWidget(emptyHintLabel_, 0);
        refreshSearchOptionControls();
    }

    void GlobalUiSearchController::refreshSearchOptionControls()
    {
        if (searchScopeLabel_ != nullptr)
        {
            searchScopeLabel_->setText(ks::i18n::sourceText(QStringLiteral("范围")));
        }
        if (searchScopeTabs_ != nullptr)
        {
            const QSignalBlocker kScopeSignalBlocker(searchScopeTabs_);
            searchScopeTabs_->setTabText(
                static_cast<int>(UiSearchScope::kGlobal),
                ks::i18n::sourceText(QStringLiteral("全局")));
            searchScopeTabs_->setTabText(
                static_cast<int>(UiSearchScope::kCurrentPage),
                ks::i18n::sourceText(QStringLiteral("当前页面")));
            searchScopeTabs_->setTabText(
                static_cast<int>(UiSearchScope::kCurrentTable),
                ks::i18n::sourceText(QStringLiteral("当前表格（%1）")).arg(
                    ks::ui::resolveTableSearchDisplayName(resolveCurrentTable())));
            searchScopeTabs_->setCurrentIndex(static_cast<int>(searchScope_));
        }
        if (searchResultsOnlyCheck_ != nullptr)
        {
            const QSignalBlocker kResultsOnlySignalBlocker(searchResultsOnlyCheck_);
            searchResultsOnlyCheck_->setText(
                ks::i18n::sourceText(QStringLiteral("仅显示搜索结果")));
            searchResultsOnlyCheck_->setChecked(searchResultsOnly_);
        }
    }

    void GlobalUiSearchController::showOptionsOnlyPopup()
    {
        ensurePopupCreated();
        currentHitList_.clear();
        if (searchProgressRow_ != nullptr)
        {
            searchProgressRow_->hide();
        }
        if (resultListWidget_ != nullptr)
        {
            resultListWidget_->clear();
            resultListWidget_->hide();
        }
        if (emptyHintLabel_ != nullptr)
        {
            emptyHintLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("搜索")));
            emptyHintLabel_->show();
        }
        refreshSearchOptionControls();
        showPopupPanel();
    }

    void GlobalUiSearchController::runSearchNow()
    {
        const QString kQueryText = pendingQueryText_.trimmed();
        if (!searchModeActive_ || !isCurrentQueryLongEnough(kQueryText))
        {
            dismissPopup();
            clearSearchResultFilters();
            return;
        }
        if (searchScope_ != UiSearchScope::kCurrentTable && !dockListProvider_)
        {
            return;
        }
        if (searchInProgress_
            && kQueryText == activeQueryText_
            && searchScope_ == activeSearchScope_)
        {
            // A scan for the same query is already in progress (e.g., a duplicate start triggered by focus); reuse it.
            return;
        }

        // New generation invalidates all old scan fragments still in the event queue; first revoke the previous round's attached row filters.
        clearSearchResultFilters();
        ++searchGeneration_;
        activeQueryText_ = kQueryText;
        activeSearchScope_ = searchScope_;
        currentHitList_.clear();
        pendingSearchDockList_.clear();
        pendingDirectTableView_.clear();
        if (activeSearchScope_ == UiSearchScope::kCurrentTable)
        {
            pendingDirectTableView_ = resolveCurrentTable();
        }
        else if (activeSearchScope_ == UiSearchScope::kCurrentPage)
        {
            if (ads::CDockWidget* currentDockWidget = resolveCurrentPageDock())
            {
                pendingSearchDockList_.append(currentDockWidget);
            }
        }
        else
        {
            const QList<ads::CDockWidget*> kDockList = dockListProvider_();
            for (ads::CDockWidget* dockWidget : kDockList)
            {
                if (dockWidget != nullptr)
                {
                    pendingSearchDockList_.append(QPointer<ads::CDockWidget>(dockWidget));
                }
            }
        }
        nextSearchDockIndex_ = 0;
        searchInProgress_ = true;

        // Progress state popup: hide the result list and empty state, showing only the progress row.
        ensurePopupCreated();
        if (resultListWidget_ != nullptr)
        {
            resultListWidget_->clear();
            resultListWidget_->setVisible(false);
        }
        if (emptyHintLabel_ != nullptr)
        {
            emptyHintLabel_->setVisible(false);
        }
        if (searchProgressBar_ != nullptr)
        {
            const int kWorkItemCount = activeSearchScope_ == UiSearchScope::kCurrentTable
                ? 1
                : static_cast<int>(pendingSearchDockList_.size());
            searchProgressBar_->setRange(
                0,
                std::max(1, kWorkItemCount));
            searchProgressBar_->setValue(0);
        }
        if (searchProgressRow_ != nullptr)
        {
            searchProgressRow_->setVisible(true);
        }
        if (!pendingSearchDockList_.isEmpty()
            && pendingSearchDockList_.first() != nullptr)
        {
            updateSearchProgressUi(pendingSearchDockList_.first()->windowTitle());
        }
        else if (!pendingDirectTableView_.isNull())
        {
            updateSearchProgressUi(
                ks::ui::resolveTableSearchDisplayName(pendingDirectTableView_.data()));
        }
        showPopupPanel();

        const quint64 kSearchGeneration = searchGeneration_;
        QTimer::singleShot(0, this, [this, kSearchGeneration]() {
            processNextSearchChunk(kSearchGeneration);
        });
    }

    void GlobalUiSearchController::processNextSearchChunk(const quint64 searchGeneration)
    {
        if (searchGeneration != searchGeneration_ || !searchInProgress_)
        {
            return;
        }

        const int kWorkItemCount = activeSearchScope_ == UiSearchScope::kCurrentTable
            ? 1
            : static_cast<int>(pendingSearchDockList_.size());
        if (nextSearchDockIndex_ >= kWorkItemCount
            || (!searchResultsOnly_
                && currentHitList_.size() >= kMaxTotalHits))
        {
            finishAsyncSearch();
            return;
        }

        if (activeSearchScope_ == UiSearchScope::kCurrentTable)
        {
            collectDirectTableSearchHits(
                pendingDirectTableView_.data(),
                activeQueryText_,
                currentHitList_);
            applySearchResultFilterToTable(
                pendingDirectTableView_.data());
        }
        else
        {
            ads::CDockWidget* dockWidget =
                pendingSearchDockList_.at(nextSearchDockIndex_).data();
            if (dockWidget != nullptr)
            {
                updateSearchProgressUi(dockWidget->windowTitle());
                // Lazy loading completion may take hundreds of milliseconds but only blocks the current shard;
                // Yield the event loop between shards to keep the progress bar and input responsive.
                if (dockPreparer_)
                {
                    dockPreparer_(dockWidget);
                }
                collectDockSearchHits(
                    dockWidget,
                    activeQueryText_,
                    currentHitList_,
                    activeSearchScope_ == UiSearchScope::kCurrentPage);
                applySearchResultFiltersToDock(
                    dockWidget,
                    activeSearchScope_ == UiSearchScope::kCurrentPage);
            }
        }
        ++nextSearchDockIndex_;
        if (searchProgressBar_ != nullptr)
        {
            searchProgressBar_->setValue(nextSearchDockIndex_);
        }

        QTimer::singleShot(0, this, [this, searchGeneration]() {
            processNextSearchChunk(searchGeneration);
        });
    }

    void GlobalUiSearchController::finishAsyncSearch()
    {
        searchInProgress_ = false;
        if (currentHitList_.size() > kMaxTotalHits)
        {
            currentHitList_.resize(kMaxTotalHits);
        }

        std::stable_sort(
            currentHitList_.begin(),
            currentHitList_.end(),
            [](const UiSearchHit& leftHit, const UiSearchHit& rightHit) {
                return leftHit.matchRank < rightHit.matchRank;
            });

        if (searchProgressRow_ != nullptr)
        {
            searchProgressRow_->setVisible(false);
        }
        rebuildResultList();
        showPopupPanel();
    }

    void GlobalUiSearchController::updateSearchProgressUi(const QString& dockTitleText)
    {
        if (searchProgressLabel_ == nullptr)
        {
            return;
        }

        const int kDockCount = activeSearchScope_ == UiSearchScope::kCurrentTable
            ? 1
            : static_cast<int>(pendingSearchDockList_.size());
        const int kDisplayIndex = std::min(nextSearchDockIndex_ + 1, std::max(1, kDockCount));
        searchProgressLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("正在搜索：%1（%2/%3）"))
                .arg(normalizeUiText(dockTitleText))
                .arg(kDisplayIndex)
                .arg(kDockCount));
    }

    void GlobalUiSearchController::rebuildResultList()
    {
        ensurePopupCreated();
        if (resultListWidget_ == nullptr)
        {
            return;
        }

        // Use the query snapshot from the scan for highlighting: new input during debouncing triggers a new scan.
        const QString kQueryText = activeQueryText_;
        // These two colors are applied to the HTML of result items (<div style="color:...">), not to QSS:
        // QTextDocument does not recognize palette(...); dynamic roles are ignored and text falls back to inherited colors. Therefore,
        // *ColorHex() must be used to obtain the specific color. The result list is rebuilt every search round and follows theme changes.
        const QString kTextPrimaryHex = ksword_theme::textPrimaryColorHex();
        const QString kTextSecondaryHex = ksword_theme::textSecondaryColorHex();
        const QString kAccentTextHex = ksword_theme::themeColorName(
            ksword_theme::ensureTextContrast(
                ksword_theme::primaryAccentColor(),
                ksword_theme::surfaceColor(),
                3.0));

        resultListWidget_->clear();
        for (const UiSearchHit& hitEntry : currentHitList_)
        {
            auto* listItem = new QListWidgetItem(resultListWidget_);
            const QString kItemHtml = QStringLiteral(
                "<div style=\"color:%1;\">%2</div>"
                "<div style=\"color:%3;margin-top:3px;\">%4</div>")
                .arg(
                    kTextPrimaryHex,
                    buildSnippetHtml(hitEntry.matchedText, kQueryText, kAccentTextHex),
                    kTextSecondaryHex,
                    hitEntry.pagePathText.toHtmlEscaped());
            listItem->setData(kResultHtmlRole, kItemHtml);
            listItem->setToolTip(
                hitEntry.matchedText
                + QStringLiteral("\n")
                + hitEntry.pagePathText);
        }

        const bool kHasResults = !currentHitList_.isEmpty();
        resultListWidget_->setVisible(kHasResults);
        if (emptyHintLabel_ != nullptr)
        {
            emptyHintLabel_->setVisible(!kHasResults);
        }
        if (kHasResults)
        {
            resultListWidget_->setCurrentRow(0);
        }
    }

    void GlobalUiSearchController::showPopupPanel()
    {
        ensurePopupCreated();
        if (popupPanel_ == nullptr || popupHostWindow_ == nullptr)
        {
            return;
        }

        // Re-fetch the theme token on every display to ensure styles are immediately correct after switching between light and dark modes.
        popupPanel_->setStyleSheet(QStringLiteral(
            "#ksGlobalUiSearchPopup{"
            "  background:%1;"
            "  border:1px solid %2;"
            "  border-radius:6px;"
            "}"
            "#ksGlobalUiSearchPopup QListWidget{"
            "  background:transparent;"
            "  border:none;"
            "}"
            "#ksGlobalUiSearchPopup QLabel#ksGlobalUiSearchEmptyHint{"
            "  color:%3;"

            "  padding:14px 0;"
            "}"
            "#ksGlobalUiSearchPopup QLabel#ksGlobalUiSearchProgressLabel{"
            "  color:%3;"

            "}"
            "#ksGlobalUiSearchPopup QProgressBar#ksGlobalUiSearchProgressBar{"
            "  background:%4;"
            "  border:none;"
            "  border-radius:3px;"
            "}"
            "#ksGlobalUiSearchPopup QProgressBar#ksGlobalUiSearchProgressBar::chunk{"
            "  background:%5;"
            "  border-radius:3px;"
            "}")
            .arg(
                ksword_theme::surfaceHex(),
                ksword_theme::borderStrongHex(),
                ksword_theme::textSecondaryHex(),
                ksword_theme::surfaceAltHex(),
                ksword_theme::themeColorName(ksword_theme::primaryAccentColor())));
        if (searchOptionsRow_ != nullptr)
        {
            searchOptionsRow_->setStyleSheet(QStringLiteral(
                "background:%1;border-bottom:1px solid %2;")
                .arg(ksword_theme::surfaceAltHex(), ksword_theme::borderStrongHex()));
        }
        if (searchScopeLabel_ != nullptr)
        {
            searchScopeLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        }
        if (searchResultsOnlyCheck_ != nullptr)
        {
            searchResultsOnlyCheck_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        }
        if (searchScopeTabs_ != nullptr)
        {
            searchScopeTabs_->setStyleSheet(QStringLiteral(
                "QTabBar::tab{background:%1;color:%2;border:1px solid %3;"
                "border-right:none;padding:4px 12px;min-width:92px;}"
                "QTabBar::tab:first{border-top-left-radius:3px;border-bottom-left-radius:3px;}"
                "QTabBar::tab:last{border-right:1px solid %3;"
                "border-top-right-radius:3px;border-bottom-right-radius:3px;}"
                "QTabBar::tab:selected{background:%4;color:%5;border-color:%4;}"
                "QTabBar::tab:hover:!selected{background:%6;color:%2;}")
                .arg(
                    ksword_theme::surfaceHex(),
                    ksword_theme::textSecondaryHex(),
                    ksword_theme::borderStrongHex(),
                    ksword_theme::themeColorName(ksword_theme::primaryAccentColor()),
                    ksword_theme::onAccentHex(),
                    ksword_theme::surfaceMutedColorHex()));
        }

        const int kAnchorWidth = popupAnchorWidget_ != nullptr ? popupAnchorWidget_->width() : 460;
        const int kPanelWidth = std::clamp(
            kAnchorWidth + 220,
            460,
            std::max(320, popupHostWindow_->width() - 24));
        const int kVisibleRowCount = std::min(
            static_cast<int>(currentHitList_.size()),
            kMaxVisibleResultRows);
        int contentHeight = 48;
        if (searchInProgress_)
        {
            contentHeight = kProgressContentHeight;
        }
        else if (!currentHitList_.isEmpty())
        {
            contentHeight = kVisibleRowCount * kResultItemHeight + 2;
        }
        popupPanel_->setFixedSize(kPanelWidth, contentHeight + kSearchOptionsRowHeight + 8);

        repositionPopupPanel();
        popupPanel_->raise();
        popupPanel_->show();
    }

    void GlobalUiSearchController::repositionPopupPanel()
    {
        if (popupPanel_ == nullptr
            || popupHostWindow_ == nullptr
            || popupAnchorWidget_ == nullptr)
        {
            return;
        }

        const QPoint kAnchorBottomLeftGlobal =
            popupAnchorWidget_->mapToGlobal(QPoint(0, popupAnchorWidget_->height()));
        const QPoint kAnchorBottomLeftInHost =
            popupHostWindow_->mapFromGlobal(kAnchorBottomLeftGlobal);

        int panelLeft = kAnchorBottomLeftInHost.x()
            + (popupAnchorWidget_->width() - popupPanel_->width()) / 2;
        const int kMaxPanelLeft = std::max(8, popupHostWindow_->width() - popupPanel_->width() - 8);
        panelLeft = std::clamp(panelLeft, 8, kMaxPanelLeft);

        const int kPanelTop = kAnchorBottomLeftInHost.y() + 6;
        popupPanel_->move(panelLeft, kPanelTop);
    }

    void GlobalUiSearchController::activateHitAtRow(const int rowIndex)
    {
        if (searchInProgress_)
        {
            // Ignore activation request: list not populated during scan; row index does not correspond to hit.
            return;
        }
        if (rowIndex < 0 || rowIndex >= currentHitList_.size())
        {
            return;
        }

        const UiSearchHit kHitEntry = currentHitList_.at(rowIndex);
        ads::CDockWidget* dockWidget = kHitEntry.pageDockWidget.data();
        QTableView* targetTableView = kHitEntry.targetTableView.data();
        if (dockWidget == nullptr && targetTableView == nullptr)
        {
            dismissPopup();
            return;
        }

        if (dockWidget != nullptr && dockPreparer_)
        {
            dockPreparer_(dockWidget);
        }
        if (dockWidget != nullptr && dockActivator_)
        {
            dockActivator_(dockWidget);
        }
        else if (dockWidget != nullptr)
        {
            dockWidget->toggleView(true);
            dockWidget->raise();
        }
        else if (targetTableView != nullptr && targetTableView->window() != nullptr)
        {
            targetTableView->window()->show();
            targetTableView->window()->raise();
            targetTableView->window()->activateWindow();
        }

        QWidget* targetWidget = kHitEntry.targetWidget.data();
        dismissPopup();
        if (targetWidget == nullptr)
        {
            return;
        }

        revealHitTargetWithinPage(targetWidget);

        // Wait for layout adjustments during tab switching and Dock bring-to-front, then scroll once and highlight.
        QPointer<QWidget> guardedTarget(targetWidget);
        const QPersistentModelIndex kGuardedModelIndex = kHitEntry.targetModelIndex;
        QPointer<QTableView> guardedTableView(targetTableView);
        QTimer::singleShot(kFlashDelayMs, this, [guardedTarget, guardedTableView, kGuardedModelIndex]() {
            if (guardedTarget == nullptr)
            {
                return;
            }
            scrollAncestorsToWidget(guardedTarget);
            if (guardedTableView != nullptr && kGuardedModelIndex.isValid())
            {
                ks::ui::TableCellSearchMatch tableMatch;
                tableMatch.tableView = guardedTableView;
                tableMatch.modelIndex = kGuardedModelIndex;
                ks::ui::revealTableCellSearchMatch(tableMatch);
            }
            SearchHitFlashOverlay::flashOnWidget(guardedTarget);
        });
    }

    void GlobalUiSearchController::moveSelection(const int rowDelta)
    {
        if (resultListWidget_ == nullptr || resultListWidget_->count() <= 0)
        {
            return;
        }
        const int kTargetRow = std::clamp(
            resultListWidget_->currentRow() + rowDelta,
            0,
            resultListWidget_->count() - 1);
        resultListWidget_->setCurrentRow(kTargetRow);
    }

    void GlobalUiSearchController::setSearchScope(const UiSearchScope searchScope)
    {
        if (searchScope_ == searchScope)
        {
            refreshSearchScopeDisplayText();
            return;
        }

        const bool kPopupWasVisible = popupPanel_ != nullptr && popupPanel_->isVisible();
        dismissPopup();
        clearSearchResultFilters();
        searchScope_ = searchScope;
        if (searchScope_ == UiSearchScope::kCurrentTable)
        {
            targetTableView_ = resolveCurrentTable();
        }
        refreshSearchScopeDisplayText();
        if (searchModeActive_ && isCurrentQueryLongEnough(pendingQueryText_.trimmed()))
        {
            if (kPopupWasVisible)
            {
                runSearchNow();
            }
            else
            {
                searchDebounceTimer_->start();
            }
        }
        else if (kPopupWasVisible)
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::cycleSearchScope(const int direction)
    {
        constexpr int kScopeCount = 3;
        const int kCurrentScopeIndex = static_cast<int>(searchScope_);
        const int kNormalizedDirection = direction < 0 ? -1 : 1;
        const int kNextScopeIndex =
            (kCurrentScopeIndex + kNormalizedDirection + kScopeCount) % kScopeCount;
        if (static_cast<UiSearchScope>(kNextScopeIndex) == UiSearchScope::kCurrentTable)
        {
            // When switching back from another scope to the 'current table', re-adopt the most recently interacted table.
            targetTableView_.clear();
            targetTableView_ = resolveCurrentTable();
        }
        setSearchScope(static_cast<UiSearchScope>(kNextScopeIndex));
    }

    void GlobalUiSearchController::clearSearchResultFilters()
    {
        for (const QPointer<QTableView>& tableView : filteredTableViewList_)
        {
            if (!tableView.isNull())
            {
                ks::ui::clearTableSearchResultFilter(tableView.data());
            }
        }
        filteredTableViewList_.clear();
    }

    void GlobalUiSearchController::applySearchResultFilterToTable(
        QTableView* tableView)
    {
        if (!searchResultsOnly_
            || tableView == nullptr
            || activeQueryText_.trimmed().isEmpty()
            || !ks::ui::isGenericTableSearchEligible(tableView))
        {
            return;
        }

        if (!ks::ui::applyTableSearchResultFilter(
                tableView,
                activeQueryText_))
        {
            return;
        }

        const QPointer<QTableView> kGuardedTable(tableView);
        if (!filteredTableViewList_.contains(kGuardedTable))
        {
            filteredTableViewList_.push_back(kGuardedTable);
        }
    }

    void GlobalUiSearchController::applySearchResultFiltersToDock(
        ads::CDockWidget* dockWidget,
        const bool visiblePageOnly)
    {
        if (!searchResultsOnly_
            || dockWidget == nullptr
            || dockWidget->widget() == nullptr)
        {
            return;
        }

        QWidget* contentWidget = dockWidget->widget();
        QList<QTableView*> tableViewList = contentWidget->findChildren<QTableView*>();
        if (QTableView* rootTableView = qobject_cast<QTableView*>(contentWidget))
        {
            tableViewList.prepend(rootTableView);
        }
        for (QTableView* tableView : tableViewList)
        {
            if (tableView == nullptr
                || (visiblePageOnly && !tableView->isVisibleTo(contentWidget)))
            {
                continue;
            }
            applySearchResultFilterToTable(tableView);
        }
    }

    ads::CDockWidget* GlobalUiSearchController::resolveCurrentPageDock() const
    {
        if (!recentPageDockWidget_.isNull()
            && recentPageDockWidget_->isVisible()
            && recentPageDockWidget_->isCurrentTab())
        {
            return recentPageDockWidget_.data();
        }
        if (!targetTableView_.isNull())
        {
            if (ads::CDockWidget* dockWidget = dockWidgetForWidget(targetTableView_.data()))
            {
                return dockWidget;
            }
        }
        if (QApplication::focusWidget() != nullptr)
        {
            if (ads::CDockWidget* dockWidget = dockWidgetForWidget(QApplication::focusWidget()))
            {
                return dockWidget;
            }
        }
        if (dockListProvider_)
        {
            const QList<ads::CDockWidget*> kDockList = dockListProvider_();
            for (ads::CDockWidget* dockWidget : kDockList)
            {
                if (dockWidget != nullptr && dockWidget->isVisible() && dockWidget->isCurrentTab())
                {
                    return dockWidget;
                }
            }
        }
        return nullptr;
    }

    QTableView* GlobalUiSearchController::resolveCurrentTable() const
    {
        if (!targetTableView_.isNull())
        {
            return targetTableView_.data();
        }
        if (!recentTableView_.isNull())
        {
            return recentTableView_.data();
        }
        if (QApplication::focusWidget() != nullptr)
        {
            if (QTableView* tableView = tableViewForWidget(QApplication::focusWidget()))
            {
                return tableView;
            }
        }

        ads::CDockWidget* dockWidget = resolveCurrentPageDock();
        if (dockWidget != nullptr && dockWidget->widget() != nullptr)
        {
            const QList<QTableView*> kTableViewList = dockWidget->widget()->findChildren<QTableView*>();
            for (QTableView* tableView : kTableViewList)
            {
                if (tableView != nullptr && tableView->isVisibleTo(dockWidget->widget()))
                {
                    return tableView;
                }
            }
        }
        return nullptr;
    }

    void GlobalUiSearchController::refreshSearchScopeDisplayText()
    {
        refreshSearchOptionControls();
        emit searchScopeDisplayTextChanged(searchScopeDisplayText());
    }

    bool GlobalUiSearchController::isQueryLongEnough(const QString& queryText)
    {
        if (queryText.isEmpty())
        {
            return false;
        }
        if (queryText.size() >= 2)
        {
            return true;
        }
        // Single-character queries only allow CJK monospaced characters (starting from U+2E80); single ASCII characters generate excessive noise.
        return queryText.at(0).unicode() >= 0x2E80;
    }

    bool GlobalUiSearchController::isCurrentQueryLongEnough(const QString& queryText) const
    {
        if (searchScope_ == UiSearchScope::kCurrentTable)
        {
            return !queryText.trimmed().isEmpty();
        }
        return isQueryLongEnough(queryText);
    }

    void activateGlobalUiSearchForTable(
        QTableView* tableView,
        const QString& queryText,
        const bool focusTopInput)
    {
        if (!gActiveSearchController.isNull())
        {
            gActiveSearchController->activateForTable(
                tableView,
                queryText,
                focusTopInput);
        }
    }
}
