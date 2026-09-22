#pragma once

#include <QString>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <vector>

class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class QTextBrowser;
class QToolButton;
class QTreeWidget;

// KernelKnowledgeTab:
// - Organize the 71 topics from 'The Second Plan' into a read-only knowledge center that is searchable and filterable;
// - Each main article provides a relationship diagram and eight completion fields via the language pack.
// - Optionally direct the user to an existing read-only observation page within the current KernelDock.
class KernelKnowledgeTab final : public QWidget
{
public:
    // RouteHandler accepts a stable routeId; KernelDock decides how to switch the actual tab.
    using RouteHandler = std::function<void(const QString& routeId)>;

    explicit KernelKnowledgeTab(QWidget* parent = nullptr);
    ~KernelKnowledgeTab() override = default;

    // setRouteHandler: Set the internal observation entry callback.
    // Input handler; no return value. An empty callback automatically disables the 'Open Related Features' button.
    void setRouteHandler(RouteHandler handler);

protected:
    // changeEvent: Respond to language pack and application palette changes.
    // Input: Qt change event. No return value; always continue to the QWidget base class for processing.
    void changeEvent(QEvent* event) override;

private:
    // initializeUi: Constructs the directory, toolbar, article reader, and all connections.
    // No input or return value; called exactly once in the constructor.
    void initializeUi();

    // retranslateUi: Reload all control texts while preserving the current topic and overlay filters.
    // No input, no return; called during language switching.
    void retranslateUi();

    // applyTheme: Applies theme colors excluding layout geometry and refreshes rich text CSS.
    // No input, no return; called during construction and theme changes.
    void applyTheme();

    // rebuildTree: Rebuilds the left directory based on the current keyword and coverage.
    // preferredTopicId: The topic to retain after rebuilding; no return value.
    void rebuildTree(const QString& preferredTopicId = QString());

    // showTopic: Renders the topic corresponding to the directory index on the right.
    // Input: full directory index; returns nothing, displays empty state on invalid index.
    void showTopic(int topicIndex);

    // selectTopic: Selects the specified directory index in the tree and scrolls it into the visible area.
    // Input is a full directory index; returns true on match, otherwise false.
    bool selectTopic(int topicIndex);

    // findTopicIndex: Locates the full catalog index by stable topic ID.
    // Input ID; returns a non-negative index if found, otherwise -1.
    int findTopicIndex(const QString& topicId) const;

    // navigateRelative: Moves forward or backward within the currently filtered topic list.
    // delta is -1 or +1; no return value, stays at current item when boundary is reached.
    void navigateRelative(int delta);

    // copyCurrentTopic: Copies the current title, summary, body, and official reference link.
    // No input or return value; silently skip if there is no current item.
    void copyCurrentTopic() const;

    // openCurrentRoute: Invoke the read-only internal navigation callback provided by KernelDock.
    // No input or return value; silently skip if the current topic has no routeId.
    void openCurrentRoute() const;

    // openCurrentReference: Opens the official Microsoft reference for the current category using the system browser.
    // No input, no return; silently skip when no valid URL is present.
    void openCurrentReference() const;

    // collectCurrentEvidence: Asynchronously calls the versioned R0 topic protocol and displays raw evidence lines.
    // No input, no return; the dialog is read-only and will not automatically trigger business scans.
    void collectCurrentEvidence();

    QLineEdit* searchEdit_ = nullptr;             // m_searchEdit: Search across titles, summaries, and body text.
    QComboBox* coverageCombo_ = nullptr;          // m_coverageCombo: Filter by underlying capability coverage.
    QLabel* resultCountLabel_ = nullptr;          // m_resultCountLabel: Current filtered match count.
    QTreeWidget* topicTree_ = nullptr;            // m_topicTree: Two-level directory for categories and topics.
    QLabel* titleLabel_ = nullptr;                // m_titleLabel: Current topic title.
    QLabel* summaryLabel_ = nullptr;              // m_summaryLabel: One-sentence summary of the current topic.
    QLabel* coverageBadge_ = nullptr;             // m_coverageBadge: Label for underlying capability coverage.
    QLabel* knowledgeBadge_ = nullptr;            // m_knowledgeBadge: Badge indicating knowledge article integrity.
    QToolButton* previousButton_ = nullptr;        // m_previousButton: Previous page icon button.
    QToolButton* nextButton_ = nullptr;            // m_nextButton: Next article icon button.
    QToolButton* copyButton_ = nullptr;            // m_copyButton: Copy full article icon button.
    QToolButton* evidenceButton_ = nullptr;        // m_evidenceButton: Collect R0 context evidence for the current topic.
    QToolButton* routeButton_ = nullptr;           // m_routeButton: Button to open the Ksword observation page.
    QToolButton* referenceButton_ = nullptr;       // m_referenceButton: Opens Microsoft official reference.
    QTextBrowser* articleView_ = nullptr;          // m_articleView: a read-only rich text view suitable for Markdown headings, relationship diagrams, and links.

    std::vector<int> visibleTopicIndexes_;         // m_visibleTopicIndexes: Full directory indexes navigable after current filtering.
    int currentTopicIndex_ = -1;                   // m_currentTopicIndex: Index of the current article in the complete table of contents.
    QString currentRouteId_;                       // m_currentRouteId: The optional internal observation route for the current article.
    QString currentReferenceUrl_;                  // m_currentReferenceUrl: Official documentation URL for the current category.
    RouteHandler routeHandler_;                    // m_routeHandler: Security navigation function injected by the parent KernelDock.
    std::uint64_t evidenceGeneration_ = 0;         // m_evidenceGeneration: Expired asynchronous results returned after switching topics.
};
