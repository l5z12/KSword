#pragma once

// ============================================================
// GlobalUiSearch.h
// Purpose:
// 1) Provides global page text search for the title bar 'Search' mode:
//    Traverse the control trees of all main function docks, collect visible text from labels, buttons,
//    group boxes, tabs, headers, placeholders, and dropdown items, and perform keyword matching;
// 2) Display the result panel below the title bar input box, showing each result
//    with the matched text and a page path in the format "Dock › Internal Tab › Group";
// 3) Upon activating a result, automatically initialize and bring the target Dock to the front, switch internal
//    Tabs/Stacked pages layer by layer, scroll to the target control, and pulse-highlight it with the theme's accent color;
// 4) Components do not directly depend on mainWindow: Dock lists, lazy-load initialization, and
//    Dock activation are all injected via callbacks to facilitate reuse and unit verification.
// ============================================================

#include <QObject>
#include <QList>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVector>

#include <functional>

class QCheckBox;
class QEvent;
class QFrame;
class QLabel;
class QLineEdit;
class QListWidget;
class QProgressBar;
class QTabBar;
class QTableView;
class QTimer;
class QWidget;

namespace ads
{
    class CDockWidget;
}

namespace ks::ui
{
    // UiSearchScope: The three search scopes in the title bar, cycled via Tab/Shift+Tab.
    enum class UiSearchScope
    {
        kGlobal,
        kCurrentPage,
        kCurrentTable
    };

    // ============================================================
    // UiSearchHit
    // Notes:
    // - Describe a page text search hit.
    // - Both the dock and the target control are held by QPointer; check for null before activation to prevent dangling pointers.
    // ============================================================
    struct UiSearchHit
    {
        QPointer<ads::CDockWidget> pageDockWidget; // pageDockWidget: The main functional Dock containing the matched text.
        QPointer<QWidget> targetWidget;            // targetWidget: The specific control containing the matched text (the page corresponding to the tab if the tab itself is matched).
        QPointer<QTableView> targetTableView;      // targetTableView: The table containing the matched cell; empty for standard UI matches.
        QPersistentModelIndex targetModelIndex;    // targetModelIndex: Stable model index for the table cell hit.
        QString matchedText;                       // matchedText: Full original text of the matched control (after single-line processing).
        QString pagePathText;                      // pagePathText: Page path text in the format 'Kernel › Callback Audit'.
        int matchRank = 2;                         // matchRank: Sorting weight (0 = exact match, 1 = prefix, 2 = contains).
    };

    // ============================================================
    // GlobalUiSearchController
    // Notes:
    // - Global controller for title bar search mode: debounced search, result
    //   pop-up, keyboard navigation, result activation jump, and target highlighting;
    // - The popup is implemented as a child control of the host main window (not an independent top-level window)
    //   to prevent focus/activation state from being hijacked by the popup under borderless window conditions.
    // ============================================================
    class GlobalUiSearchController final : public QObject
    {
        Q_OBJECT

    public:
        // DockListProvider: Returns the list of Docks participating in the search (in display order).
        using DockListProvider = std::function<QList<ads::CDockWidget*>()>;
        // DockPreparer: Ensures lazy-loaded Dock content is initialized (re-entrant safe).
        using DockPreparer = std::function<void(ads::CDockWidget*)>;
        // DockActivator: brings the Dock to the front and sets it as the active tab (including restoration from closed state).
        using DockActivator = std::function<void(ads::CDockWidget*)>;

        // Constructor:
        // - Purpose: Create the search controller and install input box/application-level event filters.
        // - Note: Created after the mainWindow initializes the title bar.
        // - Input popupHostWindow: parent window of the result popup (main window).
        // - Input searchInputEdit: input box in the center of the title bar.
        // - Input popupAnchorWidget: anchor control for horizontal alignment of the popup layer (input group container);
        // - Input parentObject: Qt parent object.
        GlobalUiSearchController(
            QWidget* popupHostWindow,
            QLineEdit* searchInputEdit,
            QWidget* popupAnchorWidget,
            QObject* parentObject = nullptr);

        // Destructor: Revoke active generic table row filters.
        ~GlobalUiSearchController() override;

        // setDockListProvider：
        // - Purpose: Inject Dock list callbacks for search participation.
        // - Invocation: Called once when wiring the mainWindow.
        void setDockListProvider(DockListProvider dockListProvider);

        // setDockPreparer：
        // - Purpose: Inject Dock lazy-load initialization callbacks (invoked one by one before search).
        // - Invocation: Called once when wiring the mainWindow.
        void setDockPreparer(DockPreparer dockPreparer);

        // setDockActivator：
        // - Purpose: Injects the Dock bring-to-front activation callback (invoked when activating results).
        // - Invocation: Called once when wiring the mainWindow.
        void setDockActivator(DockActivator dockActivator);

        // activateForTable：
        // - Purpose: Switch search scope from the table's search box/button to the 'current table' and sync the top input box.
        // - When focusTopInput=true, move keyboard focus to the top; when false, retain focus within the table input.
        void activateForTable(
            QTableView* tableView,
            const QString& queryText,
            bool focusTopInput);

        // searchScopeDisplayText: Returns the scope text currently displayed in the title bar.
        QString searchScopeDisplayText() const;

    signals:
        // requestSearchInputActivation: Request switching the title bar back to search mode; optionally request focus.
        void requestSearchInputActivation(bool focusTopInput);

        // searchScopeDisplayTextChanged: Refresh the title bar mode tag and hint after the scope changes.
        void searchScopeDisplayTextChanged(const QString& displayText);


    public slots:
        // handleQueryEdited：
        // - Purpose: Receive title bar search text changes and trigger debounced search;
        // - Triggered by: CustomTitleBar::searchTextEdited;
        // - Input queryText: current input box text (untrimmed).
        void handleQueryEdited(const QString& queryText);

        // setSearchInputActive：
        // - Purpose: Synchronize whether the title bar is currently in 'Search' input mode;
        // - Triggered by: CustomTitleBar::inputModeChanged;
        // - Immediately dismiss the results popup when searchModeActive is false.
        void setSearchInputActive(bool searchModeActive);

        // setSearchResultsOnly: Toggle the result-only filter for the universal table.
        void setSearchResultsOnly(bool checked);

        // dismissPopup：
        // - Purpose: Dismiss the result popup and stop pending debounced search.
        void dismissPopup();

    protected:
        // eventFilter：
        // - Purpose:
        //   1) Input box: Up/Down to select results, Enter to activate, Esc
        //      to collapse, and re-display results on demand when focused;
        //   2) Host window: Re-align popup on size/position changes; hide when inactive;
        //   3) Application level: Collapse when clicking outside the popup layer or input group.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // ensurePopupCreated：
        // - Purpose: Construct search options, result list, and empty-state prompt on first demand.
        void ensurePopupCreated();

        // refreshSearchOptionControls: Synchronize the range dropdown in the popup with the result display state.
        void refreshSearchOptionControls();

        // showOptionsOnlyPopup: Display operable search scopes and result-specific controls even when the query is empty.
        void showOptionsOnlyPopup();

        // runSearchNow：
        // - Purpose: Start an asynchronous chunked search (triggered by debounce timer expiry or explicit call);
        // - Note: A query that is too short is equivalent to collapsing the popup; every new start invalidates
        //   in-flight scans, and if the same query is already being scanned, the current scan is reused directly.
        void runSearchNow();

        // processNextSearchChunk：
        // - Purpose: Process a search chunk (initialize and scan one Dock), then
        //   yield the event loop via singleShot(0) before scheduling the next chunk.
        // - Input searchGeneration: the generation number of the current search. If it does not match the
        //   current generation, the scan has been replaced or cancelled by a new search; discard immediately.
        void processNextSearchChunk(quint64 searchGeneration);

        // finishAsyncSearch：
        // - Purpose: Finalize after all shards complete (or hit the result cap): sort hits, hide the
        //   progress row, populate the result list, and resize the popup based on result dimensions.
        void finishAsyncSearch();

        // updateSearchProgressUi：
        // - Purpose: Refresh the progress row text to 'Searching: Dock Name (n/N)'.
        // - Input dockTitleText: the title of the Dock currently being scanned.
        void updateSearchProgressUi(const QString& dockTitleText);

        // rebuildResultList：
        // - Purpose: Rebuild the popup list items based on the hit list (including rich text highlighting and path lines).
        void rebuildResultList();

        // showPopupPanel：
        // - Purpose: Apply the current theme style, calculate dimensions, and show or bring the popup to the front.
        void showPopupPanel();

        // repositionPopupPanel：
        // - Purpose: Horizontally center the popup panel below the anchor point and clip it within the host window bounds.
        void repositionPopupPanel();

        // activateHitAtRow：
        // - Purpose: Activate the search hit corresponding to a specific row in the list.
        // - Input rowIndex: list row index; ignored if out of bounds.
        void activateHitAtRow(int rowIndex);

        // moveSelection：
        // - Purpose: Move the current row in the results list using keyboard up/down keys (with boundary clamping).
        // - Input rowDelta: +1 for down, -1 for up.
        void moveSelection(int rowDelta);

        // isQueryLongEnough：
        // - Purpose: Determine if the query meets the minimum search length.
        // - Rule: ≥2 characters, or a single CJK monospace character (starting from U+2E80).
        static bool isQueryLongEnough(const QString& queryText);

        // isCurrentQueryLongEnough: The current table allows any single character; other ranges follow global noise-reduction rules.
        bool isCurrentQueryLongEnough(const QString& queryText) const;

        // setSearchScope/cycleSearchScope: Sets or cycles the search scope and restarts the current query.
        void setSearchScope(UiSearchScope searchScope);
        void cycleSearchScope(int direction);

        // resolveCurrentPageDock/resolveCurrentTable: Resolve the current page and table from the most recent interaction context.
        ads::CDockWidget* resolveCurrentPageDock() const;
        QTableView* resolveCurrentTable() const;

        // refreshSearchScopeDisplayText: generates 'Global/Current Page/Current Table (Name)' and notifies the title bar.
        void refreshSearchScopeDisplayText();

        // clear/applySearchResultFilters: revoke or apply generic table row filters based on the current scope.
        void clearSearchResultFilters();
        void applySearchResultFilterToTable(QTableView* tableView);
        void applySearchResultFiltersToDock(
            ads::CDockWidget* dockWidget,
            bool visiblePageOnly);

    private:
        QPointer<QWidget> popupHostWindow_;      // m_popupHostWindow: Popup parent window (main window).
        QPointer<QLineEdit> searchInputEdit_;    // m_searchInputEdit: Title bar middle input field.
        QPointer<QWidget> popupAnchorWidget_;    // m_popupAnchorWidget: Popup alignment anchor (input group container).

        DockListProvider dockListProvider_;      // m_dockListProvider: Dock list callback.
        DockPreparer dockPreparer_;              // m_dockPreparer: Dock lazy-load initialization callback.
        DockActivator dockActivator_;            // m_dockActivator: Dock bring-to-front activation callback.

        QFrame* popupPanel_ = nullptr;           // m_popupPanel: Container for the result popup panel (child control of the host window).
        QWidget* searchOptionsRow_ = nullptr;    // m_searchOptionsRow: Row for explicit options specific to the search scope and results.
        QLabel* searchScopeLabel_ = nullptr;     // m_searchScopeLabel: Search scope label.
        QTabBar* searchScopeTabs_ = nullptr;     // m_searchScopeTabs: Horizontal switching between Global/Current Page/Current Table.
        QCheckBox* searchResultsOnlyCheck_ = nullptr; // m_searchResultsOnlyCheck: Show only matching rows.
        QListWidget* resultListWidget_ = nullptr;// m_resultListWidget: Result list.
        QLabel* emptyHintLabel_ = nullptr;       // m_emptyHintLabel: Empty state hint when no results are found.
        QWidget* searchProgressRow_ = nullptr;   // m_searchProgressRow: Container for the progress row during an in-progress scan.
        QLabel* searchProgressLabel_ = nullptr;  // m_searchProgressLabel: Progress text 'Searching: Dock name (n/N)'.
        QProgressBar* searchProgressBar_ = nullptr; // m_searchProgressBar: Progress bar advancing by Dock count.
        QTimer* searchDebounceTimer_ = nullptr;  // m_searchDebounceTimer: Input debounce timer.

        QString pendingQueryText_;               // m_pendingQueryText: Most recently entered query text.
        QString activeQueryText_;                // m_activeQueryText: Query snapshot used for the current asynchronous scan.
        QVector<UiSearchHit> currentHitList_;    // m_currentHitList: Current hit list (corresponds one-to-one with list rows after completion).
        QList<QPointer<ads::CDockWidget>> pendingSearchDockList_; // m_pendingSearchDockList: Snapshot queue of docks from the current scan.
        int nextSearchDockIndex_ = 0;            // m_nextSearchDockIndex: Queue index for the next Dock to be scanned.
        quint64 searchGeneration_ = 0;           // m_searchGeneration: Search generation; increments on new search/cancellation to invalidate in-flight fragments.
        bool searchInProgress_ = false;          // m_searchInProgress: Whether an asynchronous scan is currently in progress.
        bool searchModeActive_ = true;           // m_searchModeActive: Whether the title bar is in search input mode.
        bool showPopupOnNextSearchInputFocus_ = false; // m_showPopupOnNextSearchInputFocus: Only allows the popup to expand when the top input box gains focus on the next search input for table search entries.
        bool searchResultsOnly_ = false;         // m_searchResultsOnly: Whether to hide non-matching rows in the general table.
        UiSearchScope searchScope_ = UiSearchScope::kGlobal; // m_searchScope: The search scope currently selected by the user.
        UiSearchScope activeSearchScope_ = UiSearchScope::kGlobal; // m_activeSearchScope: Snapshot of the scope used for in-flight searches.
        QPointer<QTableView> targetTableView_;     // m_targetTableView: The target table explicitly specified as the table entry.
        QPointer<QTableView> recentTableView_;     // m_recentTableView: Table with the most recent mouse/keyboard interaction.
        QPointer<ads::CDockWidget> recentPageDockWidget_; // m_recentPageDockWidget: Dock widget containing the most recently interacted control.
        QPointer<QTableView> pendingDirectTableView_; // m_pendingDirectTableView: Objects pending scan within the current table range.
        QList<QPointer<QTableView>> filteredTableViewList_; // m_filteredTableViewList: Tables currently filtered by the global search.
    };

    // activateGlobalUiSearchForTable: Generic entry point for table search, invoking the current main window's search controller.
    void activateGlobalUiSearchForTable(
        QTableView* tableView,
        const QString& queryText = QString(),
        bool focusTopInput = true);
}
