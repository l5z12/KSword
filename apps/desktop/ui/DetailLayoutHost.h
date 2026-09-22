#pragma once

// ============================================================
// DetailLayoutHost.h
// Purpose:
// - Unify the 'Data View + CodeEditorWidget' for strictly matched pages to support four detail layout types.
// - The page is still responsible for generating detail text; this class only handles layout, expansion state, and text mirroring.
// - Use QPersistentModelIndex to track source items; inline detail modifications only affect view geometry, not the business model.
// ============================================================

#include "../settings_dock/AppearanceSettings.h"

#include <QList>
#include <QObject>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVariant>
#include <QtGlobal>

class CodeEditorWidget;
class QAbstractItemView;
class QAbstractItemDelegate;
class QDialog;
class QEvent;
class QPlainTextEdit;
class QSplitter;
class QToolButton;
class QTreeWidgetItem;
class QWidget;

namespace ks::ui
{
    class EmbeddedRowDelegate;

    // DetailLayoutHost: Detail layout controller for a single page.
    // Invocation: Register with DetailLayoutRegistry after the page finishes creating the table and CodeEditorWidget.
    class DetailLayoutHost final : public QObject
    {
    public:
        // Constructor: record the view, detail editor, and page host, then immediately establish a unified splitter.
        // Input parameters: tableView, detailEditor, ownerWidget — data view, original detail widget, and page host.
        DetailLayoutHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget);
        ~DetailLayoutHost() override;

        // setTableView / setDetailEditor: Allow registry or page to rebind controls after deferred creation.
        // Input is the target control; no business return value.
        void setTableView(QAbstractItemView* tableView);
        void setDetailEditor(CodeEditorWidget* detailEditor);

        // applyScheme: Switches the current page layout; clears temporary inline views/window states from the old mode.
        void applyScheme(ks::settings::DetailDisplayScheme scheme);

        // clearEmbeddedDetails: Remove all inline details and restore source line icons.
        void clearEmbeddedDetails();

        // prepareDataRebuild: Called before rebuilding table data on the page; currently equivalent to clearing inline details.
        void prepareDataRebuild();

        // detailEditor: Returns the original CodeEditorWidget of the current page for registry deduplication.
        CodeEditorWidget* detailEditor() const;

    protected:
        // eventFilter: Listen for independent window activation state and switch opacity to 100% or 30% as required.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // EmbeddedEntry: Maintains a stable mapping between a source row and its inline detail control.
        struct EmbeddedEntry
        {
            QPersistentModelIndex sourceIndex;
            QPointer<QPlainTextEdit> textEditor;
            QTreeWidgetItem* treeSourceItem = nullptr;
            int originalRowHeight = -1;
            int detailHeight = 128;
            QVariant originalSizeHint;
        };

        // initializeHostUi / scheduleHostUiInitialization / initializeConnections：
        // Defer creation of the unified separator and arrow, and binding of text/click events, until after the page is constructed.
        void initializeHostUi();
        void scheduleHostUiInitialization();
        void initializeConnections();

        // ensureManagedSplitter: Reuses an existing splitter or wraps the table/detail in the direct layout into a new splitter.
        void ensureManagedSplitter();

        // updateBottomExpanded: Updates the visibility of the bottom details, arrow direction, and default splitter ratio.
        void updateBottomExpanded(bool expanded);
        void setManagedSplitterSizes(int tableSize, int toggleSize, int detailSize);

        // handleViewClicked: Handle a single user row click according to the current scheme.
        void handleViewClicked(const QPersistentModelIndex& sourceIndex);

        // handleDetailChanged: synchronizes original detail text to the current inline view or independent window.
        void handleDetailChanged(const QString& detailText);

        // toggleEmbeddedDetail: display or remove the read-only QPlainTextEdit detail view for the current source row.
        void toggleEmbeddedDetail(const QPersistentModelIndex& sourceIndex);

        // insertTableEmbeddedDetail / insertTreeEmbeddedDetail：
        // Only expand the view height of the source row and cover the read-only text box; do not insert any rows or nodes into the business model.
        void insertTableEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);
        void insertTreeEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);

        // installEmbeddedRowDelegate / restoreEmbeddedRowDelegate：
        // Install the drawing wrapper only when expanded rows exist, and restore the page's original delegate when the last row is collapsed.
        void installEmbeddedRowDelegate();
        void restoreEmbeddedRowDelegate();

        // embeddedOriginalRowHeight: Returns the row height before expansion for the currently drawn index; returns -1 for non-expanded rows.
        int embeddedOriginalRowHeight(const QModelIndex& modelIndex) const;

        // removeEmbeddedEntry: Removes the inline detail for the specified source row. Returns true if found and removed.
        bool removeEmbeddedEntry(const QPersistentModelIndex& sourceIndex);

        // Inline detail layouts and indicators are maintained at the view layer; batch nodes are processed in slices via the event loop.
        void updateEmbeddedEditorGeometries();
        void restoreEmbeddedEntryLayout(const EmbeddedEntry& entry);
        void refreshEmbeddedIndicators();
        void scheduleEmbeddedIndicatorRefresh();
        void queueEmbeddedIndicatorRows(const QModelIndex& parentIndex, int firstRow, int lastRow);
        void processEmbeddedIndicatorBatch(quint64 generation);
        void restoreEmbeddedIndicators();
        void setSourceExpandedIndicator(const QPersistentModelIndex& sourceIndex, bool expanded);
        void installEmbeddedIndicator(const QPersistentModelIndex& sourceIndex, bool expanded);

        // showFloatingWindow / destroyFloatingWindow: Manages the single non-modal detail window for the current page.
        void showFloatingWindow();
        void destroyFloatingWindow();

        QPointer<QAbstractItemView> tableView_;       // m_tableView: Original page table or tree.
        QPointer<CodeEditorWidget> detailEditor_;     // m_detailEditor: Original page detail editor.
        QPointer<QWidget> ownerWidget_;               // m_ownerWidget: Lifecycle host.
        QPointer<QSplitter> splitter_;                // m_splitter: Unified container for the table and original detail area.
        QPointer<QWidget> tablePane_;                 // m_tablePane: Full panel hosting the business table within the splitter.
        QPointer<QWidget> detailPane_;                // m_detailPane: Full detail pane within the splitter.
        QPointer<QWidget> toggleBar_;                  // m_toggleBar: Arrow container bar spanning the full page width to prevent fixed-width buttons from narrowing the separator.
        QPointer<QToolButton> toggleButton_;           // m_toggleButton: Arrow button for the collapsed scheme below.
        QPointer<QDialog> floatingWindow_;             // m_floatingWindow: The unique detail window for the current page.
        QPointer<CodeEditorWidget> floatingEditor_;    // m_floatingEditor: Read-only mirror editor in a standalone window.
        QPointer<QAbstractItemDelegate> embeddedSourceDelegate_; // m_embeddedSourceDelegate: The delegate currently in use on the page before inline unwind.
        QPointer<EmbeddedRowDelegate> embeddedRowDelegate_; // m_embeddedRowDelegate: Wrapper delegate restricting the source cell's drawing area for expanded rows.
        QList<EmbeddedEntry> embeddedEntries_;         // m_embeddedEntries: Currently expanded multi-line details.
        ks::settings::DetailDisplayScheme scheme_ =
            ks::settings::DetailDisplayScheme::kBottomCollapsed;
        bool bottomExpanded_ = false;                  // m_bottomExpanded: whether the bottom details are expanded.
        bool hostUiInitializationScheduled_ = false;   // m_hostUiInitializationScheduled: Indicates whether deferred initialization after page construction has been queued.
        bool indicatorBatchScheduled_ = false;         // m_indicatorBatchScheduled: Whether node icon batch tasks are queued.
        bool indicatorRefreshScheduled_ = false;       // m_indicatorRefreshScheduled: Whether icon refresh has been merged after batch data updates.
        quint64 indicatorGeneration_ = 0;              // m_indicatorGeneration: Generation counter to skip expired icon traversal.
        QList<QPersistentModelIndex> indicatorIndexes_; // m_indicatorIndexes: Source items for original icons that have been saved.
        QList<QPersistentModelIndex> pendingIndicatorIndexes_; // m_pendingIndicatorIndexes: Source items pending sharding.
    };
}
