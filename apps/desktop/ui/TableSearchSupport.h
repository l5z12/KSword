#pragma once

// ============================================================
// TableSearchSupport.h
// Purpose:
// 1) Automatically install table search entry points for all QTableView/QTableWidget instances;
// 2) Displayed only when content exceeds one screen and the page has no dedicated search box;
// 3) Show only the search button; clicking it activates the title bar search box; hide when space is insufficient;
// 4) Supports 'Show Search Results Only' and precisely restores the row hidden state prior to enabling.
// 5) Provides table name resolution, model matching, and result localization for reuse by the top search.
// ============================================================

#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVector>

class QTableView;

namespace ks::ui
{
    // TableCellSearchMatch: stores a table cell search hit and its stable model index.
    struct TableCellSearchMatch
    {
        QPointer<QTableView> tableView;       // tableView: The table that was hit.
        QPersistentModelIndex modelIndex;     // modelIndex: The matched cell index; automatically invalidated after model reset.
        QString matchedText;                  // matchedText: Cell display text.
        QString locationText;                 // locationText: Location description composed of table name, row number, and column name.
        int matchRank = 2;                    // matchRank: 0=exact match, 1=prefix, 2=contains.
    };

    // installTableSearchSupport: Installs a search button entry for the table once; safe to call repeatedly.
    void installTableSearchSupport(QTableView* tableView);

    // refreshTableSearchSupport: Re-evaluates scroll state, dedicated search box, and available space.
    void refreshTableSearchSupport(QTableView* tableView);

    // isGenericTableSearchEligible: Only allows tables without lingering external search boxes to use generic filtering.
    bool isGenericTableSearchEligible(QTableView* tableView);

    // applyTableSearchResultFilter: Hides non-matching rows and preserves the original row hidden snapshot; returns true on success.
    bool applyTableSearchResultFilter(
        QTableView* tableView,
        const QString& queryText);

    // clearTableSearchResultFilter: Revert the general filter and restore the row visibility state prior to enabling.
    void clearTableSearchResultFilter(QTableView* tableView);


    // resolveTableSearchDisplayName: Parse the table name from explicit properties, group headers, tabs, and object names.
    QString resolveTableSearchDisplayName(const QTableView* tableView);

    // collectTableCellSearchMatches: Searches for display text in the table model, returning up to maxHitCount matches.
    QVector<TableCellSearchMatch> collectTableCellSearchMatches(
        QTableView* tableView,
        const QString& queryText,
        int maxHitCount);

    // revealTableCellSearchMatch: Scroll to, select, and focus the matching table cell.
    void revealTableCellSearchMatch(const TableCellSearchMatch& searchMatch);
}
