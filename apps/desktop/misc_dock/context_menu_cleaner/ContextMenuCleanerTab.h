#pragma once

// ============================================================
// ContextMenuCleanerTab.h
// Purpose:
// 1) Provide the 'Shell Association Management' miscellaneous page.
// 2) Display context menus, URL bindings, file open associations, and Explorer third-party namespaces.
// 3) Supports refreshing, filtering, copying registry paths, and deleting selected registry items after user confirmation.
// ============================================================

#include "../../Framework.h"

#include <QVector>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;

namespace ks::misc
{
    // ContextMenuCleanerTab：
    // - Input: parent passed from Qt parent control; reads current system registry at runtime
    // - Processing: enumerate Shell menus, file associations, and Explorer namespaces to populate seven sub-page tables.
    // - Output: This control returns no value; cleanup results are reported via registry deletion, UI refresh, and log feedback.
    class ContextMenuCleanerTab final : public QWidget
    {
    public:
        // Constructor:
        // - Parameter parent: Qt parent widget, may be null.
        // - Processing logic: Create seven sub-tabs and immediately perform a registry enumeration.
        // - Return value: None.
        explicit ContextMenuCleanerTab(QWidget* parent = nullptr);
        ~ContextMenuCleanerTab() override = default;

    private:
        // MenuArea: Identifies the current context menu area being operated on.
        enum class MenuArea
        {
            kInternetExplorer, // IE context menu: Internet Explorer MenuExt.
            kDesktop,          // Desktop right-click context menu: DesktopBackground/Directory Background.
            kFile,             // File context menu: *, AllFilesystemObjects, Directory/Folder/Drive.
            kUrlBinding,       // URL binding: protocol registration and default protocol binding for the current user.
            kOpenWith,         // Open With: Candidate applications and ProgID corresponding to the file extension.
            kFormatMenu,       // Format context menu: file extensions, ProgID, and SystemFileAssociations.
            kExplorerHome      // Explorer Home: Third-party or user-registered Shell namespaces.
        };

        // DeleteKind: Identifies whether to delete the entire registry subtree or a single registry value.
        enum class DeleteKind
        {
            kRegistryTree, // RegistryTree: Deletes the complete subtree pointed to by subKeyPath.
            kRegistryValue // RegistryValue: Deletes only the value pointed to by valueName under subKeyPath.
        };

        // ContextMenuEntry: Snapshot of a single right-click menu registry entry.
        struct ContextMenuEntry
        {
            MenuArea area = MenuArea::kFile;       // area: Sub-page identifier.
            HKEY rootKey = nullptr;               // rootKey: Actual registry root key, reused during deletion.
            QString rootLabel;                    // rootLabel: Root key for display, e.g., HKCU/HKLM (64-bit).
            QString subKeyPath;                   // subKeyPath: The full subkey path to be deleted.
            REGSAM viewFlag = 0;                  // viewFlag: WOW64 view flag, ensuring enumeration/deletion of the same view.
            QString sourceGroup;                  // sourceGroup: Source category, e.g., "File *" or "Desktop Background".
            QString entryKind;                    // entryKind：shell/shellex/IE MenuExt。
            QString itemName;                     // itemName: Registry subkey name.
            QString displayName;                  // displayName: Menu display name; falls back to sub-key name if missing.
            QString commandOrHandler;             // commandOrHandler: Command, script path, CLSID, or COM Server.
            QString clsidText;                    // clsidText: COM context menu handler CLSID.
            QString detailText;                   // detailText: Supplementary information such as status markers, icons, and AppliesTo.
            QString statusText;                   // statusText: Status for enabling/disabling/expanding menus.
            DeleteKind deleteKind = DeleteKind::kRegistryTree; // deleteKind: Precise deletion granularity for the current row.
            QString valueName;                    // valueName: The name of the registry value to delete.
            bool cleanupOpenWithMru = false;      // cleanupOpenWithMru: Synchronize MRUList after deleting history open-with entries.
            bool canDelete = false;               // canDelete: whether the current row allows deletion initiated from the UI.
        };

        // AreaWidgets: Each sub-page has an independent set of controls and data cache.
        struct AreaWidgets
        {
            QWidget* page = nullptr;              // page: Root control of the sub-page.
            QVBoxLayout* layout = nullptr;        // layout: sub-page root layout.
            QWidget* toolbarWidget = nullptr;     // toolbarWidget: Refresh/Delete/Copy/Filter toolbar.
            QPushButton* refreshButton = nullptr; // refreshButton: Button to refresh the current category.
            QPushButton* deleteButton = nullptr;  // deleteButton: Button to delete selected items.
            QPushButton* restoreButton = nullptr; // restoreButton: Restore the registry backup from before the last deletion on the URL binding page.
            QPushButton* copyButton = nullptr;    // copyButton: Button to copy the selected registry path.
            QLineEdit* filterEdit = nullptr;      // filterEdit: Current category keyword filter box.
            QTableWidget* table = nullptr;        // table: Right-click menu item list.
            QLabel* statusLabel = nullptr;        // statusLabel: Current category statistics and hints.
            QVector<ContextMenuEntry> entries;    // entries: Complete enumeration result for the current category's most recent entry.
            bool hasLoaded = false;               // hasLoaded: Whether this category has completed at least one on-demand enumeration.
        };

    private:
        // initializeUi：
        // - Inputs: None;
        // - Processing: Create overall layout, description text, and seven sub-pages;
        // - Returns: Nothing.
        void initializeUi();

        // createAreaPage：
        // - Input area: Right-click menu partition to be created;
        // - Processing: initialize the toolbar, table, status bar, and signal connections for this partition tool.
        // - Returns: Nothing.
        void createAreaPage(MenuArea area);

        // refreshArea：
        // - Input area: Target partition;
        // - Processing: Re-enumerate the registry key for this area and rebuild the table.
        // - Returns: Nothing.
        void refreshArea(MenuArea area);

        // rebuildAreaTable：
        // - Input area: Target partition;
        // - Processing: Render cached entries into the table based on the current filter text.
        // - Returns: Nothing.
        void rebuildAreaTable(MenuArea area);

        // showAreaContextMenu：
        // - Input area: Target partition; localPosition: Right-click coordinates within the table viewport;
        // - Processing: Display copy/delete context menu and execute user selection.
        // - Returns: Nothing.
        void showAreaContextMenu(MenuArea area, const QPoint& localPosition);

        // deleteSelectedEntries：
        // - Input area: Target partition;
        // - Processing: Collect selected rows in the table, confirm deletion, remove the corresponding registry subkeys, and refresh.
        // - Returns: None; failure information is reported via QMessageBox and logs.
        void deleteSelectedEntries(MenuArea area);

        // isUrlBindingDeletionAllowed：
        // - Input entry: Snapshot of URL binding to be deleted;
        // - Processing: Allow HKCU exact protocol/UserChoice, and HKLM third-party protocols that do not match system protection rules.
        // - Returns: true after passing the mandatory runtime safety checks, which cannot be bypassed.
        static bool isUrlBindingDeletionAllowed(const ContextMenuEntry& entry);

        // isProtectedUrlBindingEntry：
        // - Input entry: URL protocol registration snapshot;
        // - Processing: Identify known Windows protocols, NoRemove, DelegateExecute, and Packaged COM markers.
        // - Returns: true if the entry belongs to a system/encapsulated protocol and must be protected from accidental deletion.
        static bool isProtectedUrlBindingEntry(const ContextMenuEntry& entry);

        // createUrlBindingBackup：
        // - Input entryIndexes: Indices of URL binding entries to be deleted.
        // - Processing: Copy the full registry tree to the current user's KSword backup area and atomically switch the 'latest backup' reference.
        // - Return: true if all backups succeeded; otherwise return false and write the error text.
        bool createUrlBindingBackup(const QVector<int>& entryIndexes, QString* errorTextOut) const;

        // restoreLastUrlBindingBackup：
        // - Inputs: None;
        // - Processing: After validating backup metadata, copy the batch of the most recent URL binding deletions back to their original location.
        // - Return: None. Results are reflected via the UI and logs.
        void restoreLastUrlBindingBackup();

        // copySelectedEntries：
        // - Input area: Target partition;
        // - Processing: Copy the registry path of the selected row to the clipboard.
        // - Returns: Nothing.
        void copySelectedEntries(MenuArea area) const;

        // enumerateEntriesForArea：
        // - Input area: Target partition;
        // - Processing: Dispatch to context menus, associations, or namespace enumerators by partition.
        // - Return: Snapshot of registry entries currently visible in this area.
        QVector<ContextMenuEntry> enumerateEntriesForArea(MenuArea area) const;

        // enumerateUrlBindingEntries：
        // - Inputs: None;
        // - Processing: enumerate URL Protocol registrations and current user UrlAssociations\UserChoice.
        // - Return: Snapshot of registry items for the URL binding page.
        QVector<ContextMenuEntry> enumerateUrlBindingEntries() const;

        // enumerateOpenWithEntries：
        // - Inputs: None;
        // - Processing: enumerate Explorer history 'Open With' entries and candidate handlers under Classes.
        // - Returns: Registry value or subtree snapshot for the 'Open with' page.
        QVector<ContextMenuEntry> enumerateOpenWithEntries() const;

        // enumerateExplorerHomeEntries：
        // - Inputs: None;
        // - Processing: enumerate third-party namespaces in Explorer Desktop/MyComputer/HomeFolder.
        // - Return: Snapshot of third-party program items in the Explorer home page.
        QVector<ContextMenuEntry> enumerateExplorerHomeEntries() const;

        // selectedEntryIndexes：
        // - Input area: Target partition;
        // - Processing: Read entry indexes bound to selected table rows and automatically deduplicate them.
        // - Returns an array of indices for the selected entries.
        QVector<int> selectedEntryIndexes(MenuArea area) const;

        // widgetsForArea：
        // - Input area: Target partition;
        // - Processing: Return pointer to the control group for this area;
        // - Return: Pointer to AreaWidgets; never null when area is valid.
        AreaWidgets* widgetsForArea(MenuArea area);
        const AreaWidgets* widgetsForArea(MenuArea area) const;

        // areaTitle：
        // - Input area: Target partition;
        // - Processing: Convert to Chinese tab title.
        // - Return: Title text used for the Tab and logs.
        static QString areaTitle(MenuArea area);

        // areaIconPath：
        // - Input area: Target partition;
        // - Processing: Select existing qrc icons by partition.
        // - Returns: Icon resource path.
        static QString areaIconPath(MenuArea area);

    private:
        QVBoxLayout* rootLayout_ = nullptr;   // m_rootLayout: Root layout for this page.
        QTabWidget* areaTabWidget_ = nullptr; // m_areaTabWidget: Container for seven categories of Shell association sub-tabs.
        AreaWidgets ieWidgets_;               // m_ieWidgets: IE context menu sub-page widget group.
        AreaWidgets desktopWidgets_;          // m_desktopWidgets: Desktop context menu sub-page widget group.
        AreaWidgets fileWidgets_;             // m_fileWidgets: File context menu sub-page control group.
        AreaWidgets urlBindingWidgets_;        // m_urlBindingWidgets: URL binding sub-page widget group.
        AreaWidgets openWithWidgets_;          // m_openWithWidgets: Open With sub-page widget group.
        AreaWidgets formatMenuWidgets_;        // m_formatMenuWidgets: Format context menu sub-page widget group.
        AreaWidgets explorerHomeWidgets_;      // m_explorerHomeWidgets: Explorer home page third-party program sub-page control group.
    };
}
