#pragma once

// ============================================================
// StartupDock.h
// Purpose:
// 1) Provide a centralized management entry for "Startup Items" similar to Autoruns;
// 2) Unified display of login items, services, drivers, scheduled tasks, and advanced registry persistence items.
// 3) Provide operations such as refresh, export, copy, and open file location/registry location.
// ============================================================

#include "../Framework.h"
#include "../../../shared/platform/startup/Startup.h"

#include <QHash>
#include <QIcon>
#include <QWidget>

#include <atomic>   // std::atomic_bool: Background refresh running status.
#include <cstddef>  // std::size_t: Batch table progress coordinate.
#include <cstdint>  // std::uint32_t: PID, status value, and identifier fields.
#include <deque>    // std::deque: Cache stage results in enumeration completion order.
#include <memory>   // std::unique_ptr: manages the background thread object.
#include <thread>   // std::thread: Background enumeration thread.
#include <vector>   // std::vector: stores startup item cache and supports pagination table reconstruction.

class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QEvent;
class QShowEvent;
class QTabWidget;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

class StartupDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize the UI, connect interactions, and perform the initial refresh.
    // - Parameter parent: Qt parent widget.
    explicit StartupDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop the refresh timer and release resources.
    ~StartupDock() override;

protected:
    // showEvent：
    // - Purpose: Trigger the initial enumeration only when the tab is first actually displayed.
    // - Avoid blocking during main window startup due to a full scan of startup items.
    void showEvent(QShowEvent* event) override;
    void changeEvent(QEvent* event) override;

public:
    // StartupCategory：
    // - Purpose: Define the main category for startup items, reused for overview and tab filtering.
    enum class StartupCategory : int
    {
        kAll = 0,       // Overview
        kLogon,         // Startup items (Run/RunOnce/Startup Folder).
        kServices,      // SCM services (automatic, manual, or disabled).
        kDrivers,       // SCM drivers (boot, system, automatic, manual, or disabled).
        kTasks,         // Scheduled tasks.
        kImageHijack,   // IFEO / SilentProcessExit image hijacking detection result.
        kRegistry,      // Advanced registry persistence items.
        kWmi,           // WMI persistence items.
        kHidden         // Hidden items: startup sources that do not match between the two system views.
    };

    // StartupEntry：
    // - Purpose: Unify the container for a single startup entry record.
    // - Reused by all enumerators' output and all table renderings.
    struct StartupEntry
    {
        ks::startup::StartupEntry backendEntry; // backendEntry: Complete backend record; modifications and deletions use only structured location information.
        QString uniqueIdText;           // uniqueIdText: globally unique key for cache lookup.
        StartupCategory category = StartupCategory::kAll; // category: Category.
        QString categoryText;           // categoryText: Category display text.
        QString itemNameText;           // itemNameText: Item name.
        QString publisherText;          // publisherText: Publisher/Company name.
        QString imagePathText;          // imagePathText: Target file path or host path.
        QString commandText;            // commandText: Command line or data text.
        QString locationText;           // locationText: Source location (registry key/folder/task path).
        QString locationGroupText;      // locationGroupText: Registry location corresponding to the first-level node in the registry tree.
        QString registryValueNameText;  // registryValueNameText: The actual value name used when deleting the registry value.
        QString userText;               // userText: owning user or context.
        QString detailText;             // detailText: supplementary explanation.
        QString sourceTypeText;         // sourceTypeText: Source type (Run/Service/Task...).
        bool enabled = true;            // enabled: Indicates whether the feature is not disabled; SCM precise mode is stored in backendEntry.
        bool canOpenFileLocation = false; // canOpenFileLocation: Indicates whether opening the file location is supported.
        bool canOpenRegistryLocation = false; // canOpenRegistryLocation: Whether opening the registry location is supported.
        bool canDelete = false;         // canDelete: Whether deletion of the source item is supported.
        bool deleteRegistryTree = false; // deleteRegistryTree: Whether to delete the entire registry subkey during deletion.
        QIcon itemIcon;                 // itemIcon: Item icon.
    };

    // StartupColumn：
    // - Purpose: Uniformly define table column indices to avoid hard-coded magic numbers.
    enum class StartupColumn : int
    {
        kName = 0,       // Name.
        kPublisher,      // Publisher.
        kImagePath,      // Image path.
        kCommand,        // Command line / data.
        kLocation,       // Source location.
        kUser,           // User/Context.
        kEnabled,        // Enabled status.
        kType,           // Source type.
        kDetail,         // Supplementary note.
        kCount           // Total columns.
    };

    // toStartupColumn：
    // - Purpose: Convert the column enumeration to an int index for shared use across multiple implementation files.
    static int toStartupColumn(StartupColumn column);

private:
    struct TableRebuildTarget
    {
        StartupCategory category = StartupCategory::kAll;
        QTableWidget* tableWidget = nullptr;
        std::vector<int> visibleEntryIndexList;
        std::size_t nextRowIndex = 0;
    };

    struct RegistryGroupRebuildTarget
    {
        QString locationText;
        std::vector<int> totalEntryIndexList;
        std::vector<int> visibleEntryIndexList;
        QTreeWidgetItem* groupItem = nullptr;
        std::size_t nextEntryIndex = 0;
        bool initialized = false;
    };

    struct RefreshStageResult
    {
        std::size_t stageIndex = 0;
        std::size_t stageCount = 0;
        std::vector<StartupEntry> entryList;
    };

    // ===================== Initialization =====================
    void initializeUi();
    void initializeToolbar();
    void initializeTabs();
    void initializeConnections();
    void applyTranslatedHeaders();

    // ===================== Enumeration and Refresh =====================
    void refreshAllStartupEntries();
    void requestAsyncRefresh(bool forceRefresh);
    void enqueueRefreshStageResult(
        std::size_t stageIndex,
        std::size_t stageCount,
        std::vector<StartupEntry> entryList);
    void processNextRefreshStageResult();
    void markBackendEnumerationCompleted();
    void completeRefreshAfterUiCommit();
    void rebuildAllTables(bool processesRefreshStage = false);
    void continueIncrementalTableRebuild();
    void finishIncrementalTableRebuild();
    void initializeRegistryTreeGroup(RegistryGroupRebuildTarget* target);

    // ===================== Enumerator =====================
    void appendLogonEntries(std::vector<StartupEntry>* entryListOut);
    void appendServiceEntries(std::vector<StartupEntry>* entryListOut);
    void appendDriverEntries(std::vector<StartupEntry>* entryListOut);
    void appendTaskEntries(std::vector<StartupEntry>* entryListOut);
    void appendAdvancedRegistryEntries(std::vector<StartupEntry>* entryListOut);
    void appendWinsockEntries(std::vector<StartupEntry>* entryListOut);
    void appendWmiEntries(std::vector<StartupEntry>* entryListOut);
    void appendHiddenEntries(std::vector<StartupEntry>* entryListOut);

    // ===================== Interaction =====================
    void showEntryContextMenu(StartupCategory category, QTableWidget* tableWidget, const QPoint& localPos);
    void showRegistryContextMenu(const QPoint& localPos);
    void showSelectedEntryDetails(StartupCategory category, QTableWidget* tableWidget);
    void openSelectedFileLocation(StartupCategory category, QTableWidget* tableWidget);
    void openSelectedFileProperties(StartupCategory category, QTableWidget* tableWidget);
    void openSelectedRegistryLocation(StartupCategory category, QTableWidget* tableWidget);
    void copySelectedRow(StartupCategory category, QTableWidget* tableWidget);
    void setStartupEntryEnabled(StartupEntry entry, bool enabled);
    void setStartupEntriesEnabled(std::vector<StartupEntry> entryList, bool enabled);
    void deleteStartupEntry(StartupEntry entry);
    void deleteStartupEntries(std::vector<StartupEntry> entryList);
    void exportCurrentView();
    void applyFilterAndRefresh();

    // ===================== Utilities =====================
    static QString categoryToText(StartupCategory category);
    int findEntryIndexByTableRow(StartupCategory category, int row) const;
    int findEntryIndexByRegistryTreeItem(const QTreeWidgetItem* treeItem) const;
    bool isRegistryBackedStartupEntry(const StartupEntry& entry) const;
    bool entryMatchesCurrentFilter(const StartupEntry& entry) const;
    QTableWidget* currentCategoryTable() const;
    StartupCategory currentCategory() const;
    QIcon resolveEntryIcon(const StartupEntry& entry);
    void appendEntryRow(QTableWidget* tableWidget, int rowIndex, const StartupEntry& entry, int entryIndex);
    void appendRegistryTreeLeaf(QTreeWidgetItem* parentItem, const StartupEntry& entry, int entryIndex);

private:
    // ===================== Top-level Layout =====================
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Root layout.
    QWidget* toolbarWidget_ = nullptr;       // m_toolbarWidget: The top toolbar container.
    QHBoxLayout* toolbarLayout_ = nullptr;   // m_toolbarLayout: The top toolbar layout.
    QTabWidget* sideTabWidget_ = nullptr;    // m_sideTabWidget: Container for the left-side category tabs.

    // ===================== Toolbar Controls =====================
    QPushButton* refreshButton_ = nullptr;   // m_refreshButton: Refresh button.
    QPushButton* exportButton_ = nullptr;    // m_exportButton: Export button.
    QPushButton* copyButton_ = nullptr;      // m_copyButton: Copy button.
    QLineEdit* filterEdit_ = nullptr;        // m_filterEdit: Keyword filter input box.
    QCheckBox* hideMicrosoftCheck_ = nullptr; // m_hideMicrosoftCheck: Toggle to hide Microsoft items.
    QCheckBox* hideEmptyPathCheck_ = nullptr; // m_hideEmptyPathCheck: Toggle to hide registry paths with no entries.
    QLabel* statusLabel_ = nullptr;          // m_statusLabel: Summary status text.

    // ===================== Category Page Tables =====================
    QWidget* allPage_ = nullptr;             // m_allPage: Overview page.
    QWidget* logonPage_ = nullptr;           // m_logonPage: Logon items page.
    QWidget* servicesPage_ = nullptr;        // m_servicesPage: Services page.
    QWidget* driversPage_ = nullptr;         // m_driversPage: Drivers page.
    QWidget* tasksPage_ = nullptr;           // m_tasksPage: Scheduled tasks page.
    QWidget* imageHijackPage_ = nullptr;     // m_imageHijackPage: Image hijacking detection page.
    QWidget* registryPage_ = nullptr;        // m_registryPage: Advanced registry page.
    QWidget* wmiPage_ = nullptr;             // m_wmiPage: WMI persistence page.
    QWidget* hiddenPage_ = nullptr;          // m_hiddenPage: Hidden items page.

    QTableWidget* allTable_ = nullptr;       // m_allTable: Overview table.
    QTableWidget* logonTable_ = nullptr;     // m_logonTable: Logon items table.
    QTableWidget* servicesTable_ = nullptr;  // m_servicesTable: Services table.
    QTableWidget* driversTable_ = nullptr;   // m_driversTable: Drivers table.
    QTableWidget* tasksTable_ = nullptr;     // m_tasksTable: Tasks table.
    QTableWidget* imageHijackTable_ = nullptr; // m_imageHijackTable: Image hijacking detection table.
    QTreeWidget* registryTree_ = nullptr;    // m_registryTree: Advanced registry tree (grouped by registry location).
    QTableWidget* wmiTable_ = nullptr;       // m_wmiTable: WMI persistence table.
    QTableWidget* hiddenTable_ = nullptr;    // m_hiddenTable: Hidden items table.

    // ===================== Data Cache =====================
    std::vector<StartupEntry> entryList_;    // m_entryList: Cache of all startup items.
    QHash<QString, QIcon> iconCache_;        // m_iconCache: Path-to-icon cache.
    QTimer* refreshTimer_ = nullptr;         // m_refreshTimer: Auto-refresh timer.
    QTimer* tableRebuildTimer_ = nullptr;    // m_tableRebuildTimer: Time-sliced table scheduling dispatcher.
    std::vector<TableRebuildTarget> tableRebuildTargets_; // m_tableRebuildTargets: Tables to be filled in batches.
    std::vector<RegistryGroupRebuildTarget> registryRebuildTargets_; // m_registryRebuildTargets: Registry groups to be filled in batches.
    std::size_t tableRebuildTargetIndex_ = 0; // m_tableRebuildTargetIndex: current table task index.
    std::size_t registryRebuildTargetIndex_ = 0; // m_registryRebuildTargetIndex: Current registry group index.
    std::size_t tableRebuildCompletedUnits_ = 0; // m_tableRebuildCompletedUnits: Number of completed table rebuild units.
    std::size_t tableRebuildTotalUnits_ = 0; // m_tableRebuildTotalUnits: Total workload for table rebuilding in this round.
    int lastTableRebuildProgressPercent_ = -1; // m_lastTableRebuildProgressPercent: Avoids reporting the same percentage repeatedly.
    bool tableRebuildInProgress_ = false; // m_tableRebuildInProgress: Indicates whether the view is currently being populated by time slices.
    bool tableRebuildProcessesRefreshStage_ = false; // m_tableRebuildProcessesRefreshStage: Indicates whether a batch of enumeration results is currently being applied.
    bool rebuildRegistryFirst_ = false; // m_rebuildRegistryFirst: Prioritize populating the tree when the current visible page is the registry.
    std::deque<RefreshStageResult> pendingRefreshStageResults_; // m_pendingRefreshStageResults: Stage results waiting to be added incrementally.
    std::size_t activeRefreshStageIndex_ = 0; // m_activeRefreshStageIndex: Index of the zero-based stage currently being written to the table.
    std::size_t activeRefreshStageCount_ = 0; // m_activeRefreshStageCount: Total number of enumeration stages in this round.
    std::size_t activeRefreshStageEntryCount_ = 0; // m_activeRefreshStageEntryCount: number of new entries in the current stage.
    std::size_t appliedRefreshStageCount_ = 0; // m_appliedRefreshStageCount: Number of stages fully written to the table.
    bool backendEnumerationCompleted_ = false; // m_backendEnumerationCompleted: Whether all nine backend stages have completed.
    bool refreshSnapshotStarted_ = false; // m_refreshSnapshotStarted: Whether the switch away from the old snapshot has occurred after the first batch arrives.
    bool initialRefreshDone_ = false;        // m_initialRefreshDone: Whether the initial lazy load has been completed.
    std::atomic_bool refreshInProgress_{ false }; // m_refreshInProgress: Flag indicating whether a background refresh is in progress.
    std::atomic_bool refreshQueued_{ false };     // m_refreshQueued: Flag indicating if a new request was received during a refresh.
    std::atomic_bool startupActionInProgress_{ false }; // m_startupActionInProgress: Indicates whether a reversible start/stop action is in progress.
    std::atomic_bool destroying_{ false };        // m_destroying: Destruction has started; background threads no longer dispatch UI callbacks.
    std::unique_ptr<std::thread> refreshThread_;  // m_refreshThread: Background enumeration of thread objects.
    std::unique_ptr<std::thread> actionThread_;   // m_actionThread: Managed worker thread for startup item modifications.
    int progressPid_ = 0;                         // m_progressPid: PID of the startup item enumeration progress task.
};
