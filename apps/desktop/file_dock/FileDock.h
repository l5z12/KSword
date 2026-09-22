#pragma once

// ============================================================
// FileDock.h
// Purpose:
// 1) Implement a dual-pane file explorer with independent left and right panels;
// 2) Provide navigation, filtering, sorting, basic file operations, and right-click analysis menu;
// 3) Provide column management and file details window entry points.
// ============================================================

#include "../Framework.h"
#include "ManualFileSystemParser.h"

#include <QStringList>
#include <QWidget>

#include <cstdint>     // std::uint64_t: File size statistics.
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>      // std::vector: Navigation history container.

// Qt forward declarations: Reduce header file coupling.
class QCheckBox;
class QComboBox;
class QDialog;
class QEvent;
class QFileSystemModel;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QListView;
class QMenu;
class QPlainTextEdit;
class QPushButton;
class QStandardItemModel;
class QStackedWidget;
class QSortFilterProxyModel;
class QSplitter;
class QStatusBar;
class QTabWidget;
class QTableWidget;
class QToolButton;
class QTreeView;
class QVBoxLayout;
class QWidget;

// FileDeleteMode: Permission tier for right-click "Delete", ordered from low to high by "required permission strength".
// - Directories are always deleted recursively in post-order (children before parents) regardless of the mode; the difference lies only in the permissions used for deletion.
// - Later modes are more irreversible; the UI must clearly explain the differences in the confirmation dialog.
enum class FileDeleteMode
{
    kRecycleBin,     // R3 current permissions; moved to Recycle Bin, can be restored from Recycle Bin.
    kPermanentR3,    // R3 current permission; recursive permanent deletion without sending to Recycle Bin.
    kForceR3,        // R3 privilege escalation: Clear attributes, take ownership, grant full control, then recursively delete permanently.
    kPendingReboot,  // R3 privilege escalation: registers PendingFileRenameOperations for deletion on the next reboot.
    kDriverR0Native, // R0 driver: Low-level Zw* approach, retaining existing compatibility fallback.
    kDriverR0Irp,    // R0 driver: IRP_MJ_SET_INFORMATION traverses the complete file system stack.
    kDriverR0Posix   // R0 driver: FileDispositionInformationEx POSIX unlink semantics.
};

// ============================================================
// FileDock
// Notes:
// - Both left and right columns use the same FilePanelWidgets structure for description;
// - Each panel independently maintains path history, filtering, and sorting state.
// ============================================================
class FileDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize the dual-pane UI and set the default directory.
    // - Parameter parent: Qt parent widget.
    explicit FileDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: The default destructor suffices; all child widgets are automatically released via Qt's parent-child relationship.
    ~FileDock() override;

    // openFileDetailByPath：
    // - Purpose: Expose the file details window entry point (including Property/Hash/Signature/PE tabs) to the outside.
    // - For cross-page linkage calls by modules such as ServiceDock.
    // - Parameter filePath: Absolute path of the target file.
    void openFileDetailByPath(const QString& filePath);

    // unlockFileByPath：
    // - Purpose: Exposes the "file unlocker" entry point (single path).
    // - Used for cross-page linkage calls after system context menu commands are launched.
    void unlockFileByPath(const QString& targetPath);

protected:
    // changeEvent: Redraws the localized size/type text of the file model immediately after a language switch.
    void changeEvent(QEvent* event) override;

    // eventFilter：
    // - Input: watched is the filtered object, event is the Qt event object
    // - Processing: Intercept only right-click press events on the file list viewport to preserve multi-selection sets or switch to the single line hit by the right-click.
    // - Returns: true if the event has been handled by FileDock; otherwise, passes to the QWidget default implementation.
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    // ManualParseBackend：
    // - Purpose: normalize 'read method' dropdown index to backend type, avoiding magic index comparisons at each call site;
    // - WindowsApi uses QFileSystemModel and does not enter the tiling parsing pipeline.
    enum class ManualParseBackend
    {
        kWindowsApi = 0,   // Windows API（QFileSystemModel）。
        kManualFs,         // R3 raw volume manual parsing (automatic detection or forced NTFS/FAT32/exFAT).
        kR0Driver,         // R0 ZwQueryDirectoryFile paginated enumeration.
        kMftStrict,        // Pure $MFT scan; disable all WinAPI/FSCTL fallbacks.
        kR0Irp             // R0: Self-built IRP sent directly to the file system stack.
    };

    // FilePanelWidgets：
    // - Purpose: Aggregate all controls and runtime state for a single file panel.
    struct FilePanelWidgets
    {
        QWidget* rootWidget = nullptr;         // Panel root container.
        QVBoxLayout* rootLayout = nullptr;     // Panel main layout.

        QWidget* navWidget = nullptr;          // Navigation bar container.
        QHBoxLayout* navLayout = nullptr;      // Navigation bar layout.
        QPushButton* backButton = nullptr;     // Back button.
        QPushButton* forwardButton = nullptr;  // Forward button.
        QPushButton* upButton = nullptr;       // Parent directory button.
        QPushButton* refreshButton = nullptr;  // Refresh button.
        QStackedWidget* pathStack = nullptr;   // Address area stacked widget (breadcrumb or edit box, mutually exclusive).
        QLineEdit* pathEdit = nullptr;         // Address bar input field (edit mode).
        QComboBox* driveCombo = nullptr;       // Drive jump dropdown on the right side of the address bar.
        QWidget* breadcrumbWidget = nullptr;   // Breadcrumb container (display mode).
        QHBoxLayout* breadcrumbLayout = nullptr; // Breadcrumb layout.
        QPushButton* breadcrumbEditTriggerButton = nullptr; // Breadcrumb trailing empty click hotspot.

        QWidget* toolWidget = nullptr;         // Toolbar container.
        QHBoxLayout* toolLayout = nullptr;     // Toolbar layout.
        QComboBox* viewModeCombo = nullptr;    // View mode selection (icon/list/details/tree).
        QCheckBox* showSystemCheck = nullptr;  // Show system files toggle.
        QCheckBox* showHiddenCheck = nullptr;  // Show hidden files toggle.
        QComboBox* sortModeCombo = nullptr;    // Sort mode selection.
        QComboBox* readModeCombo = nullptr;    // Read mode (Windows API / R3 manual / R0 driver / forced FS).
        QLineEdit* filterEdit = nullptr;       // Quick filter input box for file names.

        QStackedWidget* fileViewStack = nullptr; // File view container (switching between icon/list and details/tree).
        QListView* compactFileView = nullptr;  // Actual icon grid or vertical list view.
        QTreeView* fileView = nullptr;         // Details/tree view, also holding the shared selection.
        QFileSystemModel* fsModel = nullptr;   // Raw file system model.
        QSortFilterProxyModel* proxyModel = nullptr; // Filter proxy model.
        QStandardItemModel* manualModel = nullptr;   // Manual parsing original model.
        QSortFilterProxyModel* manualProxyModel = nullptr; // Manual parsing proxy model.

        QStatusBar* statusBar = nullptr;       // Panel status bar.
        QLabel* pathStatusLabel = nullptr;     // Current path status.
        QLabel* selectionStatusLabel = nullptr; // Selected count/size status.
        QLabel* diskStatusLabel = nullptr;     // Disk space status.
        QLabel* parserStatusLabel = nullptr;   // Current parser status indicator.

        std::vector<QString> history;          // Path history list.
        int historyIndex = -1;                 // Current history index.
        QString currentPath;                   // Current directory path.
        QString manualLoadedPath;              // Manually parsed model current loaded directory path.
        QString panelNameText;                 // Panel name (used for logs and notifications).
        QString lastStatusLogSignature;        // Status bar log deduplication signature.
        QString lastFilterLogSignature;        // Filter parameter log deduplication signature.
        bool pathEditMode = false;             // Whether currently in path edit mode.
        ks::file::ManualFsType lastManualFsType = ks::file::ManualFsType::kUnknown; // FS type identified by the most recent manual parsing.
        ks::file::ManualFsType manualRequestedFsType = ks::file::ManualFsType::kUnknown; // Manually requested parsing type for the current read mode.
        int manualRequestedReadMode = 0;        // Index of the read mode corresponding to the current model, preventing erroneous reuse of R3/R0 results.
        bool manualResultPartial = false;       // true if R0 paging/name boundaries cause incomplete results.
        QString manualSourceDetail;             // Actual parsing source summary for the current tiling model.
        QStringList manualSuspiciousNames;      // Only entry names visible via bypass paths (suspected to be hidden).
        bool manualParseInProgress = false;    // Whether the manual parsing background task is in progress.
        bool manualParsePending = false;       // Whether there is a pending manual parse request.
        bool manualParsePendingShowWarning = false; // Whether the pending request requires a failure dialog.
        int manualParseRequestSerial = 0;      // Manual parse request serial number (used to discard stale results).
        QString manualParsingPath;             // The path currently being processed by the background parser (to avoid duplicate parsing of the same path).
        int manualParsingReadMode = -1;        // Index of the read mode used by the current background parser; must re-parse if the path changes and the mode changes.
    };

    struct FileOplockAccessRecord;
    struct FileOplockEntry;
    enum class FileOplockLevel
    {
        kLevel1,
        kLevel2,
        kBatch,
        kFilter
    };

    // ======================= UI Initialization ========================
    // initializeUi：
    // - Purpose: Build a dual-pane splitter layout and initialize the left and right panels.
    void initializeUi();

    // initializePanel：
    // - Purpose: Initializes all controls for a file panel.
    // - Parameter panel: The panel structure to be initialized.
    // - Parameter titleText: The panel title text.
    void initializePanel(FilePanelWidgets& panel, const QString& titleText);

    // initializeConnections：
    // - Purpose: Bind signal-slot interaction logic for a single panel.
    // - Parameter panel: Target panel.
    void initializeConnections(FilePanelWidgets& panel);

    // initializeRecoveryPage：
    // - Purpose: initialize the "File Recovery" vertical tab page.
    void initializeRecoveryPage();

    // ======================= IRP Construction ========================
    // initializeIrpBuilderPage：
    // - Purpose: initialize the 'IRP Builder' vertical tab page, covering all 28 IRP_MJ_* functions.
    void initializeIrpBuilderPage();

    // applyIrpMajorPreset：
    // - Input: The currently selected IRP_MJ_* value;
    // - Processing: Enable/disable parameter fields and fill in common default values according to the definition of this major,
    //   and also enable the corresponding confirmation switch requirements for write semantics and PnP/power-related requests.
    // - Returns: Nothing.
    void applyIrpMajorPreset(int majorFunction);

    // applyIrpOperationPreset：
    // - Input: common operation preset ID
    // - Processing: Fill Major, InformationClass, access rights, input buffer, and directory flags in one go;
    // - Note: Parameters are filled but not sent; write operations still require explicit user confirmation.
    void applyIrpOperationPreset(int presetId);

    // submitConstructedIrp：
    // - Purpose: Collect page parameters, submit a single R0 self-built IRP in a background thread, and fill in the results.
    // - Note: Write semantics and dangerous major functions require user confirmation again before submission.
    void submitConstructedIrp();

    // updateIrpBuilderEnabledState：
    // - Purpose: Uniformly toggle page control availability based on background task status.
    void updateIrpBuilderEnabledState(bool submitting);

    // irpMajorDisplayText / irpMinorDisplayText：
    // - Purpose: Map IRP_MJ_* and IRP_MN_* values to dropdown labels containing the value and name.
    static QString irpMajorDisplayText(int majorFunction);

    // parseNumericField / parseHexPayload / formatHexDump：
    // - Purpose: Common implementation for page input parsing and output display.
    // - parseNumericField accepts both decimal and 0x-prefixed hexadecimal; an empty string is treated as 0.
    static bool parseNumericField(
        const QString& text,
        unsigned long long& valueOut,
        QString& errorTextOut);
    static bool parseHexPayload(
        const QString& text,
        std::vector<std::uint8_t>& bytesOut,
        QString& errorTextOut);
    static QString formatHexDump(const std::vector<std::uint8_t>& data);

    // ======================= Navigation and status ========================
    // navigateToPath：
    // - Purpose: Switch the panel directory and optionally record history.
    // - Parameter panel: Target panel.
    // - Parameter pathText: Target directory path.
    // - Parameter recordHistory: Whether to write navigation history.
    void navigateToPath(FilePanelWidgets& panel, const QString& pathText, bool recordHistory);

    // refreshPanel：
    // - Purpose: Refresh the current directory and reapply filters/sorting.
    void refreshPanel(FilePanelWidgets& panel);

    // rebuildBreadcrumb：
    // - Purpose: Rebuild clickable breadcrumbs based on the current path.
    void rebuildBreadcrumb(FilePanelWidgets& panel);

    // setPathEditMode：
    // - Purpose: Toggle address bar display mode (true = edit box, false = breadcrumb).
    void setPathEditMode(FilePanelWidgets& panel, bool editMode);

    // refreshDriveCombo：
    // - Purpose: Refresh the drive combo box list and synchronize the currently selected item.
    void refreshDriveCombo(FilePanelWidgets& panel);

    // updatePanelStatus：
    // - Purpose: Update the status bar (path, selected count, capacity, etc.).
    void updatePanelStatus(FilePanelWidgets& panel);

    // applyPanelFilterAndSort：
    // - Purpose: Applies settings for showing/hiding files, name filtering, and sorting modes.
    void applyPanelFilterAndSort(FilePanelWidgets& panel);

    // applyReadModeToPanel：
    // - Purpose: Switches the panel model based on the read mode (Windows API / Auto-Manual / Forced Filesystem Parsing).
    void applyReadModeToPanel(FilePanelWidgets& panel);

    // configureFileViewSelection：
    // - Input: panel is the file panel to be configured;
    // - Processing: Unify restoring full-row selection behavior for the file list to avoid reverting to default interaction after setModel() replaces the selection model.
    // - Returns: Nothing.
    void configureFileViewSelection(FilePanelWidgets& panel);

    // recreateFileSystemModel：
    // - Input: panel is the panel requiring forced refresh of Windows API directory data;
    // - Processing: Rebuild QFileSystemModel and reattach it to the proxy model to bypass QFileSystemModel's caching of size and mtime.
    // - Returns: Nothing.
    void recreateFileSystemModel(FilePanelWidgets& panel);

    // reloadManualModel：
    // - Purpose: Manually parse the current directory and populate the model.
    // - Parameter showWarningMessage: whether to show a dialog box on failure.
    bool reloadManualModel(FilePanelWidgets& panel, bool showWarningMessage);

    // requestAsyncManualReload：
    // - Purpose: Asynchronously execute manual parsing to avoid blocking the UI thread.
    // - Parameter panel: Target panel.
    // - Parameter showWarningMessage: Whether to show a dialog box on failure.
    void requestAsyncManualReload(FilePanelWidgets& panel, bool showWarningMessage);

    // currentModeIsManual：
    // - Purpose: Determine if the current panel is in manual parsing mode.
    bool currentModeIsManual(const FilePanelWidgets& panel) const;

    // currentModeUsesDriver：
    // - Purpose: Determine whether the tiled directory model should be populated via KswordARK's R0 directory query.
    bool currentModeUsesDriver(const FilePanelWidgets& panel) const;

    // requestedManualFsTypeForPanel：
    // - Purpose: Parse the forced file system type based on the read mode combo box.
    // - Returns Unknown to indicate 'manual auto-detection'.
    ks::file::ManualFsType requestedManualFsTypeForPanel(const FilePanelWidgets& panel) const;

    // manualParseBackendForPanel：
    // - Purpose: Map the read method dropdown index to ManualParseBackend.
    // - All tiled parsing dispatches must go through this function; the index-to-backend mapping is maintained in only one place.
    ManualParseBackend manualParseBackendForPanel(const FilePanelWidgets& panel) const;

    // parseBackendIsKernel：
    // - Purpose: Determine if the result originates from Ring 0 to distinguish R0/R3 sources in status text and logs.
    static bool parseBackendIsKernel(ManualParseBackend backend);

    // parseBackendDisplayText / parseBackendLogTag：
    // - Purpose: Provides a unified backend name for UI hints and structured logs.
    static QString parseBackendDisplayText(ManualParseBackend backend);
    static const char* parseBackendLogTag(ManualParseBackend backend);

    // runManualParseBackend：
    // - Input: backend type, target path, and forced file system type;
    // - Processing: Invoke the corresponding parser to fold the difference diagnosis into sourceDetailOut for status bar display.
    // - Returns: true on successful parsing; on failure, errorTextOut contains the reason.
    // - Note: This function reads only the file system and driver, touching no UI objects, and can be called from a background thread.
    static bool runManualParseBackend(
        ManualParseBackend backend,
        const QString& pathText,
        ks::file::ManualFsType requestedFsType,
        std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
        ks::file::ManualFsType& fsTypeOut,
        QString& errorTextOut,
        bool& usedWinApiFallbackOut,
        bool& partialOut,
        QString& sourceDetailOut,
        QStringList& suspiciousNamesOut);

    // ======================= File Operations ========================
    // showPanelContextMenu：
    // - Purpose: Display the right-click menu (operations + analysis submenus).
    void showPanelContextMenu(FilePanelWidgets& panel, const QPoint& localPos);

    // openSelectedItems：
    // - Purpose: Open currently selected items (supports multi-selection; enters directories or opens via system).
    void openSelectedItems(FilePanelWidgets& panel);

    // copySelectedItemPath：
    // - Purpose: Copy the full path of the selected item to the clipboard.
    void copySelectedItemPath(FilePanelWidgets& panel);

    // copySelectedItemKernelPath：
    // - Purpose: Copy the selected item's kernel namespace path (\??\...) to the clipboard.
    void copySelectedItemKernelPath(FilePanelWidgets& panel);

    // copySelectedItemShortName：
    // - Purpose: Copy the short filename (8.3 name) of selected items to the clipboard.
    void copySelectedItemShortName(FilePanelWidgets& panel);

    // copySelectedItems：
    // - Purpose: Directly copy the currently selected items in the current panel to the current directory of the opposite panel.
    void copySelectedItems(FilePanelWidgets& panel);

    // cutSelectedItems：
    // - Purpose: Directly move the currently selected items in the current panel to the current directory of the opposite panel.
    void cutSelectedItems(FilePanelWidgets& panel);

    // oppositePanelFor：
    // - Input: sourcePanel is the source panel initiating the copy/cut action;
    // - Processing: Resolve the opposite panel based on the left/right panel instance address.
    // - Return: Returns the pointer to the opposite panel on success; returns nullptr if the source cannot be identified.
    FilePanelWidgets* oppositePanelFor(FilePanelWidgets& sourcePanel);

    // transferSelectedItemsToOppositePanel：
    // - Input: sourcePanel is the source panel; moveItems is true to move, false to copy;
    // - Handling: Read selected paths from the source panel, set the target to the opposite panel's currentPath, and copy/move items one by one;
    // - Returns: none. Failed items are logged and update the progress status.
    void transferSelectedItemsToOppositePanel(FilePanelWidgets& sourcePanel, bool moveItems);

    // createNewFileOrFolder：
    // - Purpose: Create a new file or folder in the current directory.
    void createNewFileOrFolder(FilePanelWidgets& panel, bool createFolder);

    // renameSelectedItem：
    // - Purpose: Rename the currently selected item.
    void renameSelectedItem(FilePanelWidgets& panel);

    // deleteSelectedItem：
    // - Purpose: Delete the currently selected item using the 'Move to Recycle Bin' mode (triggered via the Delete key shortcut).
    void deleteSelectedItem(FilePanelWidgets& panel);

    // deleteSelectedItemByDriver：
    // - Purpose: Performs a recursive hard delete on the currently selected items via the KswordARK driver.
    // - Note: The new driver expands the directory tree internally in R0; the old driver automatically falls back to R3 for sequential expansion and deletion.
    void deleteSelectedItemByDriver(FilePanelWidgets& panel);

    // deleteSelectedItemsWithMode：
    // - Input: panel is the source panel for the action, mode is the permission level;
    // - Processing: Unified pre-permission checks, confirmation messages, background batch deletion, and result aggregation.
    //   Directories are processed in post-order semantics ('children first, then directory') across all levels.
    // - Returns: No return value; results are feedback via logs, progress bars, and message boxes.
    void deleteSelectedItemsWithMode(FilePanelWidgets& panel, FileDeleteMode mode);

    // takeOwnershipSelectedItems：
    // - Purpose: Execute 'Take Ownership + Grant Full Control' on the currently selected items.
    // - Note: Invokes system takeown/icacls; failure messages are aggregated and reported.
    void takeOwnershipSelectedItems(FilePanelWidgets& panel);

    // setSelectedFileIntegrityLevel：
    // - Input: panel is the source panel for the right-click menu, integrityRid is the target S-1-16-* Mandatory Label RID.
    // - Processing: R0 kernel APIs are used to write file/directory integrity labels first; if the driver is unavailable or outdated, it falls back to R3.
    // - Returns: nothing. Results are reported via logs and message boxes.
    void setSelectedFileIntegrityLevel(
        FilePanelWidgets& panel,
        unsigned long integrityRid,
        const QString& levelDisplayText);

    // unlockSelectedItemsByDriver：
    // - Purpose: Scan processes occupying selected paths, list candidate processes, and terminate them via R3/R0 based on user selection;
    // - Note: Used for the 'File Unlocker' right-click action; does not directly delete files.
    void unlockSelectedItemsByDriver(FilePanelWidgets& panel);

    // addOplockToSelectedFile：
    // - Purpose: Request and hold an R3 Oplock at the specified level for the currently selected file.
    // - Note: The Oplock lifecycle is managed by FileDock until triggered, manually released, or FileDock is destructed.
    void addOplockToSelectedFile(FilePanelWidgets& panel, FileOplockLevel level);

    // releaseSelectedFileOplock：
    // - Purpose: Releases the Oplock held by FileDock on the currently selected file.
    void releaseSelectedFileOplock(FilePanelWidgets& panel);

    // showSelectedFileOplockAccessRecords：
    // - Purpose: Display access process records captured by the currently selected file's Oplock.
    void showSelectedFileOplockAccessRecords(FilePanelWidgets& panel);

    // releaseAllActiveOplocks：
    // - Purpose: Release all Oplocks currently held by FileDock.
    // - Parameter showMessage: If true, displays the release count to the user.
    void releaseAllActiveOplocks(bool showMessage);

    // hasActiveOplockForPath / activeOplockCount / activeOplockBreakCountForPath / activeOplockAccessProcessCountForPath：
    // - Purpose: Query current Oplock hold and trigger counts for enabling/disabling and displaying in the right-click menu.
    bool hasActiveOplockForPath(const QString& filePath) const;
    std::size_t activeOplockCount() const;
    std::uint64_t activeOplockBreakCountForPath(const QString& filePath) const;
    std::size_t activeOplockAccessProcessCountForPath(const QString& filePath) const;

    // handleOplockCompleted：
    // - Purpose: Background wait thread notifies the UI that the Oplock has been accessed, triggering and accumulating the count.
    void handleOplockCompleted(
        std::shared_ptr<FileOplockEntry> entry,
        bool completionOk,
        unsigned long completionError,
        bool acknowledgeOk,
        unsigned long acknowledgeError,
        std::size_t capturedProcessCount);

    // handleOplockRearmPending：
    // - Purpose: Background wait thread notifies UI: triggers re-suspension of same-level Oplock (temporarily failed); thread continues retrying.
    void handleOplockRearmPending(std::shared_ptr<FileOplockEntry> entry, unsigned long requestError);

    // fileOplockLevelText / fileOplockControlCode：
    // - Purpose: Map menu selections to user-visible names and Windows FSCTL request codes.
    static QString fileOplockLevelText(FileOplockLevel level);
    static unsigned long fileOplockControlCode(FileOplockLevel level);

    // requestFileOplock / acknowledgeFileOplockBreak / cancelFileOplockRequest：
    // - Purpose: Encapsulates Oplock async request, break ACK, and manual cancellation, ensuring handles are closed only upon manual release in counting mode.
    static bool requestFileOplock(FileOplockEntry& entry, unsigned long& requestError);
    static bool acknowledgeFileOplockBreak(FileOplockEntry& entry, unsigned long& acknowledgeError);
    static void cancelFileOplockRequest(FileOplockEntry& entry);

    // recordFileOplockAccessPrograms：
    // - Purpose: Scan and record candidate processes accessing the target file after an Oplock is triggered.
    static std::size_t recordFileOplockAccessPrograms(FileOplockEntry& entry, std::uint64_t breakSequence);

    // unlockPathsByDriver：
    // - Purpose: Maintain compatibility with the legacy 'File Unlocker' entry point while unifying the handoff to the 'File Occupation and Unlock' tab in the properties window.
    // - This page provides handle closure, R3 process termination, and R0 process termination; no separate unlock window exists.
    // - Parameters triggerTag and panelForRefresh are retained for ABI compatibility; old callers do not need to fork.
    void unlockPathsByDriver(
        const std::vector<QString>& targetPaths,
        const QString& triggerTag,
        FilePanelWidgets* panelForRefresh);

    // showColumnManagerDialog：
    // - Purpose: Pop up the column manager to toggle column display states.
    void showColumnManagerDialog(FilePanelWidgets& panel);

    // showFileDetailDialog：
    // - Purpose: Open file detail dialog (multi-tab info display); initialTabKey can jump directly to the specified tab.
    void showFileDetailDialog(const QString& filePath, const QString& initialTabKey = QString());
    void showFileDetailDialog(const QStringList& filePaths, const QString& initialTabKey = QString());

    // openHandleUsageScanWindow：
    // - Purpose: Maintain compatibility with existing call sites to open the unified usage/unlock page within the properties window.
    // - No longer pop up a separate scan result window.
    // - Parameter scanPaths: Collection of paths to be scanned (files or directories).
    void openHandleUsageScanWindow(const std::vector<QString>& scanPaths);

    // openMappedProcessScanWindow：
    // - Purpose: Open the R0 Section/ControlArea 'mapped process' scan window based on selected files.
    // - Note: The first version only accepts files; directories are skipped. Failure reasons are displayed in the window status bar.
    // - Parameter scanPaths: Collection of file paths to be scanned.
    void openMappedProcessScanWindow(const std::vector<QString>& scanPaths);

    // ======================= Utility Functions ========================
    // currentIndexPath：
    // - Purpose: Get the absolute path corresponding to the currently selected index of the panel.
    // - Returns: An empty string if nothing is selected.
    QString currentIndexPath(const FilePanelWidgets& panel) const;

    // selectedPaths：
    // - Purpose: Retrieve the current multi-selected path list from the panel.
    std::vector<QString> selectedPaths(const FilePanelWidgets& panel) const;

    // formatSizeText：
    // - Purpose: Format byte size (B/KB/MB/GB).
    static QString formatSizeText(std::uint64_t sizeBytes);

    // ======================= File Recovery ========================
    // refreshRecoveryVolumeList：
    // - Purpose: Refresh the list of scannable volumes (NTFS volumes only).
    void refreshRecoveryVolumeList();

    // scanDeletedFilesForRecovery：
    // - Purpose: Scan NTFS deleted items on the current volume and display them in the table.
    void scanDeletedFilesForRecovery();

    // scanDeletedFilesForRecoveryAsync：
    // - Purpose: Asynchronously scan the current volume to avoid blocking the UI during undelete scans.
    void scanDeletedFilesForRecoveryAsync();

    // recoverSelectedDeletedFiles：
    // - Purpose: Perform recovery on selected deleted items (currently supports resident data recovery).
    void recoverSelectedDeletedFiles();

    // recoverSelectedDeletedFilesAsync：
    // - Purpose: Asynchronously recover selected deleted items to avoid blocking the UI during recovery.
    void recoverSelectedDeletedFilesAsync();

    // installRecoveryTableMenu：
    // - Purpose: Install a right-click menu for the deleted items table (copy row / file properties / restore selected).
    void installRecoveryTableMenu();

    // showDeletedFilePropertiesDialog：
    // - Purpose: Display full forensic attributes for a single deleted item (record number, sequence number, recoverability, etc.).
    // - Input parameter rowIndex: table row index; no dialog is shown if out of bounds.
    void showDeletedFilePropertiesDialog(int rowIndex);

    // applyRecoveryFilter：
    // - Purpose: Filter the deleted items table based on the search box content, supporting both substring and regex modes.
    // - Note: Only row visibility is changed; the cache order remains untouched, keeping row number mappings for right-click and restore entries valid.
    void applyRecoveryFilter();

    // updateRecoveryViewState：
    // - Purpose: Toggle between the 'empty state guide page' and the 'results table'.
    // - Input parameter hasResults: true displays the table, false displays the guide page.
    // - Parameter emptyHintText: Hint text displayed on the guide page.
    void updateRecoveryViewState(bool hasResults, const QString& emptyHintText);

private:
    // Root layout control.
    QVBoxLayout* rootLayout_ = nullptr;       // FileDock root layout.
    QTabWidget* rootTabWidget_ = nullptr;     // Vertical root tabs (File Management / File Recovery / IRP Construction).
    QWidget* fileManagerPage_ = nullptr;      // File manager page container.
    QWidget* fileRecoveryPage_ = nullptr;     // File recovery page container.
    QWidget* irpBuilderPage_ = nullptr;       // IRP builder page container.
    QSplitter* mainSplitter_ = nullptr;       // Left-right splitter.

    // Construct IRP page controls. Parameter fields must use text boxes, not spin boxes:
    // IRP parameters are commonly documented in WDK as hexadecimal constants; forcing decimal input
    // would require users to manually convert every time they fill in CreateOptions or IoControlCode.
    QLineEdit* irpPathEdit_ = nullptr;             // Target NT/Win32 path.
    QComboBox* irpOperationPresetCombo_ = nullptr; // Common operation presets; fill parameters only, do not auto-send.
    QComboBox* irpMajorCombo_ = nullptr;           // IRP_MJ_* selection.
    QLineEdit* irpMinorEdit_ = nullptr;            // IRP_MN_* value.
    QComboBox* irpLayerCombo_ = nullptr;           // Target stack layer.
    QLineEdit* irpDesiredAccessEdit_ = nullptr;    // CREATE：ACCESS_MASK。
    QLineEdit* irpShareAccessEdit_ = nullptr;      // CREATE: Share bit.
    QLineEdit* irpCreateDispositionEdit_ = nullptr;// CREATE: Disposition.
    QLineEdit* irpCreateOptionsEdit_ = nullptr;    // CREATE: Options bit.
    QLineEdit* irpFileAttributesEdit_ = nullptr;   // CREATE: File attributes.
    QLineEdit* irpInformationClassEdit_ = nullptr; // Various information classes / power states.
    QLineEdit* irpControlCodeEdit_ = nullptr;      // DEVICE_CONTROL / FSCTL control codes.
    QLineEdit* irpSecurityInformationEdit_ = nullptr; // SECURITY_INFORMATION。
    QLineEdit* irpByteOffsetEdit_ = nullptr;       // READ/WRITE/LOCK offset.
    QLineEdit* irpLockKeyEdit_ = nullptr;          // LOCK_CONTROL Key。
    QLineEdit* irpLockLengthEdit_ = nullptr;       // LOCK_CONTROL length.
    QLineEdit* irpOutputBytesEdit_ = nullptr;      // Expected output buffer length.
    QLineEdit* irpTimeoutEdit_ = nullptr;          // Wait timeout (milliseconds).
    QLineEdit* irpPatternEdit_ = nullptr;          // DIRECTORY_CONTROL wildcard.
    QPlainTextEdit* irpInputHexEdit_ = nullptr;    // Inline input data (hexadecimal).
    QCheckBox* irpConfirmCheck_ = nullptr;         // Write semantics confirmation.
    QCheckBox* irpAllowDangerousCheck_ = nullptr;  // Additional confirmation for dangerous PnP/Power major events.
    QCheckBox* irpCreateOnlyCheck_ = nullptr;      // Execute only CREATE.
    QCheckBox* irpRestartScanCheck_ = nullptr;     // SL_RESTART_SCAN。
    QCheckBox* irpSingleEntryCheck_ = nullptr;     // SL_RETURN_SINGLE_ENTRY。
    QCheckBox* irpReparseCheck_ = nullptr;         // FILE_OPEN_REPARSE_POINT。
    QCheckBox* irpDirectoryIntentCheck_ = nullptr; // FILE_DIRECTORY_FILE。
    QPushButton* irpSendButton_ = nullptr;         // Send button.
    QLabel* irpStatusLabel_ = nullptr;             // Result status summary.
    QTableWidget* irpResultTable_ = nullptr;       // Status and device stack information for each stage.
    QPlainTextEdit* irpOutputHexEdit_ = nullptr;   // Data written back by the target driver.
    bool irpSubmitInProgress_ = false;             // Whether the submission task is in progress.

    // File recovery page control.
    QComboBox* recoveryVolumeCombo_ = nullptr; // Recovery volume selection dropdown.
    QPushButton* recoveryRefreshButton_ = nullptr; // Refresh volume button.
    QPushButton* recoveryScanButton_ = nullptr;    // Scan button.
    QPushButton* recoveryExportButton_ = nullptr;  // Recovery export button.
    QTableWidget* recoveryTable_ = nullptr;        // Deletion result table.
    QLabel* recoveryStatusLabel_ = nullptr;        // Scan status label.
    QLineEdit* recoveryFilterEdit_ = nullptr;      // Result search input box.
    QToolButton* recoveryFilterRegexButton_ = nullptr; // Search regex toggle.
    QString recoveryBaseStatusText_;               // Scan statistics text without applied filter information.
    QStackedWidget* recoveryViewStack_ = nullptr;  // Results stack container (choose between boot page or results table).
    QWidget* recoveryEmptyPage_ = nullptr;         // Empty state guide page container.
    QPushButton* recoveryEmptyScanButton_ = nullptr; // Scan button in the center of the boot page.
    QLabel* recoveryEmptyHintLabel_ = nullptr;     // Boot page description text
    std::vector<ks::file::NtfsDeletedFileEntry> deletedRecoveryItems_; // Deleted items cache (including resident data).
    bool recoveryScanInProgress_ = false;          // Status of the background task for accidental deletion scanning.
    bool recoveryRecoverInProgress_ = false;       // Status of the background task for accidental deletion recovery.

    // Left and right panel instances.
    FilePanelWidgets leftPanel_;              // Left panel state.
    FilePanelWidgets rightPanel_;             // Right panel state.
    bool transferInProgress_ = false;         // Whether a background task is running during cross-panel copy/move.

    // File locker background thread status.
    std::thread unlockerWorkerThread_;
    std::atomic_bool unlockerWorkerStopRequested_{ false };
    std::atomic_bool unlockerWorkerRunning_{ false };
    mutable std::mutex unlockerWorkerMutex_;

    // Oplock hold state.
    std::vector<std::shared_ptr<FileOplockEntry>> activeOplocks_;
    mutable std::mutex activeOplockMutex_;
};
