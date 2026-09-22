#pragma once

// ============================================================
// DiskEditorTab.h
// Purpose:
// 1) Provide a physical disk view and sector editing page similar to DiskGenius;
// 2) Display a user-friendly horizontal bar partition map, partition table, sector HEX editor, and operation logs.
// 3) Write operations default to 'read-only/unlock/secondary confirmation/sector alignment' protection to prevent accidental operations.
// ============================================================

#include "DiskAdvancedModels.h"
#include "DiskEditorModels.h"

#include "../../Framework.h"

#include <QByteArray>
#include <QWidget>

#include <cstdint>
#include <vector>

class QCheckBox;
class QComboBox;
class QGroupBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QSplitter;
class QTabWidget;
class QTableWidget;
class QVBoxLayout;
class HexEditorWidget;

namespace ks::misc
{
    class DiskMapWidget;

    // DiskEditorTab:
    // - Input: User-selected physical disk, offset, and read length;
    // - Processing logic: enumerate disks in the background, render the layout on the main thread, and read/write as needed.
    // - Return behavior: no business return value; all results are displayed in the UI and logs.
    class DiskEditorTab final : public QWidget
    {
    public:
        // Constructor:
        // - parent is the Qt parent widget;
        // - Asynchronously enumerate disks after initializing the UI.
        explicit DiskEditorTab(QWidget* parent = nullptr);

        // Destructor:
        // - Background rollback uses QPointer.
        // - No need to manually wait for the thread.
        ~DiskEditorTab() override = default;

    private:
        // initializeUi：
        // - Create the top toolbar, partition view, sector editor area, and log area;
        // - No input parameters or return value.
        void initializeUi();

        // initializeToolbar：
        // - Create disk selection, refresh, jump, and read/write protection buttons;
        // - No input parameters or return value.
        void initializeToolbar();

        // initializeLayoutPanels：
        // - Creates the bar chart, partition table, HEX editor, side details, and log.
        // - No input parameters or return value.
        void initializeLayoutPanels();

        // initializeAdvancedPanels：
        // - Create tabs for structure parsing, volume mapping, health information, search, and imaging tools.
        // - parent is the parent widget hosting the advanced panel.
        // - No return value.
        void initializeAdvancedPanels(QWidget* parent);

        // initializeConnections：
        // - Connect UI signals to page actions;
        // - No input parameters or return value.
        void initializeConnections();

        // refreshDiskListAsync：
        // - enumerate physical disks in the background.
        // - forceRefresh indicates a user-initiated refresh;
        // - No return value; updates the main thread after completion.
        void refreshDiskListAsync(bool forceRefresh);

        // applyDiskList：
        // - Apply background enumeration results.
        // - disks: disk list
        // - errorText is for failure diagnostics;
        // - No return value.
        void applyDiskList(std::vector<DiskDeviceInfo> disks, const QString& errorText);

        // currentDisk：
        // - Get the currently selected disk.
        // - Returns the disk pointer; returns nullptr if no disk is selected.
        const DiskDeviceInfo* currentDisk() const;

        // currentPartition：
        // - Get the currently selected partition or unallocated block.
        // - Returns the partition pointer; returns nullptr if none is selected.
        const DiskPartitionInfo* currentPartition() const;

        // updateDiskSummary：
        // - Refresh the disk summary card.
        // - No input parameters or return value.
        void updateDiskSummary();

        // rebuildPartitionTable：
        // - Rebuild partition table based on the current disk;
        // - No input parameters or return value.
        void rebuildPartitionTable();

        // rebuildVolumeHints：
        // - Fills in the partition table and partition detail hints using the latest volume mapping results.
        // - No input parameters or return value.
        void rebuildVolumeHints();

        // syncPartitionSelection：
        // - Synchronizes the table, bar chart, offset input box, and details;
        // - partitionIndex corresponds to DiskPartitionInfo::tableIndex.
        // - focusHex indicates whether to immediately read the starting sector of the partition.
        // - No return value.
        void syncPartitionSelection(int partitionIndex, bool focusHex);

        // readCurrentRangeAsync：
        // - Read bytes based on the current disk, offset, and length.
        // - reasonText is the log description;
        // - No return value.
        void readCurrentRangeAsync(const QString& reasonText);

        // applyReadResult：
        // - Apply background read results to the HEX editor;
        // - baseOffset is the read offset;
        // - bytes: data read.
        // - errorText being null indicates success;
        // - No return value.
        void applyReadResult(std::uint64_t baseOffset, const QByteArray& bytes, const QString& errorText);

        // writeCurrentBuffer：
        // - Write the current HEX buffer back to disk;
        // - Perform internal validation and require user confirmation.
        // - No return value.
        void writeCurrentBuffer();

        // refreshStructureReportAsync：
        // - Read the leading sectors in the background and parse MBR/GPT/boot sectors/volume mappings/health information;
        // - reasonText is the log description;
        // - No return value.
        void refreshStructureReportAsync(const QString& reasonText);

        // applyStructureReport：
        // - Apply the structure parsing report to the advanced page table;
        // - report: parsing result.
        // - errorText being null indicates success;
        // - No return value.
        void applyStructureReport(DiskStructureReport report, const QString& errorText);

        // rebuildStructureTable：
        // - Rebuild the structure fields table using m_structureReport.fields;
        // - No input parameters or return value.
        void rebuildStructureTable();

        // rebuildVolumeTable：
        // - Rebuild the volume mapping table using m_structureReport.volumes;
        // - No input parameters or return value.
        void rebuildVolumeTable();

        // rebuildHealthTable：
        // - Rebuilds the device capabilities/health table using m_structureReport.healthItems;
        // - No input parameters or return value.
        void rebuildHealthTable();

        // rebuildRawBackendSelector：
        // - Rebuild the three-layer access dropdown based on the current disk R0 pre-check result.
        // - Unavailable layers are not added to the list to prevent the UI from claiming a backend that does not exist.
        void rebuildRawBackendSelector();

        // currentRawBackend：
        // - Returns the currently explicitly selected R0 disk backend.
        // - If nothing is selected, revert to the Windows storage stack backend.
        unsigned long currentRawBackend() const;

        // runSearchAsync：
        // - Perform disk range search based on tool area input.
        // - No input parameters or return value.
        void runSearchAsync();

        // runHashAsync：
        // - Calculate range hashes based on tool area inputs;
        // - No input parameters or return value.
        void runHashAsync();

        // runExportAsync：
        // - Export disk image fragments based on tool area input.
        // - No input parameters or return value.
        void runExportAsync();

        // runImportAsync：
        // - Import files from the tool area to the disk.
        // - Execute read-only protection and WRITE confirmation before writing;
        // - No return value.
        void runImportAsync();

        // runCompareAsync：
        // - Compare disk ranges and files based on tool area input.
        // - No input parameters or return value.
        void runCompareAsync();

        // runScanAsync：
        // - Performs a quick read scan based on the tool area input;
        // - No input parameters or return value.
        void runScanAsync();

        // applyRangeTaskResult：
        // - Apply results from search, hash, export, import, compare, and read-scan tasks.
        // - taskName: task name;
        // - result is the background result;
        // - No return value.
        void applyRangeTaskResult(const QString& taskName, DiskRangeTaskResult result);

        // updateToolRangeFromSelection：
        // - Synchronize the current partition or read range to the tool area's offset/length.
        // - when usePartitionRange=true, prefer the full range of the current partition;
        // - No return value.
        void updateToolRangeFromSelection(bool usePartitionRange);

        // browseToolFile：
        // - Open the file selection dialog and fill in the tool file path;
        // - When saveMode=true, select a save path; otherwise, select an existing file.
        // - No return value.
        void browseToolFile(bool saveMode);

        // parseToolRange：
        // - Parse tool region offset/length;
        // - offsetOut/lengthOut receive the results.
        // - Returns true if parsing was successful.
        bool parseToolRange(std::uint64_t& offsetOut, std::uint64_t& lengthOut) const;

        // updateDirtyState：
        // - Set whether the current buffer has unsaved modifications.
        // - dirty is the target state.
        // - No return value.
        void updateDirtyState(bool dirty);

        // appendLog：
        // - Write to the right-side operation log.
        // - message is the log body;
        // - No return value.
        void appendLog(const QString& message);

        // severityText：
        // - Convert structure/health severity to Chinese text.
        // - severity is the input severity level;
        // - Returns display text.
        static QString severityText(DiskStructureSeverity severity);

        // parseAddressText：
        // - Parses decimal or 0x hexadecimal addresses.
        // - text: input text
        // - valueOut is the output value;
        // - Returns true if parsing was successful.
        static bool parseAddressText(const QString& text, std::uint64_t& valueOut);

        // setControlsEnabledForBusy：
        // - Enable/disable buttons based on background task status;
        // - When busy is true, it indicates that a read/write/refresh operation is in progress.
        // - No return value.
        void setControlsEnabledForBusy(bool busy);

    private:
        QVBoxLayout* rootLayout_ = nullptr;        // m_rootLayout: Page root layout.
        QWidget* toolbarWidget_ = nullptr;         // m_toolbarWidget: The top toolbar container.
        QHBoxLayout* toolbarLayout_ = nullptr;     // m_toolbarLayout: The top toolbar layout.
        QComboBox* diskCombo_ = nullptr;           // m_diskCombo: Physical disk selection box.
        QComboBox* backendCombo_ = nullptr;        // m_backendCombo: R0 disk access backend selection box (three-layer).
        QPushButton* refreshButton_ = nullptr;     // m_refreshButton: Refresh disk list button.
        QPushButton* readButton_ = nullptr;        // m_readButton: Read current range button.
        QPushButton* writeButton_ = nullptr;       // m_writeButton: Button to write back the current buffer.
        QPushButton* partitionStartButton_ = nullptr; // m_partitionStartButton: Jump to the start of the current partition.
        QLineEdit* offsetEdit_ = nullptr;          // m_offsetEdit: Read start offset.
        QSpinBox* lengthSpin_ = nullptr;           // m_lengthSpin: Read length.
        QCheckBox* readOnlyCheck_ = nullptr;       // m_readOnlyCheck: Read-only protection switch.
        QCheckBox* requireAlignedCheck_ = nullptr; // m_requireAlignedCheck: Write sector alignment protection.
        QLabel* statusLabel_ = nullptr;            // m_statusLabel: Page status summary.

        DiskMapWidget* diskMapWidget_ = nullptr;   // m_diskMapWidget: Horizontal bar partition chart.
        QSplitter* mainSplitter_ = nullptr;        // m_mainSplitter: Splitter for the left layout and right log details.
        QTableWidget* partitionTable_ = nullptr;   // m_partitionTable: Partition list.
        HexEditorWidget* hexEditor_ = nullptr;     // m_hexEditor: Sector HEX viewer/editor.
        QTabWidget* advancedTabs_ = nullptr;        // m_advancedTabs: Collection of advanced analysis and tool tabs.
        QTableWidget* structureTable_ = nullptr;    // m_structureTable: MBR/GPT/boot sector parsing table.
        QTableWidget* volumeTable_ = nullptr;       // m_volumeTable: Volume and drive letter mapping table.
        QTableWidget* healthTable_ = nullptr;       // m_healthTable: Device capabilities/health table.
        QTableWidget* searchResultTable_ = nullptr; // m_searchResultTable: Sector search result table.
        QPushButton* analyzeButton_ = nullptr;      // m_analyzeButton: Button to refresh structure parsing.
        QPushButton* toolUseSelectionButton_ = nullptr; // m_toolUseSelectionButton: Button to use the current read range.
        QPushButton* toolUsePartitionButton_ = nullptr; // m_toolUsePartitionButton: Button to use the current partition range.
        QPushButton* toolBrowseOpenButton_ = nullptr; // m_toolBrowseOpenButton: Button to select the input file.
        QPushButton* toolBrowseSaveButton_ = nullptr; // m_toolBrowseSaveButton: Button to select the output file.
        QPushButton* searchButton_ = nullptr;       // m_searchButton: Range search button.
        QPushButton* hashButton_ = nullptr;         // m_hashButton: Range hash button.
        QPushButton* exportButton_ = nullptr;       // m_exportButton: Image export button.
        QPushButton* importButton_ = nullptr;       // m_importButton: Image import button.
        QPushButton* compareButton_ = nullptr;      // m_compareButton: File comparison button.
        QPushButton* scanButton_ = nullptr;         // m_scanButton: Read scan button.
        QLineEdit* toolOffsetEdit_ = nullptr;       // m_toolOffsetEdit: Advanced tool start offset.
        QLineEdit* toolLengthEdit_ = nullptr;       // m_toolLengthEdit: Advanced tool length.
        QLineEdit* searchPatternEdit_ = nullptr;    // m_searchPatternEdit: Search pattern input.
        QLineEdit* toolFileEdit_ = nullptr;         // m_toolFileEdit: Path to the image/compare file.
        QComboBox* searchModeCombo_ = nullptr;      // m_searchModeCombo: Search mode.
        QComboBox* hashAlgorithmCombo_ = nullptr;   // m_hashAlgorithmCombo: Hash algorithm.
        QSpinBox* maxResultSpin_ = nullptr;         // m_maxResultSpin: Maximum number of search/diff results.
        QSpinBox* scanBlockSpin_ = nullptr;         // m_scanBlockSpin: Read scan block size.
        QLabel* diskSummaryLabel_ = nullptr;       // m_diskSummaryLabel: Disk summary text.
        QLabel* partitionDetailLabel_ = nullptr;   // m_partitionDetailLabel: Current partition details.
        QPlainTextEdit* logEdit_ = nullptr;        // m_logEdit: Operation log.

        std::vector<DiskDeviceInfo> disks_;        // m_disks: Current disk enumeration cache.
        DiskStructureReport structureReport_;      // m_structureReport: Advanced structure/volume/health report.
        QByteArray loadedBytes_;                   // m_loadedBytes: Recently read raw buffer.
        std::uint64_t loadedBaseOffset_ = 0;       // m_loadedBaseOffset: Disk offset corresponding to the HEX buffer.
        int selectedPartitionIndex_ = -1;          // m_selectedPartitionIndex: Current partition index.
        bool busy_ = false;                        // m_busy: Background task mutex flag.
        bool dirty_ = false;                       // m_dirty: Whether the current HEX buffer has been modified.
    };
}
