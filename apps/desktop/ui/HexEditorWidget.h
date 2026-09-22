#pragma once

// ============================================================
// HexEditorWidget.h
// Purpose:
// - Provides a unified hex view/edit control.
// - Supports common tools such as search, jump, copy, and export.
// - Subsequent UIs displaying byte data should reuse this component.
// ============================================================

#include <QByteArray>
#include <QWidget>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

class QObject;
class QEvent;
class QPoint;
class QComboBox;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QShortcut;
class QTabWidget;
class QTableWidget;
class QTableWidgetItem;
class QToolButton;
class QWidget;
class QVBoxLayout;
class CodeEditorWidget;

// HexEditorWidget：
// - Unify the hex viewer.
// - Support both read-only and editable modes.
// - Supports Ctrl+F asynchronous search and Ctrl+G jump.
class HexEditorWidget final : public QWidget
{
    Q_OBJECT

public:
    // SearchMode：
    // - Define search mode;
    // - HexBytes supports the "AA BB ??" format.
    enum class SearchMode : int
    {
        kHexBytes = 0,
        kAsciiText,
        kUtf16Text
    };

    // Constructor:
    // - parent: Qt parent widget, may be null.
    explicit HexEditorWidget(QWidget* parent = nullptr);

    // Destructor:
    // - Only release Qt child widgets during component destruction.
    // - Asynchronous search threads use a ticket mechanism to automatically discard expired results.
    ~HexEditorWidget() override;

protected:
    // eventFilter：
    // - Purpose: Intercept mouse events on the hex table viewport.
    // - Implements text-based linear drag selection to avoid the default rectangular selection box.
    // Invocation: Automatically called back by the Qt event system.
    // Input watched: the object being monitored (primarily m_hexTable->viewport()).
    // Input parameter event: the event object.
    // Returns: true if the event was handled; false to pass it to the base class for further processing.
    bool eventFilter(QObject* watched, QEvent* event) override;

public:

    // setRegionData：
    // - Purpose: Set display data based on 'memory pointer + length'.
    // - regionPointer: Input memory region pointer, which may be nullptr.
    // - regionSize: Length of the input memory region (in bytes).
    // - baseAddress: the logical starting address of this region.
    void setRegionData(
        const void* regionPointer,
        std::size_t regionSize,
        std::uint64_t baseAddress = 0);

    // setByteArray：
    // - Purpose: Set display data directly from a QByteArray.
    // - bytes: input byte data;
    // - baseAddress: logical starting address.
    void setByteArray(const QByteArray& bytes, std::uint64_t baseAddress = 0);

    // clearData：
    // - Purpose: Clear byte data and search highlights in the component.
    void clearData();

    // setEditable：
    // - Purpose: Set whether editing of hexadecimal cells is allowed.
    // - editable: true = editable, false = read-only.
    void setEditable(bool editable);

    // isEditable：
    // - Returns whether currently editable.
    bool isEditable() const;

    // setBytesPerRow：
    // - Purpose: Set bytes per row (recommended: 8/16/32).
    // - bytesPerRow: number of bytes per row; invalid values are clamped.
    void setBytesPerRow(int bytesPerRow);

    // bytesPerRow：
    // - Returns the current bytes per row.
    int bytesPerRow() const;

    // jumpToAbsoluteAddress：
    // - Purpose: Jump to absolute address;
    // - absoluteAddress: target address
    // - Returns: true if the position is successfully located; false if out of range.
    bool jumpToAbsoluteAddress(std::uint64_t absoluteAddress);

    // jumpToOffset：
    // - Purpose: Navigate by 'relative offset';
    // - offset: Byte offset calculated from baseAddress.
    // - Returns: true if the position is successfully located; false if out of range.
    bool jumpToOffset(std::uint64_t offset);

    // jumpToRow：
    // - Purpose: Jump to target row;
    // - rowIndex: 0-based row index;
    // - Returns: true if the position is successfully located; false if out of range.
    bool jumpToRow(std::uint64_t rowIndex);

    // openFindPanel：
    // - Purpose: Display the find panel and focus the input field.
    void openFindPanel();

    // openJumpPanel：
    // - Purpose: Display the jump panel and focus the input field.
    void openJumpPanel();

    // setByteAtAbsoluteAddress：
    // - Purpose: Externally modify bytes at a specified address (e.g., rollback on write failure).
    // - absoluteAddress: absolute address
    // - byteValue: target byte value;
    // - keepSelection: whether to retain the current selection focus.
    // - Returns: true on success; false if the address is out of bounds.
    bool setByteAtAbsoluteAddress(
        std::uint64_t absoluteAddress,
        std::uint8_t byteValue,
        bool keepSelection = true);

    // data：
    // - Returns a copy of the data held by the current component.
    QByteArray data() const;

    // regionSize：
    // - Returns the current data length (in bytes).
    std::size_t regionSize() const;

    // baseAddress：
    // - Returns the current logical base address.
    std::uint64_t baseAddress() const;

    // selectedAbsoluteAddress：
    // - Returns the absolute address corresponding to the currently selected cell.
    // - Returns baseAddress when no valid bytes are selected.
    std::uint64_t selectedAbsoluteAddress() const;

    // selectedOffset：
    // - Returns the relative offset of the currently selected cell;
    // - Returns 0 when no valid bytes are selected.
    std::uint64_t selectedOffset() const;

    // selectedBytes：
    // - Purpose: Returns a copy of the bytes covered by the current selection for direct use by external components (e.g., memory search/write-back).
    // - Internally reuses selection collection logic, concatenates in ascending offset order; non-contiguous selections are compacted into continuous bytes.
    // - Return: A copy of the selected bytes; returns an empty QByteArray if no selection exists.
    QByteArray selectedBytes() const;

    // selectionRange：
    // - Purpose: Retrieve the half-open offset range of the current selection within the buffer for external absolute address conversion.
    // - Output parameter startOffsetOut: On a match, write the minimum offset of the selection range (inclusive).
    // - Output parameter endOffsetOut: on match, write the selection's maximum offset plus one (exclusive);
    // - Return: true if a selection exists; false otherwise, leaving both output parameters unchanged.
    bool selectionRange(std::uint64_t& startOffsetOut, std::uint64_t& endOffsetOut) const;

signals:
    // byteEdited：
    // - Purpose: Triggered after user edits a byte.
    // - absoluteAddress: the absolute address of the modified byte;
    // - oldValue: byte value before modification;
    // - newValue: the byte after modification.
    void byteEdited(
        std::uint64_t absoluteAddress,
        std::uint8_t oldValue,
        std::uint8_t newValue);

    // currentAddressChanged：
    // - Purpose: Triggered when the user switches the selected cell.
    void currentAddressChanged(std::uint64_t absoluteAddress);

    // selectionChanged：
    // - Purpose: Triggered when the selection changes to notify external components of the selected byte range.
    // - startOffset: minimum offset of the selection (inclusive); 0 if no selection.
    // - endOffset: one past the maximum offset of the selection (exclusive); 0 if no selection exists;
    // - hasSelection: true indicates a valid selection currently exists; false indicates the selection is empty.
    void selectionChanged(
        std::uint64_t startOffset,
        std::uint64_t endOffset,
        bool hasSelection);

    // aboutToShowContextMenu：
    // - Purpose: Allow external actions to be appended before the right-click context menu is shown.
    // - menu: the menu object about to be displayed;
    // - absoluteAddress: the target address for the current menu.
    // - hasByte: true indicates the target address contains valid bytes.
    void aboutToShowContextMenu(
        QMenu* menu,
        std::uint64_t absoluteAddress,
        bool hasByte);

private:
    // SearchPattern：
    // - Purpose: Describe the byte template after parsing the search pattern.
    struct SearchPattern
    {
        QByteArray patternBytes;
        QByteArray maskBytes;
        QString normalizeText;
    };

    // NavigateDirection：
    // - Purpose: Record how to automatically position the cursor after asynchronous search completion.
    enum class NavigateDirection : int
    {
        kNone = 0,
        kNext,
        kPrevious
    };

private:
    // initializeUi：
    // - Purpose: Create the main layout, toolbar, search panel, jump panel, and table.
    void initializeUi();

    // initializeConnections：
    // - Purpose: Connects editing, right-click, shortcuts, and tool buttons.
    void initializeConnections();

    // rebuildTable：
    // - Purpose: Rebuild the entire hex table based on the current content of m_buffer.
    void rebuildTable();

    // updateHeaderText：
    // - Purpose: Rebuild the header (address + byte column + ASCII).
    void updateHeaderText();

    // updateSummaryLabel：
    // - Purpose: Refresh the top summary text (length, base address, pattern).
    void updateSummaryLabel();

    // updateStatusLabel：
    // - Purpose: Refresh the bottom status text.
    void updateStatusLabel(const QString& statusText);

    // initializeSelectionInspector：
    // - Purpose: Create the bottom "Selection Inspector" panel.
    // - Display start/end addresses, HEX/ASCII/UTF-16, and integer interpretations.
    void initializeSelectionInspector();

    // updateSelectionInspector：
    // - Purpose: Refresh inspector text based on current selection.
    // - Falls back to displaying the current byte or placeholder content when no selection exists.
    void updateSelectionInspector();

    // buildSelectedByteArray：
    // - Purpose: Convert the current selection to a contiguous byte array for display.
    // - Output in ascending offset order for reuse by various preview formats.
    QByteArray buildSelectedByteArray() const;

    // formatSelectionHexPreview：
    // - Purpose: Format the selected bytes into a HEX preview string.
    // - Automatically truncates and adds ellipsis when too long.
    QString formatSelectionHexPreview(const QByteArray& selectedBytes) const;

    // formatSelectionAsciiPreview：
    // - Purpose: Format selected bytes into ASCII preview text.
    // - Display all non-printable characters uniformly as '.' without truncating the length.
    QString formatSelectionAsciiPreview(const QByteArray& selectedBytes) const;

    // formatSelectionUtf16Preview：
    // - Purpose: Attempt to decode the selected content as UTF-16LE.
    // - Display unavailable hint when length is less than two bytes.
    QString formatSelectionUtf16Preview(const QByteArray& selectedBytes) const;

    // formatSelectionIntegerPreview：
    // - Purpose: Interpret integers and floats based on the first 1, 2, 4, or 8 bytes.
    // - Facilitates quick judgment of whether the selection resembles a numeric field.
    QString formatSelectionIntegerPreview(const QByteArray& selectedBytes) const;

    // updateAsciiCellByRow：
    // - Purpose: Update the display of the ASCII column for the specified row.
    void updateAsciiCellByRow(int rowIndex);

    // refreshAsciiTabText：
    // - Purpose: Synchronize the complete ASCII text of the current buffer to the ASCII page editor.
    void refreshAsciiTabText();

    // updateRowHighlightByRow：
    // - Purpose: Refresh the background color of the specified row based on the search hit mask.
    void updateRowHighlightByRow(int rowIndex);

    // updateSelectionHighlightRange：
    // - Purpose: Refresh affected rows based on the union of the old and new selection ranges.
    // - Avoids rebuilding the entire table on every drag.
    void updateSelectionHighlightRange(
        bool oldRangeValid,
        std::uint64_t oldStartOffset,
        std::uint64_t oldEndOffset,
        bool newRangeValid,
        std::uint64_t newStartOffset,
        std::uint64_t newEndOffset);

    // parseAddressNumber：
    // - Purpose: Parse decimal or hexadecimal number text.
    bool parseAddressNumber(const QString& text, std::uint64_t& valueOut) const;

    // parseSearchPattern：
    // - Purpose: Parse input text into a matchable byte template according to the search mode.
    bool parseSearchPattern(
        SearchMode mode,
        const QString& text,
        SearchPattern& patternOut,
        QString& errorTextOut) const;

    // parseHexPattern：
    // - Purpose: Parse HEX pattern input (supports ?? wildcards).
    bool parseHexPattern(
        const QString& text,
        SearchPattern& patternOut,
        QString& errorTextOut) const;

    // parseAsciiPattern：
    // - Purpose: Parse ASCII/UTF-16 mode input.
    bool parseAsciiPattern(
        SearchMode mode,
        const QString& text,
        SearchPattern& patternOut,
        QString& errorTextOut) const;

    // ensureSearchResultReady：
    // - Purpose: Ensure the search result corresponding to the current input is available.
    // - direction: the navigation direction requested by the user.
    // - startOffset: Navigation start offset
    // - Returns: true = results are ready for use; false = asynchronous search has started.
    bool ensureSearchResultReady(
        NavigateDirection direction,
        std::uint64_t startOffset);

    // startSearchAsync：
    // - Purpose: Asynchronously scan the current buffer to avoid blocking the UI.
    void startSearchAsync(
        const SearchPattern& pattern,
        SearchMode mode,
        const QString& searchText,
        NavigateDirection direction,
        std::uint64_t startOffset);

    // applySearchResult：
    // - Purpose: Apply asynchronous search results and execute pending navigation.
    void applySearchResult(
        std::uint64_t ticket,
        const std::vector<std::uint64_t>& matchOffsets,
        int matchLength,
        SearchMode mode,
        const QString& searchText,
        const QString& normalizedText,
        std::uint64_t dataRevision);

    // clearSearchState：
    // - Purpose: Clear search cache and highlights.
    void clearSearchState();

    // gotoMatchByDirection：
    // - Purpose: Jump to the previous or next match item based on direction.
    void gotoMatchByDirection(
        NavigateDirection direction,
        std::uint64_t startOffset);

    // setCurrentMatchIndex：
    // - Purpose: Set the current match index and scroll/select.
    void setCurrentMatchIndex(int matchIndex);

    // selectRangeByOffset：
    // - Purpose: Select cells by offset range.
    void selectRangeByOffset(
        std::uint64_t offset,
        int length,
        bool scrollToCenter);

    // selectLinearRange：
    // - Purpose: Select bytes by 'text-style linear range'.
    // - Both selection start and end points are inclusive; maintains continuous byte semantics across lines.
    void selectLinearRange(
        std::uint64_t anchorOffset,
        std::uint64_t currentOffset,
        bool scrollToCurrent);

    // rowColumnToOffset：
    // - Purpose: Convert row/column to byte offset.
    // - Returns true if the cell corresponds to a valid byte.
    bool rowColumnToOffset(
        int row,
        int column,
        std::uint64_t& offsetOut) const;

    // offsetToRowColumn：
    // - Purpose: Convert byte offset to row/column.
    bool offsetToRowColumn(
        std::uint64_t offset,
        int& rowOut,
        int& columnOut) const;

    // viewportPosToOffset：
    // - Purpose: Map viewport coordinates to byte offset.
    // - Supports clamping out-of-bounds coordinates to maintain continuous selection when dragging to edges.
    bool viewportPosToOffset(
        const QPoint& viewportPos,
        std::uint64_t& offsetOut) const;

    // collectSelectedOffsets：
    // - Purpose: Collect all currently selected byte offsets.
    std::vector<std::uint64_t> collectSelectedOffsets() const;

    // copySelectedAsHex：
    // - Purpose: Copy the selected bytes as hexadecimal text.
    void copySelectedAsHex();

    // copySelectedAsAscii：
    // - Purpose: Copy selected bytes as ASCII text.
    void copySelectedAsAscii();

    // copyCurrentAddress：
    // - Purpose: Copy the current cell address.
    void copyCurrentAddress();

    // copyCurrentRowDump：
    // - Purpose: Copy the current row's 'Address + HEX + ASCII' text.
    void copyCurrentRowDump();

    // exportBinaryFile：
    // - Purpose: Export the current buffer as a binary file.
    void exportBinaryFile();

    // exportHexTextFile：
    // - Purpose: Export the current buffer as a hexadecimal text file.
    void exportHexTextFile();

    // exportSelectedHexDataFile：
    // - Purpose: Export the selected region as a plain HEX byte text file.
    void exportSelectedHexDataFile();

    // buildRowDumpText：
    // - Purpose: Construct dump text for a specified row.
    QString buildRowDumpText(int rowIndex) const;

    // buildFullDumpText：
    // - Purpose: Construct the dump text for all data.
    QString buildFullDumpText() const;

private:
    // m_rootLayout: Root layout.
    QVBoxLayout* rootLayout_ = nullptr;

    // m_toolbarLayout: The top toolbar area layout.
    QHBoxLayout* toolbarLayout_ = nullptr;

    // m_summaryLabel: Displays current data length, base address, and row width.
    QLabel* summaryLabel_ = nullptr;

    // m_bytesPerRowCombo: Bytes per row selection box.
    QComboBox* bytesPerRowCombo_ = nullptr;

    // m_findButton: Open find panel button.
    QToolButton* findButton_ = nullptr;

    // m_jumpButton: Jump panel open button.
    QToolButton* jumpButton_ = nullptr;

    // m_exportButton: Export button.
    QToolButton* exportButton_ = nullptr;

    // m_findPanel: Find panel container.
    QWidget* findPanel_ = nullptr;

    // m_findLayout: Find panel layout.
    QHBoxLayout* findLayout_ = nullptr;

    // m_findModeCombo: Find mode combo box.
    QComboBox* findModeCombo_ = nullptr;

    // m_findEdit: Find input box.
    QLineEdit* findEdit_ = nullptr;

    // m_findPrevButton: Find Previous button.
    QToolButton* findPrevButton_ = nullptr;

    // m_findNextButton: Find Next button.
    QToolButton* findNextButton_ = nullptr;

    // m_findCloseButton: Button to close the find panel.
    QToolButton* findCloseButton_ = nullptr;

    // m_findResultLabel: Displays the find result statistics.
    QLabel* findResultLabel_ = nullptr;

    // m_jumpPanel: Container for the jump panel.
    QWidget* jumpPanel_ = nullptr;

    // m_jumpLayout: Jump panel layout.
    QHBoxLayout* jumpLayout_ = nullptr;

    // m_jumpModeCombo: Jump mode (absolute address/offset/line number).
    QComboBox* jumpModeCombo_ = nullptr;

    // m_jumpEdit: Jump input box.
    QLineEdit* jumpEdit_ = nullptr;

    // m_jumpApplyButton: Jump execution button.
    QToolButton* jumpApplyButton_ = nullptr;

    // m_jumpCloseButton: Button to close the jump panel.
    QToolButton* jumpCloseButton_ = nullptr;

    // m_viewTabWidget: Main view area Tab (HEX / ASCII).
    QTabWidget* viewTabWidget_ = nullptr;

    // m_hexViewPage: HEX page container.
    QWidget* hexViewPage_ = nullptr;

    // m_asciiViewPage: ASCII page container.
    QWidget* asciiViewPage_ = nullptr;

    // m_asciiEditor: Built-in read-only text editor used for the ASCII page.
    CodeEditorWidget* asciiEditor_ = nullptr;

    // m_hexTable: Hexadecimal data table (located on the HEX page).
    QTableWidget* hexTable_ = nullptr;

    // m_selectionInspectorPanel: Bottom selection inspector container.
    QWidget* selectionInspectorPanel_ = nullptr;

    // m_selectionInspectorLayout: Selection inspector layout.
    QGridLayout* selectionInspectorLayout_ = nullptr;

    // m_selectionSummaryLabel: Displays summary information such as selection start/end addresses and length.
    QLabel* selectionSummaryLabel_ = nullptr;

    // m_selectionHexPreviewLabel: Displays HEX preview text.
    QLabel* selectionHexPreviewLabel_ = nullptr;

    // m_selectionAsciiPreviewLabel: Displays ASCII preview text.
    QLabel* selectionAsciiPreviewLabel_ = nullptr;

    // m_selectionUtf16PreviewLabel: Displays UTF-16 preview text.
    QLabel* selectionUtf16PreviewLabel_ = nullptr;

    // m_selectionIntegerPreviewLabel: Displays integer/float interpretation text.
    QLabel* selectionIntegerPreviewLabel_ = nullptr;

    // m_statusLabel: Bottom status text.
    QLabel* statusLabel_ = nullptr;

    // m_findShortcut: Ctrl+F shortcut.
    QShortcut* findShortcut_ = nullptr;

    // m_jumpShortcut: Ctrl+G shortcut.
    QShortcut* jumpShortcut_ = nullptr;

    // m_findNextShortcut: F3 shortcut.
    QShortcut* findNextShortcut_ = nullptr;

    // m_findPrevShortcut: Shift+F3 shortcut.
    QShortcut* findPrevShortcut_ = nullptr;

    // m_copyHexShortcut: Ctrl+C to copy HEX.
    QShortcut* copyHexShortcut_ = nullptr;

    // m_copyAsciiShortcut: Ctrl+Shift+C to copy ASCII.
    QShortcut* copyAsciiShortcut_ = nullptr;

    // m_buffer: Current displayed data copy.
    QByteArray buffer_;

    // m_baseAddress: Current data base address.
    std::uint64_t baseAddress_ = 0;

    // m_editable: Whether byte editing is currently allowed.
    bool editable_ = false;

    // m_bytesPerRow: Current number of bytes per row.
    int bytesPerRow_ = 16;

    // m_ignoreItemChanged: Prevent triggering edit logic during internal program backfill.
    bool ignoreItemChanged_ = false;

    // m_matchMask: Search highlight mask (1 = byte match).
    QByteArray matchMask_;

    // m_matchOffsets: List of starting offsets for found matches.
    std::vector<std::uint64_t> matchOffsets_;

    // m_currentMatchIndex: Current match index; -1 indicates no match.
    int currentMatchIndex_ = -1;

    // m_currentMatchLength: Current match length (bytes).
    int currentMatchLength_ = 0;

    // m_lastSearchMode: Last search mode.
    SearchMode lastSearchMode_ = SearchMode::kHexBytes;

    // m_lastSearchText: The original input from the last search.
    QString lastSearchText_;

    // m_lastSearchNormalizeText: Last search normalized display text.
    QString lastSearchNormalizeText_;

    // m_bufferRevision: Data version number (incremented when data changes).
    std::uint64_t bufferRevision_ = 0;

    // m_searchReadyRevision: Data version corresponding to search results.
    std::uint64_t searchReadyRevision_ = 0;

    // m_searchTicket: Asynchronous search ticket (used to discard stale results).
    std::atomic<std::uint64_t> searchTicket_{ 0 };

    // m_searchRunning: Whether an asynchronous search is currently in progress.
    bool searchRunning_ = false;

    // m_pendingDirection: Navigation direction to execute after search completion.
    NavigateDirection pendingDirection_ = NavigateDirection::kNone;

    // m_pendingStartOffset: Starting offset for navigation to be executed after search completion.
    std::uint64_t pendingStartOffset_ = 0;

    // m_linearSelectDragging：
    // - Purpose: Mark whether the left mouse button drag selection process is currently active.
    bool linearSelectDragging_ = false;

    // m_linearSelectAnchorOffset：
    // - Purpose: Record the offset for text-based drag-selection anchors.
    std::uint64_t linearSelectAnchorOffset_ = 0;

    // m_linearSelectAnchorValid：
    // - Purpose: Mark whether the anchor offset is valid.
    bool linearSelectAnchorValid_ = false;

    // m_selectionVisualAsciiColumn：
    // - Purpose: Marks whether the current linear selection targets the ASCII column for visual highlighting.
    // - When true, only the ASCII column displays multi-line selections; when false, the hex byte column displays them.
    bool selectionVisualAsciiColumn_ = false;

    // m_selectionRangeValid：
    // - Purpose: Marks whether a custom linear selection range currently exists.
    // - The selection range is always stored as a 'byte offset interval' to facilitate reuse of copy/parse logic.
    bool selectionRangeValid_ = false;

    // m_selectionRangeStartOffset：
    // - Purpose: Record the current selection start offset (inclusive).
    std::uint64_t selectionRangeStartOffset_ = 0;

    // m_selectionRangeEndOffset：
    // - Purpose: Record the current selection end offset (inclusive).
    std::uint64_t selectionRangeEndOffset_ = 0;
};
