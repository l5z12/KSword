#pragma once

// ============================================================
// DumpMemoryView.h
// Purpose:
// - Provides a read-only memory viewer for dump files by virtual address;
// - Only use DumpMemoryRange validated during the parsing phase; do not guess content for uncaught addresses.
// - Reopen the original DMP as read-only during reading, and verify file size/modification
//   time to avoid interpreting a replaced file at the same path as an old parse result.
// Call method:
// - MinidumpDock::renderResult calls setDumpData(result) after successful parsing.
// - Allows users to input virtual addresses or 'module name + offset' to browse via read, previous page, and next page.
// ============================================================

#include <QWidget>

#include <cstdint>
#include <vector>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTextBrowser;
class HexEditorWidget;

namespace ks::minidump
{
    struct DumpMemoryRange;
    struct DumpParseResult;
    struct MemoryRegionEntry;
    struct ModuleEntry;
}

// DumpMemoryView: Read-only browsing page for virtual memory captured in the dump.
class DumpMemoryView final : public QWidget
{
public:
    // Constructor purpose: create address input, pagination toolbar, description area, and unified hexadecimal controls.
    explicit DumpMemoryView(QWidget* parent = nullptr);

    // setDumpData: Replaces the currently dumped verified memory range and sets a default address.
    // Parameter result: the parser's self-contained result; this object only copies lightweight metadata and does not retain file mappings.
    void setDumpData(const ks::minidump::DumpParseResult& result);

    // clearData: Removes the current dump association to prevent previous results from persisting on the new analysis page.
    void clearData();

    // retranslateUi purpose: Update fixed text according to the current language while keeping loaded bytes unchanged.
    void retranslateUi();

private:
    // readAddressText purpose: Parse user input for 'address' or 'module name + offset'.
    // Returns true when writing to addressOut; module name matches case-insensitively against full path and base filename.
    bool readAddressText(const QString& text, std::uint64_t* addressOut) const;

    // findRangeIndex: Locates the index of the capture range covering the address; returns -1 if not found.
    int findRangeIndex(std::uint64_t address) const;

    // findPreferredInitialAddress purpose: Selects a captured range containing valid bytes for the initial open.
    // Preserve fault address priority first; otherwise, read-only sample each range to avoid defaulting to all-zero pages, which
    // could mislead users into thinking the viewer failed to read. If no non-zero bytes are found, fall back to the first range.
    std::uint64_t findPreferredInitialAddress() const;

    // loadCurrentInput purpose: Read address input box content and display result in the hex control.
    void loadCurrentInput();

    // loadAddress: Reads up to 64 KiB of contiguous bytes from the verified range.
    // Retain the error reason on read failure; never display partial or out-of-bounds data.
    bool loadAddress(std::uint64_t address);

    // goPreviousPage / goNextPage: Page through the current or adjacent capture range by read size.
    void goPreviousPage();
    void goNextPage();

    // selectedReadBytes: reads the single read length selected by the user, capped at 64 KiB.
    std::uint64_t selectedReadBytes() const;

    // setMessage: Updates the copyable status text.
    void setMessage(const QString& text);

    // formatHex: Uniformly renders addresses/file offsets as uppercase hexadecimal with a 0x prefix.
    static QString formatHex(std::uint64_t value);

    // m_addressLabel/m_addressEdit: Target virtual address or module name + offset input.
    QLabel* addressLabel_ = nullptr;
    QLineEdit* addressEdit_ = nullptr;
    QLabel* readSizeLabel_ = nullptr;
    QComboBox* readSizeCombo_ = nullptr;
    QPushButton* readButton_ = nullptr;
    QPushButton* previousButton_ = nullptr;
    QPushButton* nextButton_ = nullptr;
    QTextBrowser* messageView_ = nullptr; // m_messageView: Readable status and mapping description (copyable).
    HexEditorWidget* hexEditor_ = nullptr; // m_hexEditor: Read-only hex editor with find, copy, and export controls.

    QString filePath_;                 // m_filePath: The original DMP path during parsing.
    std::uint64_t expectedFileSize_ = 0; // m_expectedFileSize: File size during parsing.
    std::int64_t expectedFileLastModifiedUtcMs_ = -1; // UTC modification timestamp during parsing.
    std::vector<ks::minidump::DumpMemoryRange> ranges_; // m_ranges: Readable ranges sorted by virtual address.
    std::vector<ks::minidump::ModuleEntry> modules_; // m_modules: Module name + offset input and ownership hints.
    std::vector<ks::minidump::MemoryRegionEntry> memoryRegions_; // m_memoryRegions: Address attribute hint.
    std::uint64_t currentAddress_ = 0; // m_currentAddress: Current page start address.
    std::uint64_t currentReadBytes_ = 0; // m_currentReadBytes: The actual number of bytes loaded for the current page.
    int currentRangeIndex_ = -1;       // m_currentRangeIndex: The capture range to which the current page belongs.
};
