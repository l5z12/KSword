#pragma once

// ============================================================
// DdmaPage.h
// Purpose:
// 1) Configure and manage DDMA (Direct Disk Memory Access) channels; this configuration is shared by the Memory
//    Search, Memory Viewer, Driver Memory Read/Write, and System Memory Audit sub-pages under the 'Memory' page.
// 2) Provides physical read/write entry points for DDMA itself.
// 3) Provide "standard channel vs. DDMA" same-location verification to detect physical pages redirected by SLAT.
//
// What is DDMA:
// - Enables the disk controller to use bus-master DMA to directly read/write arbitrary physical addresses. The data path
//   goes through the HBA without traversing the CPU page tables, so it is not constrained by SLAT/EPT and can access physical
//   pages that are redirected or hidden by upper-layer virtualization. Technical source: https://github.com/btbd/ddma.
//
// Cost (must always be clearly explained on the UI, never hidden):
// - Structurally requires borrowing a disk sector as a transit buffer; this page therefore mandates that the user
//   explicitly specify the temporary sector LBA and confirm it can be overwritten, providing no default values.
// - On machines with kernel debugging enabled, MiShowBadMapper may trigger a BSOD, in which case the entire channel is disabled.
// ============================================================

#include "MemoryAccessBackend.h"
// DdmaDiskEntry is stored by value in std::vector; the complete type must be available, not forward-declared.
#include "../../../shared/ark_client/ArkDriverClient.h"
// Pure arithmetic for temporary sector candidates resides in shared/evidence, Qt-free and Win32-free, with unit tests covering the same code.
#include "../../../shared/evidence/DdmaScratchPlan.h"
// The radix rules for addresses and sector numbers are also defined in shared/evidence; both sides share the same definition and are covered by exhaustive tests.
#include "../../../shared/evidence/NumericTextParse.h"

#include <QByteArray>
#include <QString>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

class QCheckBox;
class QEvent;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class HexEditorWidget;
class CodeEditorWidget;

namespace ks::ui
{
    class VisibleTableWidget;
}

class DdmaPage final : public QWidget
{
public:
    // Constructor:
    // - Purpose: Construct the DDMA page UI and set it to 'unconfigured' state;
    // - Parameter parent: Qt parent widget pointer, may be null.
    explicit DdmaPage(QWidget* parent = nullptr);

    // session：
    // - Purpose: Returns the current DDMA session configuration;
    // - Returns: const reference. This page is the sole writer for the process-level session, so this returns the written data.
    //   Local copy of the ksword::memory_backend instance; both are identical.
    const ksword::memory_backend::DdmaSession& session() const { return session_; }

    // setSessionChangedCallback：
    // - Purpose: Register a session change callback to refresh backend states of other pages in MemoryDock after configuration changes.
    // - Parameter callback: Parameterless callback, invoked on the main thread.
    void setSessionChangedCallback(std::function<void()> callback);

protected:
    // changeEvent：
    // - Purpose: Re-applies semantic color styles after a light/dark theme switch.
    // - Parameter event: Qt event object.
    void changeEvent(QEvent* event) override;

private:
    // ========================================================
    // UI construction
    // ========================================================

    // initializeUi: Constructs the root layout and four groups.
    void initializeUi();
    // buildIntroGroup: Constructs the top description block explaining what DDMA is and its costs.
    QGroupBox* buildIntroGroup();
    // buildChannelGroup: Builds the temporary sector input, confirmation checkbox, probe button, and disk table.
    QGroupBox* buildChannelGroup();
    // buildAccessGroup: Constructs the physical read/write entry point for DDMA itself.
    QGroupBox* buildAccessGroup();
    // buildCompareGroup: Constructs the 'Standard Channel vs DDMA' same-address verification entry.
    QGroupBox* buildCompareGroup();

    // applySemanticStyles：
    // - Purpose: Apply semantic colors to session status labels and high-risk buttons.
    // - Note: Semantic styles are a snapshot at the moment of invocation; construction and theme switching must follow the same path.
    void applySemanticStyles();

    // ========================================================
    // Interaction logic
    // ========================================================

    // parseScratchLbaFromUi：
    // - Purpose: Parse the scratch LBA input field.
    // - Parameter lbaOut: Output parsed result;
    // - Parameter errorTextOut: Reason for failure.
    // - Returns: true if the user entered a valid LBA. Empty input is treated as not entered
    //   and will not degenerate to 0—LBA 0 is the MBR sector and must not be selected by default.
    bool parseScratchLbaFromUi(std::uint64_t& lbaOut, QString& errorTextOut) const;

    // probeChannels：
    // - Purpose: enumerate \Driver\Disk devices and perform block-by-block ATA DMA read probes (when LBA is filled).
    // - Processing: Write results to disk table and refresh capability flags and session availability.
    void probeChannels();

    // ScratchDetection: complete result of a single candidate detection, including evidence text ready for display.
    struct ScratchDetection
    {
        bool ok = false;                // Whether available candidates have been calculated.
        std::uint64_t suggestedLba = 0; // Suggested LBA to fill in.
        QString sourceText;             // Candidate source: dedicated temporary file / unallocated gap.
        QString summaryText;            // User-facing conclusions and evidence.
        QString contextText;            // Sector context: ownership, offset, content preview.
        QString scratchFilePath;        // Temporary file path when using the file route; otherwise empty.
        bool contentAllZero = false;    // Whether the suggested range is currently all zeros.
    };

    // detectScratchByOwnedFile：
    // - Purpose: Create a dedicated scratch file within a selected volume on the disk and use its own clusters as the scratch area.
    // - Why not "pick a free cluster": Between reading the volume bitmap and the actual DMA operation,
    //   the system might allocate that cluster to a new file and write to it. Our "restore" would then
    //   overwrite the newly written file data with old content. By claiming the cluster first, this race
    //   condition is eliminated—the sectors belong to us, and any corruption affects only our own file.
    // - Processing: enumerate volumes → find those on this disk → create a file and persist it → retrieve
    //   pointers to get LCNs → convert to disk LBA using the volume start offset and cluster size.
    // - Returns: ok=true and scratchFilePath non-empty on success; summaryText explains reason on failure.
    ScratchDetection detectScratchByOwnedFile(
        std::uint32_t driveIndex,
        std::uint32_t sectorSize);

    // detectScratchCandidatesForSelectedDisk：
    // - Purpose: Read the partition table of the currently selected disk to calculate unallocated gaps suitable
    //   for use as a scratch area, and read back the actual content of the suggested interval as secondary evidence.
    // - Handling: The partition table only states 'Unallocated' without guaranteeing the space is truly empty—the disk
    //   header gap is where bootloaders reside. Therefore, the arithmetic logic is delegated to shared/evidence; this function
    //   only handles Win32 reading and verifies the single empirical evidence of 'whether the read-back data is all zeros'.
    // - Return: detection result; if failed, summaryText explains the step where it got stuck.
    ScratchDetection detectScratchCandidatesForSelectedDisk();

    // detectScratchCandidatesByGap：
    // - Fallback: When the dedicated scratch file path is unavailable, select candidates from unallocated gaps in the partition table;
    // - Note: A partition table marking a region as "Unallocated" only means no entry exists, not that
    //   the region is empty. Both hierarchical classification and content verification are required.
    ScratchDetection detectScratchCandidatesByGap(
        std::uint32_t driveIndex,
        const ksword::ark::DdmaDiskEntry& entry);

    // buildScratchContextText：
    // - Purpose: Generate context text describing "what this sector is now" for a candidate starting LBA;
    // - Content: target disk, coverage range, disk byte offset, **whether it falls within a partition
    //   or outside it**, whether current content is all zeros, and a hex preview of the first 128 bytes;
    // - Note: Always read and calculate on the fly without reusing intermediate values from the detection process.
    //   This is for user 're-confirmation' and must reflect the actual disk state at the moment the button is clicked.
    QString buildScratchContextText(
        std::uint32_t driveIndex,
        std::uint64_t startLba,
        std::uint32_t sectorSize,
        bool& allZeroOut);

    // detectScratchFromUi: Writes detection results to the LBA input box and displays evidence.
    // Deliberately **do not** check the confirmation box on behalf of the user: automatically calculating candidates is to save manual calculation, not to assume responsibility for them.
    void detectScratchFromUi();

    // physicalDriveIndexFromDeviceName：
    // - Input: device object names like \Device\Harddisk0\DR0
    // - Output: Disk index used to construct \\.\PhysicalDriveN;
    // - Return: Indicates parsing success or failure. If the name cannot be retrieved, do not guess; detection must fail.
    static bool physicalDriveIndexFromDeviceName(
        const std::wstring& deviceName,
        std::uint32_t& indexOut);

    // activateSelectedDisk：
    // - Purpose: Set the currently selected row in the disk table as the DDMA channel and persist it as a session configuration.
    void activateSelectedDisk();

    // clearSession：
    // - Purpose: Clear session configuration to immediately revert all pages to the standard channel.
    void clearSession();

    // refreshSessionState：
    // - Purpose: Recalculate session availability and refresh the status label based on current controls and detection results.
    // - Note: The sole availability criterion is in MemoryAccessBackend::isDdmaUsable;
    //   this function only displays the conclusion without re-implementing the criterion.
    void refreshSessionState();

    // readPhysicalFromUi: reads physical memory via DDMA using UI parameters and populates the hex view.
    void readPhysicalFromUi();

    // writePhysicalFromUi: writes back modified bytes from the hex view to physical memory via DDMA.
    void writePhysicalFromUi();

    // compareBackendsFromUi：
    // - Purpose: Read one page from the same physical address via both the standard channel and DDMA, then compare them byte-by-byte.
    // - Note: The inconsistency between the two is direct evidence that "this page has been redirected
    //   or hidden by SLAT"; this is the entire value proposition of DDMA relative to standard channels.
    void compareBackendsFromUi();

    // parseAddressText: Parses a physical address. Without a prefix, it is interpreted as hexadecimal; with a '0x' prefix, it is always hexadecimal.
    static bool parseAddressText(const QString& text, std::uint64_t& valueOut);
    // parseSectorNumberText: Parses sector LBA. LBA represents a count, not an address; values without a prefix are treated as decimal.
    static bool parseSectorNumberText(const QString& text, std::uint64_t& valueOut);
    // formatAddress: format as 16-bit hexadecimal text.
    static QString formatAddress(std::uint64_t address);

private:
    // ========================================================
    // Session and probe cache
    // ========================================================

    ksword::memory_backend::DdmaSession session_;      // Current session configuration.
    std::vector<ksword::ark::DdmaDiskEntry> diskCache_; // Disk detected in the most recent probe.
    bool probeCompleted_ = false;                      // Whether at least one successful probe has occurred.
    bool kernelDebuggerEnabled_ = false;               // Detected kernel debugger status.
    std::uint32_t transferBytes_ = 0;                  // Transfer length reported by R0.
    std::uint32_t scratchSectorCount_ = 0;             // R0 self-reported scratch sector count.
    std::function<void()> sessionChangedCallback_;     // Session change callback

    // ========================================================
    // Read/Write snapshot
    // ========================================================

    QByteArray originalBytes_;     // Original bytes read back, used to compare differences.
    QByteArray editedBytes_;       // Edit cache; on write-back, submit only the delta.
    std::uint64_t snapshotAddress_ = 0; // Snapshot start physical address.
    bool hasSnapshot_ = false;     // Whether a valid snapshot exists.

    // ========================================================
    // Control
    // ========================================================

    QLineEdit* scratchLbaEdit_ = nullptr;          // Scratch sector LBA input.
    QCheckBox* scratchAckCheck_ = nullptr;         // Override acknowledgment checkbox.
    QLabel* scratchImpactLabel_ = nullptr;         // Indicates which sectors will be overwritten by the real-time display.
    QPushButton* probeButton_ = nullptr;           // Probe button.
    QPushButton* detectScratchButton_ = nullptr;   // Detect candidate scratch sector button.
    QLabel* scratchDetectLabel_ = nullptr;         // Detection conclusion and evidence.
    // Sector context: Once the candidate is finalized, expand the current state of this sector to the user for confirmation.
    CodeEditorWidget* scratchContextView_ = nullptr;
    QString scratchFilePath_;                      // Current exclusive scratch file path; may be null.
    QPushButton* activateButton_ = nullptr;        // Activate channel button.
    QPushButton* clearButton_ = nullptr;           // Clear session button.
    ks::ui::VisibleTableWidget* diskTable_ = nullptr; // Disk table.
    QLabel* capabilityLabel_ = nullptr;            // Capability flag summary.
    QLabel* sessionStateLabel_ = nullptr;          // Session availability status.

    QLineEdit* accessAddressEdit_ = nullptr;       // Physical address input.
    QSpinBox* accessLengthSpin_ = nullptr;         // Read length.
    QPushButton* accessReadButton_ = nullptr;      // DDMA read button.
    QPushButton* accessWriteButton_ = nullptr;     // DDMA write-back button.
    HexEditorWidget* accessHexEditor_ = nullptr;   // Hex editor view.
    QLabel* accessStatusLabel_ = nullptr;          // Read/write status text.

    QLineEdit* compareAddressEdit_ = nullptr;      // Verify physical address input.
    QPushButton* compareButton_ = nullptr;         // Review button.
    QLabel* compareResultLabel_ = nullptr;         // Review conclusion.
    QTableWidget* compareTable_ = nullptr;         // Byte-by-byte difference details.
};
