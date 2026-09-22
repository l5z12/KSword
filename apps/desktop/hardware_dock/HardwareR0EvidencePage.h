#pragma once

// ============================================================
// HardwareR0EvidencePage.h
// Purpose:
// 1) Adds a read-only R0 hardware evidence page in the Hardware Dock.
// 2) Reuse the existing Kernel CPU Integrity protocol via ArkDriverClient;
// 3) Display R0 entry evidence for per-CPU control registers, MSRs, IDT/GDT/IDTR/GDTR, etc.
// ============================================================

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <atomic>   // std::atomic_bool/std::atomic_uint64_t: Used for asynchronous query mutual exclusion and tickets.
#include <cstdint>  // std::uint32_t/std::uint64_t: protocol fields and address display.
#include <vector>   // std::vector: Stores the R0 evidence cache.

class CodeEditorWidget;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QVBoxLayout;

// HardwareR0EvidencePage:
// - Input: Qt parent control;
// - Processing: Only query R0 CPU/IDT evidence asynchronously via ArkDriverClient, without directly calling DeviceIoControl.
// - Returns: this control has no business return value; query results are displayed directly in the table and detail editor.
class HardwareR0EvidencePage final : public QWidget
{
public:
    // Constructor:
    // - parent: Qt parent control;
    // - Processing: initialize UI, bind controls, and delay-start a single R0 evidence refresh.
    explicit HardwareR0EvidencePage(QWidget* parent = nullptr);

    // Destructor:
    // - Does not hold a raw thread handle.
    // - QRunnable callbacks use QPointer to prevent access after object destruction.
    ~HardwareR0EvidencePage() override = default;

private:
    // initializeUi:
    // - Inputs: None;
    // - Processing: Create the toolbar, evidence table, and details area;
    // - Returns: Nothing.
    void initializeUi();

    // initializeConnections:
    // - Inputs: None;
    // - Processing: Connection refresh, filtering, risk screening, and table selection events;
    // - Returns: Nothing.
    void initializeConnections();

    // refreshEvidenceAsync:
    // - Input: forceRefresh indicates a user-initiated refresh;
    // - Processing: background query for R0 capability, DynData capability, and CPU integrity evidence;
    // - Returns: None; results are populated into the UI via a queued connection.
    void refreshEvidenceAsync(bool forceRefresh);

    // applyEvidenceQueryResults:
    // - Atomically replace R0 capabilities, DynData, and CPU evidence cache by ticket;
    // - When the table menu opens, defer loading the entire result set to ensure the UserRole cache index remains valid.
    void applyEvidenceQueryResults(
        std::uint64_t ticket,
        ksword::ark::DriverCapabilitiesQueryResult capabilityResult,
        ksword::ark::DynDataCapabilitiesResult dynDataResult,
        ksword::ark::DriverIntegrityResult integrityResult);

    // rebuildEvidenceTable:
    // - Input: None; reads m_evidenceCache and filter controls.
    // - Processing: Rebuild table display without accessing the driver.
    // - Returns: Nothing.
    void rebuildEvidenceTable();

    // showSelectedEvidenceDetail:
    // - Input: None; reads the currently selected row in the table;
    // - Handling: Map back from UserRole to the evidence cache and populate the detail editor.
    // - Returns: Nothing.
    void showSelectedEvidenceDetail();

    // setStatusText:
    // - Input: status text and color;
    // - Processing: Uniformly refresh status label styles.
    // - Returns: Nothing.
    void setStatusText(const QString& text, const QString& colorText);

private:
    QVBoxLayout* rootLayout_ = nullptr;       // m_rootLayout: Page root layout.
    QPushButton* refreshButton_ = nullptr;    // m_refreshButton: Refresh R0 evidence button.
    QCheckBox* riskOnlyCheck_ = nullptr;      // m_riskOnlyCheck: Show only riskFlags with non-zero values.
    QLineEdit* filterEdit_ = nullptr;         // m_filterEdit: Local filter for owner/detail/risk/class text.
    QSpinBox* maxRowsSpin_ = nullptr;         // m_maxRowsSpin: Maximum evidence rows per batch.
    QSpinBox* idtVectorsSpin_ = nullptr;      // m_idtVectorsSpin: Number of IDT vectors expanded per CPU.
    QLabel* statusLabel_ = nullptr;           // m_statusLabel: Displays R0 query status summary.
    QTableWidget* evidenceTable_ = nullptr;   // m_evidenceTable: CPU/MSR/IDT/GDT evidence table.
    CodeEditorWidget* detailEditor_ = nullptr;// m_detailEditor: Evidence detail text editor.

    ksword::ark::DriverCapabilitiesQueryResult lastCapabilityResult_; // m_lastCapabilityResult: Snapshot of the most recent driver capabilities.
    ksword::ark::DynDataCapabilitiesResult lastDynDataResult_; // m_lastDynDataResult: Most recent DynData capability snapshot.
    ksword::ark::DriverIntegrityResult lastIntegrityResult_; // m_lastIntegrityResult: Summary of the most recent full response.
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> evidenceCache_; // m_evidenceCache: Cache for the most recent R0 evidence row.
    std::atomic_bool refreshing_{ false };    // m_refreshing: Prevent concurrent refresh.
    std::atomic<std::uint64_t> refreshTicket_{ 0 }; // m_refreshTicket: Discard expired background results.
};
