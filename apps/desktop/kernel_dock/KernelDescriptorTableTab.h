#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"
#include "KernelCleanImageBaseline.h"

#include <QString>
#include <QWidget>

#include <cstddef>
#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTextEdit;

// KernelDescriptorTableKind：
// - Purpose: Specify whether the descriptor sub-page displays only the IDT or only the GDT.
// - Usage: Create two separate instances in the I/O Management tab to avoid having a table type dropdown within sub-tabs.
enum class KernelDescriptorTableKind
{
    kIdt,
    kGdt
};

// KernelDescriptorTableTab: Displays per-CPU IDT or GDT as a read-only R0 CPU snapshot.
// The IDT page displays handler module ownership; the GDT page expands segment/TSS bitfields.
class KernelDescriptorTableTab final : public QWidget
{
public:
    // Constructor:
    // - Input tableKind: fixed descriptor type to display; parent: Qt parent widget;
    // - Processing: Create a dedicated table for the corresponding IDT/GDT and asynchronously refresh it upon first display.
    // - Returns: no explicit return value.
    explicit KernelDescriptorTableTab(
        KernelDescriptorTableKind tableKind,
        QWidget* parent = nullptr);
    ~KernelDescriptorTableTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyResult(
        ksword::ark::DriverIntegrityResult result,
        std::vector<ks::kernel::TrustedIdtBaselineResult>
            trustedIdtBaselines);
    void rebuildTable();
    void showCurrentDetail();
    void restoreSelectedIdtBaseline();
    void showCopyMenu(const QPoint& position);
    bool rowMatchesFilter(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        std::size_t sourceIndex) const;
    QString columnText(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        int column,
        std::size_t sourceIndex) const;
    QString detailText(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        std::size_t sourceIndex) const;
    static QString tableName(const ksword::ark::DriverIntegrityEvidenceEntry& row);
    static QString descriptorTypeText(const ksword::ark::DriverIntegrityEvidenceEntry& row);
    static QString riskText(std::uint32_t riskFlags);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    KernelDescriptorTableKind tableKind_; // m_tableKind: Current instance fixed to display IDT or GDT.
    QLineEdit* filterEdit_ = nullptr;      // m_filterEdit: Keyword filter for the current type entry.
    QPushButton* refreshButton_ = nullptr; // m_refreshButton: Re-reads the current descriptor table.
    QPushButton* restoreIdtButton_ = nullptr; // m_restoreIdtButton: Boot-time baseline restore button created only on the IDT page.
    QLabel* statusLabel_ = nullptr;        // m_statusLabel: Asynchronously query status and item count.
    QTableWidget* table_ = nullptr;        // m_table: descriptor structured result table.
    QTextEdit* detailEdit_ = nullptr;      // m_detailEdit: Read-only diagnostic details for the current table entry.
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> rows_; // m_rows: R0 snapshot for the current type.
    std::vector<ks::kernel::TrustedIdtBaselineResult> trustedIdtBaselines_; // m_trustedIdtBaselines: Trusted image/PDB expected handler evidence aligned with IDT entries.
    bool refreshRunning_ = false;          // m_refreshRunning: Prevents duplicate concurrent queries.
    bool firstRefreshStarted_ = false;     // m_firstRefreshStarted: Flag for initial automatic refresh.
};
