#pragma once

#include <QDialog>
#include <QString>

#include <array>
#include <cstdint>

class CodeEditorWidget;
class QLabel;
class QPushButton;
class QCheckBox;
class QTableWidget;

namespace ksword::ark
{
    struct DriverImageControlResult;
    struct DriverImageValues;
}

// DriverObject/KLDR image metadata and PsLoadedModuleList advanced transaction editor.
// The UI only warns of risks and obtains explicit confirmation, without imposing restrictions based on target category, product identity, or request values.
class KernelDriverImageEditorDialog final : public QDialog
{
public:
    explicit KernelDriverImageEditorDialog(
        const QString& driverObjectName,
        QWidget* parent = nullptr);

private:
    // initializeUi: Constructs an opaque dialog, a five-field table, a details editor, and a high-risk action bar.
    void initializeUi();
    // refreshSnapshot: First determine the DriverObject identity, then query the R0 transaction/load chain lock snapshot.
    void refreshSnapshot();
    // queryTransaction: Refresh the transaction based on established identity, with an option to overwrite user target values.
    bool queryTransaction(
        ksword::ark::DriverImageControlResult& resultOut,
        bool resetDesiredValues);
    // applySelectedFields: Parse target values of checked rows and submit a five-field atomic CAS request.
    void applySelectedFields();
    // hideFromLoadedModuleList: unlink resources within the resource lock using the latest Flink/Blink snapshot.
    void hideFromLoadedModuleList();
    // restoreManagedState: Restore checked fields and decide whether to re-insert the load chain based on checkbox states.
    void restoreManagedState();
    // abandonRecoveryRecord: Maintain the current dangerous state and permanently discard the R0 recovery record.
    void abandonRecoveryRecord();

    // applyResultToView: Project the complete response to the table, details, and action availability status.
    void applyResultToView(
        const ksword::ark::DriverImageControlResult& result,
        bool resetDesiredValues);
    // updateDetails: Displays address, chain, mask, generation, and status bits using CodeEditorWidget.
    void updateDetails(
        const ksword::ark::DriverImageControlResult& result);
    // setActionsEnabled: uniformly controls transaction buttons to prevent requests before identity is established.
    void setActionsEnabled(bool querySucceeded, bool recordPresent);
    // setStatus: Updates the copyable status text and semantic color.
    void setStatus(const QString& text, const QString& colorHex);

    // selectedFieldMask: Reads table checkboxes and generates the shared protocol fieldMask.
    std::uint32_t selectedFieldMask() const;
    // parseDesiredValues: Parses target columns from the table; only checks 32-bit width for natural ULONG fields.
    bool parseDesiredValues(
        ksword::ark::DriverImageValues& valuesOut,
        QString& errorOut) const;
    // confirmDanger: After warning, require input of an action phrase to confirm without changing the target or value.
    bool confirmDanger(
        const QString& warningText,
        const QString& phrase) const;

    // fieldValue / setFieldValue: access the five-field model by fixed row index.
    static std::uint64_t fieldValue(
        const ksword::ark::DriverImageValues& values,
        int row);
    static void setFieldValue(
        ksword::ark::DriverImageValues& values,
        int row,
        std::uint64_t value);
    static QString pointerText(std::uint64_t address);
    static QString ntStatusText(long status);
    static bool parseUnsigned64(
        const QString& text,
        std::uint64_t& valueOut);

    QString requestedDriverName_;              // Original name selected by the user from the object directory.
    QString canonicalDriverName_;              // Canonical DriverObject name returned by R0.
    QLabel* riskLabel_ = nullptr;              // Permanently visible high-risk explanation.
    QLabel* identityLabel_ = nullptr;          // DriverObject/module identity summary.
    QLabel* statusLabel_ = nullptr;            // Current action and NTSTATUS.
    QTableWidget* table_ = nullptr;            // Five-field current/target/transaction detail table.
    CodeEditorWidget* detailEditor_ = nullptr; // Complete chain and transaction evidence, read-only.
    QCheckBox* restoreLinkCheckBox_ = nullptr; // Whether to reload the load chain during restoration.
    QPushButton* refreshButton_ = nullptr;     // Refresh identity and transaction snapshot.
    QPushButton* applyButton_ = nullptr;       // Atomic application checkbox fields.
    QPushButton* hideButton_ = nullptr;        // Unlink from PsLoadedModuleList.
    QPushButton* restoreButton_ = nullptr;     // Restore field/load chain.
    QPushButton* abandonButton_ = nullptr;     // Abandon recovery record.

    std::uint64_t moduleBase_ = 0;             // Initial identity module base address.
    std::uint64_t driverObjectAddress_ = 0;    // Precise DriverObject address.
    std::uint64_t currentLinkFlink_ = 0;       // Flink of the most recently queried load chain.
    std::uint64_t currentLinkBlink_ = 0;       // Blink of the loaded chain from the most recent query.
    std::array<std::uint64_t, 5> currentValues_{}; // Atomic snapshot of the last five fields.
    std::uint32_t generation_ = 0;             // Current transaction generation.
    std::uint32_t responseFlags_ = 0;          // Chain and record status bits.
    std::uint32_t managedFieldMask_ = 0;       // Current managed field mask.
};
