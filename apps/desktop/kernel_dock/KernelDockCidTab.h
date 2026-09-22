#pragma once

// ============================================================
// KernelDockCidTab.h
// Purpose:
// 1) Provide read-only CID / cross-view aggregation pages;
// 2) Merge process and thread cross-view results, displaying public walk / CID / Active / ThreadList evidence;
// 3) R3 read-only display only; no fixes, hiding, unlinking, or write operations.
// ============================================================

#include "../Framework.h"

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QPoint>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class CodeEditorWidget;
class QHBoxLayout;

class KernelDockCidTab final : public QWidget
{
public:
    explicit KernelDockCidTab(QWidget* parent = nullptr);
    ~KernelDockCidTab() override = default;

private:
    // CidTableSummary：
    // - Purpose: Cache the summary of the enumCidTable response header;
    // - Input: Populated by the refresh thread from ArkDriverClient::enumCidTable;
    // - Output: Status bar and details area display PspCidTable, count, truncation, and access budget.
    struct CidTableSummary
    {
        bool queried = false;                       // queried: Whether enumCidTable has been called in this round.
        bool ok = false;                            // ok: Whether transmission and protocol parsing succeeded.
        bool unsupported = false;                   // unsupported: true for old drivers or when a handler is missing.
        std::uint32_t status = 0;                   // status: R0 CID enumeration semantic status.
        std::uint32_t totalCount = 0;               // totalCount: Total number of CID entries observed by R0.
        std::uint32_t returnedCount = 0;            // returnedCount: Number of CID rows returned by R0 to R3.
        std::uint32_t visitedCount = 0;             // visitedCount: Number of entries actually accessed in R0.
        std::uint32_t maxVisitCount = 0;            // maxVisitCount: R0 visit budget for this session.
        std::uint32_t flags = 0;                    // flags: R0 response flags, retaining truncation/policy information.
        long lastStatus = 0;                        // lastStatus: Most recent NTSTATUS in R0.
        std::uint64_t pspCidTableAddress = 0;       // pspCidTableAddress: address of PspCidTable.
        std::uint64_t dynDataCapabilityMask = 0;    // dynDataCapabilityMask: DynData capability bits.
        std::uint32_t htTableCodeOffset = 0;        // htTableCodeOffset: offset of HandleTable.TableCode.
        std::uint32_t hteLowValueOffset = 0;        // hteLowValueOffset: offset of HandleTableEntry.LowValue.
        QString messageText;                        // messageText: ArkDriverClient diagnostic information.
    };

    struct CidEvidenceRow
    {
        bool isRawCid = false;
        bool isThread = false;
        std::uint32_t cidValue = 0;
        std::uint32_t cidHandleIndex = 0;
        std::uint32_t cidExpectedKind = 0;
        std::uint32_t cidEntryFlags = 0;
        long cidReferenceStatus = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t processObjectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t activeListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        std::uint32_t publicThreadId = 0;
        std::uint32_t threadListThreadId = 0;
        std::uint32_t cidTableThreadId = 0;
        std::uint32_t threadListProcessId = 0;
        long publicWalkStatus = 0;
        long activeListStatus = 0;
        long cidTableStatus = 0;
        long threadListStatus = 0;
        long startAddressStatus = 0;
        QString imageNameText;
        QString detailText;
    };

    // initializeUi：
    // - Create the toolbar, table, and details panel;
    // - Remains read-only during initial construction; refreshes are driven by a background thread.
    void initializeUi();

    // initializeConnections：
    // - Binds refresh, filtering, and detail linkage;
    // - All operations only update the local display, without triggering the write path.
    void initializeConnections();

    // refreshAsync：
    // - Background query for process/thread cross-view.
    // - Populate the table and detail panel upon success.
    void refreshAsync();

    // applyRefreshResult：
    // - Input rows/errorText/success: refresh result.
    // - Processing: restore button states and rebuild the table.
    void applyRefreshResult(std::vector<CidEvidenceRow> rows, const QString& errorText, bool success);

    // rebuildTable：
    // - Rebuilds the result table based on the filter keyword;
    // - Read-only display; editing or operations are not allowed.
    void rebuildTable();

    // showContextMenu：
    // - Show copy menu;
    // - Does not provide any delete/repair/unlink buttons.
    void showContextMenu(const QPoint& localPosition);

    // copyCurrentRow：
    // - Copy the current row to the clipboard.
    // - Fields use tab separation for easy pasting into logs or spreadsheets.
    void copyCurrentRow() const;

    // selectedRow：
    // - Returns the currently selected row.
    // - Returns nullptr when no row is selected or the index is out of bounds.
    const CidEvidenceRow* selectedRow() const;

    // buildDetailText：
    // - Generates detail text for the current row;
    // - Pure formatting only, no driver IOCTLs involved; [KernelObjectSummary] section is filled by background tasks.
    QString buildDetailText(const CidEvidenceRow* row) const;

    // scheduleDetailRefresh：
    // - Input: None; directly reads the currently selected row;
    // - Processing: Immediately render local details and push the R0 object summary request into a 150ms debounce window.
    // - Returns: None. Simultaneously increments generation to invalidate all in-flight callbacks.
    void scheduleDetailRefresh();

    // requestKernelObjectSummaryAsync：
    // - Input: None; generates targetKind/cidValue/objectAddress based on the currently selected row;
    // - Processing: Execute queryKernelObjectSummary in QThreadPool and validate generation upon callback.
    // - Returns: none. The UI is only touched within the callback slot.
    void requestKernelObjectSummaryAsync();

    // appendKernelObjectSummaryText：
    // - Input summaryText: [KernelObjectSummary] segment pre-formatted by the background thread.
    // - Processing: Append to local detail text and write to the detail panel.
    // - Returns: Nothing.
    void appendKernelObjectSummaryText(const QString& summaryText);

    // buildDiagnosticDetailText：
    // - Input: diagnostic reason for current empty table or empty filter match;
    // - Processing: Expand the CID table summary, filter keywords, and driver messages into detailed text;
    // - Return: Read-only description directly displayable in CodeEditorWidget.
    QString buildDiagnosticDetailText(const QString& reasonText) const;

    // insertDiagnosticRow：
    // - Input: table short title, status column text, and detail text;
    // - Processing: Write a copyable diagnostic placeholder row to the current table.
    // - Returns: No return value; diagnostic details are stored in UserRole for reading by the detail area.
    void insertDiagnosticRow(const QString& titleText, const QString& statusText, const QString& detailText);

    // rowMatchesFilter：
    // - Filter by text keyword.
    // - Filter fields cover type, PID/TID, address, status, and detail summary.
    bool rowMatchesFilter(const CidEvidenceRow& row) const;

    static QTableWidgetItem* readOnlyItem(const QString& text);
    static QString formatHex32(std::uint32_t value);
    static QString formatHex64(std::uint64_t value);
    static QString statusLabelText(long statusValue);
    static QString sourceMaskText(std::uint32_t mask);
    static QString anomalyFlagsText(std::uint32_t flags);
    static QString denoiseFlagsText(std::uint32_t flags);
    static QString detailStatusText(std::uint32_t status);
    static QString roleText(bool isThread);
    static QString cidKindText(std::uint32_t kind);
    static QString cidEntryFlagsText(std::uint32_t flags);
    static QString cidEnumStatusText(std::uint32_t status);
    static QString objectSummaryStatusText(std::uint32_t status);
    static QString objectHeaderStatusText(std::uint32_t status);
    static QString fixedWideText(const wchar_t* text, std::size_t maxChars);
    static bool cidSummaryTruncated(const CidTableSummary& summary);

    // formatKernelObjectSummaryText：
    // - Input summary: Pure value type result returned by queryKernelObjectSummary;
    // - Processing: Perform only string formatting; safe to execute on background threads.
    // - Returns: text appended to the details panel section.
    static QString formatKernelObjectSummaryText(const ksword::ark::KernelObjectSummaryAuditResult& summary);

private:
    QHBoxLayout* toolbarLayout_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    CodeEditorWidget* detailEditor_ = nullptr;
    QTimer* detailRequestTimer_ = nullptr;     // detailRequestTimer: Debounce timer for R0 object summary requests.

    std::atomic_bool refreshing_{ false };
    CidTableSummary cidSummary_;
    std::vector<CidEvidenceRow> rows_;
    QString detailBaseText_;                   // detailBaseText: Local detail text for the current row; append the summary after it during rollback.
    std::uint64_t detailGeneration_ = 0;       // detailGeneration: Re-injects old summaries discarded when a new row is selected.
};
