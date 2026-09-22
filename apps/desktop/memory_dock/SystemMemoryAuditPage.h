#pragma once

// ============================================================
// SystemMemoryAuditPage.h
// Purpose:
// 1) Audit actual resident physical memory from a system-wide perspective, rather than merely listing ordinary processes
// 2) Simultaneously display process private resident pages, kernel pool tags, Big Pool, and page list chains;
// 3) Clearly display physical memory remainder that cannot be uniquely attributed by stable snapshot interfaces.
// ============================================================

#include "MemoryAccessBackend.h"

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

class QCheckBox;
class QEvent;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTimer;
class QTreeWidget;

class SystemMemoryAuditPage final : public QWidget
{
public:
    explicit SystemMemoryAuditPage(QWidget* parent = nullptr);

    // refreshSnapshot: Re-collect the full system memory snapshot and refresh all audit views.
    void refreshSnapshot();

    // setDdmaSessionProvider：
    // - Purpose: Inject DDMA session read entry point so the "DDMA Cross-Check" button on this page can retrieve the current channel configuration.
    // - Parameter provider: A value-returning function returning a const reference, registered by MemoryDock after DDMA page construction.
    // - Note: This page does not hold or modify DDMA configuration; it is read-only. The verification entry remains disabled if not registered.
    void setDdmaSessionProvider(
        std::function<const ksword::memory_backend::DdmaSession&()> provider);

    // refreshDdmaCrossCheckState：
    // - Purpose: Refresh the enabled state and tooltip of the review entry based on current session availability.
    // - Note: DDMA sessions are maintained by other pages. A session change must trigger a callback here; otherwise, a
    //   button that will inevitably fail upon clicking will remain. Therefore, this is a public external refresh entry point.
    void refreshDdmaCrossCheckState();

protected:
    void changeEvent(QEvent* event) override;

private:
    struct ProcessRow
    {
        std::uint64_t identity = 0;
        std::uint32_t pid = 0;
        std::uint32_t sessionId = 0;
        QString name;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t workingSetBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t privateCommitBytes = 0;
        std::uint64_t pagedPoolQuotaBytes = 0;
        std::uint64_t nonPagedPoolQuotaBytes = 0;
        std::uint32_t hardFaultCount = 0;
        std::int64_t privateResidentDeltaBytes = 0;
    };

    struct PoolTagRow
    {
        std::uint32_t tag = 0;
        QString tagText;
        std::uint64_t pagedBytes = 0;
        std::uint64_t nonPagedBytes = 0;
        std::uint64_t pagedOutstanding = 0;
        std::uint64_t nonPagedOutstanding = 0;
        std::int64_t totalDeltaBytes = 0;
    };

    struct BigPoolRow
    {
        std::uint64_t identity = 0;
        std::uint64_t virtualAddress = 0;
        std::uint64_t sizeBytes = 0;
        std::uint32_t tag = 0;
        QString tagText;
        bool nonPaged = false;
        std::int64_t sizeDeltaBytes = 0;
    };

    struct TagMetadata
    {
        QString source;
        QString description;
    };

    enum class UserMemoryKind : std::uint8_t
    {
        kPrivate,
        kImage,
        kMappedFile,
        kPagefileSection,
        kUnknown
    };

    struct UserResidencyRow
    {
        std::uint32_t pid = 0;
        QString processName;
        UserMemoryKind kind = UserMemoryKind::kUnknown;
        QString backingPath;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t shareableResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
    };

    struct UserResidencyScan
    {
        QString sampledAt;
        QStringList errors;
        std::uint32_t processCount = 0;
        std::uint32_t accessibleProcessCount = 0;
        std::uint32_t inaccessibleProcessCount = 0;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
        std::vector<UserResidencyRow> rows;
    };

    struct SnapshotError
    {
        QString sourceText;
        QString argument;
    };

    struct Snapshot
    {
        QString sampledAt;
        QStringList errors;
        std::vector<SnapshotError> pendingErrors;
        std::uint64_t pageSize = 4096;

        std::uint64_t installedPhysicalBytes = 0;
        std::uint64_t hardwareReservedBytes = 0;
        std::uint64_t totalPhysicalBytes = 0;
        std::uint64_t availableBytes = 0;
        std::uint64_t residentAvailableBytes = 0;
        std::uint64_t inUseBytes = 0;
        std::uint64_t committedBytes = 0;
        std::uint64_t commitLimitBytes = 0;
        std::uint64_t peakCommitmentBytes = 0;
        std::uint64_t sharedCommittedBytes = 0;

        bool memoryListAvailable = false;
        std::uint64_t zeroBytes = 0;
        std::uint64_t freeBytes = 0;
        std::uint64_t modifiedBytes = 0;
        std::uint64_t modifiedNoWriteBytes = 0;
        std::uint64_t modifiedPageFileBytes = 0;
        std::uint64_t badBytes = 0;
        std::array<std::uint64_t, 8> standbyBytes{};
        std::array<std::uint64_t, 8> repurposedBytes{};

        bool performanceAvailable = false;
        std::uint64_t pagedPoolCommittedBytes = 0;
        std::uint64_t nonPagedPoolBytes = 0;
        std::uint64_t pagedPoolResidentBytes = 0;
        std::uint64_t systemCodeResidentBytes = 0;
        std::uint64_t systemDriverResidentBytes = 0;
        std::uint64_t systemCacheResidentBytes = 0;
        std::uint64_t mdlAllocatedBytes = 0;
        std::uint64_t pfnDatabaseCommittedBytes = 0;
        std::uint64_t systemPageTableCommittedBytes = 0;
        std::uint64_t contiguousAllocatedBytes = 0;
        std::uint64_t broadSystemCacheBytes = 0;

        std::uint64_t processPrivateResidentBytes = 0;
        std::uint64_t processWorkingSetReferenceBytes = 0;
        std::uint64_t processSharedResidentReferenceBytes = 0;
        std::uint64_t processPrivateCommitBytes = 0;
        std::uint64_t processPagedPoolQuotaBytes = 0;
        std::uint64_t processNonPagedPoolQuotaBytes = 0;
        std::vector<ProcessRow> processes;

        std::uint64_t poolTagPagedBytes = 0;
        std::uint64_t poolTagNonPagedBytes = 0;
        std::vector<PoolTagRow> poolTags;
        std::vector<BigPoolRow> bigPool;

        std::uint64_t identifiedResidentLowerBoundBytes = 0;
        std::uint64_t unattributedResidentBytes = 0;
    };

    void initializeUi();
    void initializeConnections();
    void retranslateUi();
    // applyThemedStyle: Centrally dispatch styles dependent on theme tokens (summary card shells, card titles, and values).
    // Called once during construction; called again when changeEvent receives a palette change.
    void applyThemedStyle();
    // updateSummaryTiles: Writes the current snapshot's numeric values into the 6 summary tiles.
    void updateSummaryTiles();
    void scheduleCurrentDetailViewRebuild();
    void rebuildCurrentDetailView();
    void applySnapshot(Snapshot snapshot, std::uint64_t ticket);
    void startUserResidencyScan();
    void applyUserResidencyScan(UserResidencyScan scan, std::uint64_t ticket);
    void rebuildOverview();
    void rebuildUserResidencyTable();
    void rebuildProcessTable();
    void rebuildPoolTagTable();
    void rebuildBigPoolTable();
    void updateDetails();
    void updateStatus();
    void loadPoolTagMetadata();

    // runDdmaCrossCheck：
    // - Purpose: For a given physical page, read one page via both the standard channel and DDMA, then compare byte-by-byte;
    // - Handling logic: If reading fails on either side, only report "unable to compare" without concluding consistency or inconsistency;
    // - Note: The inconsistency between the two is direct evidence that "this page was redirected or hidden by SLAT,"
    //   which is precisely the second perspective needed for the "unattributable resident memory" column on this page.
    void runDdmaCrossCheck();

    static Snapshot collectSnapshot();
    static UserResidencyScan collectUserResidency(const std::vector<ProcessRow>& processes, std::uint64_t pageSize);
    static QString formatBytes(std::uint64_t bytes);
    static QString formatDelta(std::int64_t bytes);
    static QString formatPercent(std::uint64_t bytes, std::uint64_t totalBytes);

private:
    QPushButton* refreshButton_ = nullptr;
    QPushButton* userResidencyScanButton_ = nullptr;
    QCheckBox* autoRefreshCheck_ = nullptr;
    QSpinBox* intervalSpin_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* totalLabel_ = nullptr;
    QLabel* installedLabel_ = nullptr;
    QLabel* inUseLabel_ = nullptr;
    QLabel* availableLabel_ = nullptr;
    QLabel* commitLabel_ = nullptr;
    QLabel* unattributedLabel_ = nullptr;
    QTabWidget* detailTabs_ = nullptr;
    QTreeWidget* overviewTree_ = nullptr;
    QTableWidget* userResidencyTable_ = nullptr;
    QTableWidget* processTable_ = nullptr;
    QTableWidget* poolTagTable_ = nullptr;
    QTableWidget* bigPoolTable_ = nullptr;
    QPlainTextEdit* detailText_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTimer* autoRefreshTimer_ = nullptr;

    // DDMA cross-check entry point. This page only reads DDMA sessions; configuration remains on the DDMA sub-page.
    QLineEdit* ddmaCrossCheckAddressEdit_ = nullptr;
    QPushButton* ddmaCrossCheckButton_ = nullptr;
    QLabel* ddmaCrossCheckResultLabel_ = nullptr;
    std::function<const ksword::memory_backend::DdmaSession&()> ddmaSessionProvider_;

    Snapshot snapshot_;
    UserResidencyScan userResidencyScan_;
    bool hasSnapshot_ = false;
    bool refreshing_ = false;
    bool startUserResidencyScanAfterSnapshot_ = false;
    bool detailViewRebuildScheduled_ = false;
    bool overviewDirty_ = true;
    bool userResidencyTableDirty_ = true;
    bool processTableDirty_ = true;
    bool poolTagTableDirty_ = true;
    bool bigPoolTableDirty_ = true;
    QHash<std::uint64_t, std::uint64_t> previousProcessPrivateBytes_;
    QHash<std::uint32_t, std::uint64_t> previousPoolTagBytes_;
    QHash<std::uint64_t, std::uint64_t> previousBigPoolBytes_;
    QHash<QString, std::uint64_t> previousSummaryBytes_;
    QHash<QString, std::int64_t> summaryDeltaBytes_;
    QHash<std::uint32_t, TagMetadata> poolTagMetadata_;
    QString poolTagMetadataSource_;
    QString lastSnapshotWarningSignature_;
    std::atomic<std::uint64_t> snapshotRefreshTicket_{ 0 };
    std::atomic<std::uint64_t> userResidencyScanTicket_{ 0 };
    std::atomic_bool userResidencyScanInProgress_{ false };
};
