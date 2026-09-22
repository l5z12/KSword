#pragma once

// System-thread management and exact-build, read-only Ex work-queue evidence.

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KernelThreadAuditTab final : public QWidget
{
public:
    enum class Mode
    {
        kSystemThreads,
        kWorkQueueThreads
    };

    explicit KernelThreadAuditTab(Mode mode, QWidget* parent = nullptr);
    void requestRefresh();

    // ModuleQueryStatus：
    // - Purpose: Describe the result status of kernel module enumeration, allowing callers to distinguish between 'no modules found' and 'query failure';
    // - Ok: Enumeration succeeded; the returned module list is trustworthy;
    // - ApiUnavailable: Unable to retrieve ntdll!NtQuerySystemInformation; capability unavailable.
    // - LengthQueryFailed: Pre-query length failed or exceeded the safety limit; formal query was not initiated;
    // - SnapshotFailed: Formal query failed or returned insufficient data to parse the module header.
    enum class ModuleQueryStatus : std::uint32_t
    {
        kOk,
        kApiUnavailable,
        kLengthQueryFailed,
        kSnapshotFailed
    };

    // ModuleRecord：
    // - Purpose: Describes the location information of a loaded kernel module to map kernel addresses to specific drivers.
    // - name: module filename (without directory); falls back to the path's last segment if path resolution fails;
    // - path: full module path (original path format returned by the system).
    // - baseAddress: module image base address; 0 indicates an invalid record
    // - imageSize: Module image size (bytes), forming the address ownership range together with the base address.
    // - kernelImage: true indicates the module is the kernel main image (the first module in the enumeration results).
    struct ModuleRecord
    {
        QString name;
        QString path;
        std::uint64_t baseAddress = 0;
        std::uint32_t imageSize = 0;
        bool kernelImage = false;
    };

    // queryKernelModules：
    // - Purpose: enumerate currently loaded kernel modules for address ownership and driver location reuse;
    // - Note: Uses R3 NtQuerySystemInformation; does not depend on a driver and can be called from any thread.
    // - Out parameter queryStatusOut: Nullable; writes the enumeration status code for this run (see ModuleQueryStatus).
    // - Output nativeStatusOut: optional; writes the NTSTATUS returned by the last native call.
    // - Output parameter requiredBytesOut: optional; writes the required buffer byte count obtained from the pre-query.
    // - Returns: a list of modules ordered by system enumeration order; on failure, returns an empty list with details in queryStatusOut.
    static std::vector<ModuleRecord> queryKernelModules(
        ModuleQueryStatus* queryStatusOut,
        long* nativeStatusOut,
        unsigned long* requiredBytesOut);

    // findOwnerModule：
    // - Purpose: Find the host module containing the specified kernel address in the module list.
    // - Input modules: the module list returned by queryKernelModules.
    // - Input parameter address: the kernel address to resolve ownership; passing 0 is treated as invalid and results in a direct miss.
    // - Output parameter matchedOut: nullable; true indicates the host module was matched, false indicates no match;
    // - Returns: The module record if found; otherwise, returns a default-constructed empty record (baseAddress=0).
    static ModuleRecord findOwnerModule(
        const std::vector<ModuleRecord>& modules,
        std::uint64_t address,
        bool* matchedOut);

protected:
    void changeEvent(QEvent* event) override;

private:
    enum class Column
    {
        kThreadId = 0,
        kEThread,
        kCategory,
        kQueueType,
        kNodePriority,
        kWorkQueueAddress,
        kState,
        kWaitReason,
        kStartRoutine,
        kParameter,
        kModule,
        kModuleBase,
        kModulePath,
        kR0Status,
        kProtection,
        kCount
    };

    enum class ViewPreset
    {
        kOverview,
        kEvidence,
        kCustom
    };

    enum class ProtectionKind : std::uint32_t
    {
        kUnknownModule,
        kKernelImage,
        kMissingThreadIdentity,
        kBestEffortR0Recheck,
        kReadOnlyWorkQueueEvidence
    };

    enum SnapshotDiagnosticFlag : std::uint32_t
    {
        kDiagnosticNone = 0U,
        kDiagnosticR3EnumerationEmpty = 1U << 0U,
        kDiagnosticR0ThreadUnavailable = 1U << 1U,
        kDiagnosticModuleUnavailable = 1U << 2U,
        kDiagnosticWorkQueueTransportFailed = 1U << 3U,
        kDiagnosticWorkQueueUnsupported = 1U << 4U,
        kDiagnosticWorkQueuePartial = 1U << 5U
    };

    struct ThreadRow
    {
        std::uint32_t threadId = 0;
        std::uint64_t createTime100ns = 0;
        std::uint64_t startAddress = 0;
        std::uint64_t queueAddress = 0;
        std::uint64_t workItemAddress = 0;
        std::uint64_t parameterAddress = 0;
        std::uint64_t threadObject = 0;
        int priority = 0;
        int basePriority = 0;
        std::uint32_t state = 0;
        std::uint32_t waitReason = 0;
        std::uint32_t r0Flags = 0;
        std::uint32_t r0FieldFlags = 0;
        std::uint32_t r0Status = 0;
        std::uint32_t workQueueRowKind = 0;
        std::uint32_t queueType = 0;
        std::uint32_t queuePriorityIndex = 0;
        std::uint32_t nodeIndex = 0;
        std::uint32_t workQueueFlags = 0;
        std::uint32_t workQueueStatus = 0;
        ModuleRecord module;
        bool moduleResolved = false;
        bool workerKnown = false;
        bool activeWorker = false;
        bool protectedTarget = true;
        ProtectionKind protectionKind = ProtectionKind::kUnknownModule;
    };

    struct Snapshot
    {
        std::vector<ThreadRow> rows;
        std::uint32_t diagnosticFlags = kDiagnosticNone;
        unsigned long r0Win32Error = ERROR_SUCCESS;
        ModuleQueryStatus moduleQueryStatus = ModuleQueryStatus::kOk;
        long moduleNativeStatus = 0;
        unsigned long moduleRequiredBytes = 0;
        std::uint32_t workQueueQueryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
        std::uint32_t workQueueStatusFlags = 0;
        std::uint32_t workQueueTotalCount = 0;
        std::uint32_t workQueueNodeCount = 0;
        std::uint32_t workQueueQueuesVisited = 0;
        std::uint32_t workQueueCorruptCount = 0;
        std::uint32_t workQueueReadFailureCount = 0;
        std::uint32_t workQueueReferenceFailureCount = 0;
        long workQueueLastStatus = 0;
        bool usedNtQuery = false;
        bool r0Available = false;
    };

    void initializeUi();
    void applyTranslatedText();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();
    void applyColumnPreset(ViewPreset preset);
    void updatePresetButtons();
    void showHeaderMenu(const QPoint& localPosition);
    void showRowMenu(const QPoint& localPosition);
    void runControlAction(unsigned long action);
    void runControlAction(const ThreadRow& row, unsigned long action);
    const ThreadRow* selectedRow() const;
    int selectedSourceIndex() const;

    static Snapshot collectSnapshot(Mode mode);
    static QString stateText(std::uint32_t stateValue);
    static QString waitReasonText(std::uint32_t waitReasonValue);
    static QString r0StatusText(std::uint32_t statusValue);
    static QString addressText(std::uint64_t addressValue);
    static QString pointerText(std::uint64_t addressValue);
    static QString protectionReasonText(ProtectionKind protectionKind);
    static QString queueTypeText(std::uint32_t queueType);
    static QString workQueueEntryStatusText(std::uint32_t status);
    static QString snapshotDiagnosticText(const Snapshot& snapshot, Mode mode);

    Mode mode_ = Mode::kSystemThreads;
    ViewPreset viewPreset_ = ViewPreset::kOverview;
    QLineEdit* filterEdit_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* suspendButton_ = nullptr;
    QPushButton* resumeButton_ = nullptr;
    QPushButton* terminateButton_ = nullptr;
    QPushButton* overviewButton_ = nullptr;
    QPushButton* evidenceButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    CodeEditorWidget* detailEditor_ = nullptr;
    std::vector<ThreadRow> rows_;
    bool refreshRunning_ = false;
    std::uint64_t refreshTicket_ = 0;
};
