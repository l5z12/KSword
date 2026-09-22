#pragma once

// ============================================================
// DirectKernelCallMonitorWidget.h
// Purpose:
// 1) Provides the 'Direct Kernel Call' tab for the 'Monitor' module;
// 2) Collect system call events based on the Windows ETW System Syscall Provider;
// 3) Resolve syscall numbers to Nt*, Zw*, NtUser*, or NtGdi* names using ntdll/win32u export stubs;
// 4) Provide PID filtering, real-time filtering, pause, export, and details viewing capabilities.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

class QPoint;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;
struct _EVENT_RECORD;

class DirectKernelCallMonitorWidget final : public QWidget
{
public:
    explicit DirectKernelCallMonitorWidget(QWidget* parent = nullptr);
    ~DirectKernelCallMonitorWidget() override;

public:
    enum EventColumn
    {
        kEventColumnTime100ns = 0,
        kEventColumnPidTid,
        kEventColumnProcess,
        kEventColumnSyscallNumber,
        kEventColumnServiceName,
        kEventColumnVerdict,
        kEventColumnCallAddress,
        kEventColumnEventName,
        kEventColumnDetail,
        kEventColumnCount
    };

    struct SyscallMapEntry
    {
        std::uint32_t syscallNumber = 0;
        QString serviceName;
        QString sourceModule;
    };

    struct DecodedProperty
    {
        QString name;
        QString valueText;
        std::uint64_t numericValue = 0;
        bool hasNumericValue = false;
    };

    struct ModuleRange
    {
        std::uint64_t startAddress = 0;
        std::uint64_t endAddress = 0;
        QString moduleName;
        QString imagePath;
    };

    // ProcessIdentityCacheEntry：
    // - Purpose: Limit high-frequency ETW events from repeatedly opening process handles for the same PID.
    // - Call pattern: processNameForPid revalidates the creation time at most once per second.
    // - Return behavior: Caches display name, creation time, and last verification time; does not actively access the system.
    struct ProcessIdentityCacheEntry
    {
        QString processText; // processText: The process name and PID displayed during capture.
        std::uint64_t creationTime100ns = 0U; // creationTime100ns: Combined with PID to form the historical event identity.
        std::chrono::steady_clock::time_point lastValidationTime{}; // lastValidationTime: timestamp of the most recent identity validation.
    };

    struct CapturedEventRow
    {
        QString time100nsText;
        std::uint32_t pid = 0;
        std::uint64_t processCreationTime100ns = 0U; // processCreationTime100ns: Creation time of the corresponding process instance at the time of the event.
        std::uint32_t tid = 0;
        QString pidTidText;
        QString processText;
        std::uint32_t syscallNumber = 0;
        bool hasSyscallNumber = false;
        QString syscallNumberText;
        QString serviceName;
        QString verdictText;
        std::uint64_t callAddress = 0;
        QString callAddressText;
        QString eventName;
        QString detailText;
        QString detailAllText;
        QString globalSearchText;
    };

private:
    void initializeUi();
    void initializeConnections();
    void reloadSyscallMap();
    void startCapture();
    void stopCapture();
    void stopCaptureInternal(bool waitForThread);
    void setCapturePaused(bool paused);
    void updateActionState();
    void updateStatusLabel();
    void flushPendingRows();
    void appendEventRow(const CapturedEventRow& rowValue);
    void scheduleFilterApply();
    void applyFilter();
    void clearFilter();
    void exportVisibleRowsToTsv();
    void showEventContextMenu(const QPoint& position);
    void openEventDetailViewerForRow(int rowIndex);

    static void WINAPI eventRecordCallback(struct _EVENT_RECORD* eventRecordPtr);
    void enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    CapturedEventRow buildRowFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    std::vector<DecodedProperty> decodeEventProperties(
        const struct _EVENT_RECORD* eventRecordPtr,
        QString* eventNameOut) const;
    QString serviceNameForNumber(std::uint32_t syscallNumber) const;
    // processNameForPid:
    // - Query or reuse the name corresponding to the PID, and synchronously return the process creation time;
    // - Input: pid - the PID carried in the ETW event;
    // - Output parameter creationTime100nsOut: creation time used for historical jump validation.
    // - Returns: Process display text including the PID.
    QString processNameForPid(
        std::uint32_t pid,
        std::uint64_t* creationTime100nsOut);
    QString moduleNameForAddress(std::uint32_t pid, std::uint64_t addressValue);
    void refreshModuleRangesForPid(std::uint32_t pid);
    std::set<std::uint32_t> parsePidSet(const QString& text) const;
    bool shouldCapturePid(std::uint32_t pid) const;

private:
    QVBoxLayout* rootLayout_ = nullptr;
    QWidget* controlPanel_ = nullptr;
    QLineEdit* targetPidEdit_ = nullptr;
    QCheckBox* globalCaptureCheck_ = nullptr;
    QCheckBox* resolveAddressCheck_ = nullptr;
    QSpinBox* maxRowsSpin_ = nullptr;
    QSpinBox* bufferSizeSpin_ = nullptr;
    QPushButton* reloadMapButton_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* pauseButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QPushButton* exportButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* mapStatusLabel_ = nullptr;

    QWidget* filterPanel_ = nullptr;
    QLineEdit* processFilterEdit_ = nullptr;
    QLineEdit* serviceFilterEdit_ = nullptr;
    QLineEdit* detailFilterEdit_ = nullptr;
    QLineEdit* globalFilterEdit_ = nullptr;
    QCheckBox* regexCheck_ = nullptr;
    QCheckBox* caseCheck_ = nullptr;
    QCheckBox* invertCheck_ = nullptr;
    QCheckBox* keepBottomCheck_ = nullptr;
    QPushButton* clearFilterButton_ = nullptr;
    QLabel* filterStatusLabel_ = nullptr;
    QTableWidget* eventTable_ = nullptr;
    QTimer* uiUpdateTimer_ = nullptr;
    QTimer* filterDebounceTimer_ = nullptr;

    std::unordered_map<std::uint32_t, SyscallMapEntry> syscallMap_;
    mutable std::mutex syscallMapMutex_;
    std::unordered_map<std::uint32_t, ProcessIdentityCacheEntry> processNameCache_; // Cache mapping PID to rate-limited identity verification.
    std::unordered_map<std::uint32_t, std::vector<ModuleRange>> moduleRangeCache_;
    std::mutex cacheMutex_;
    static constexpr std::size_t kPendingRowCapacity = 24000;
    static constexpr std::size_t kUiFlushRowLimit = 160;
    static constexpr int kUiFlushBudgetMs = 4;
    static constexpr int kProcessIdentityValidationIntervalMs = 1000; // Re-verification interval for the same PID identity, balancing PID reuse and ETW throughput.

    std::deque<CapturedEventRow> pendingRows_;
    std::mutex pendingMutex_;
    std::size_t pendingDroppedRows_ = 0;
    std::set<std::uint32_t> capturePidSet_;
    mutable std::mutex captureConfigMutex_;

    std::atomic_bool captureRunning_{ false };
    std::atomic_bool capturePaused_{ false };
    std::atomic_bool captureStopFlag_{ false };
    std::atomic_bool captureAllProcesses_{ false };
    std::atomic_bool resolveCallAddress_{ true };
    std::unique_ptr<std::thread> captureThread_;
    std::atomic<std::uint64_t> sessionHandle_{ 0 };
    std::atomic<std::uint64_t> traceHandle_{ 0 };
    QString sessionName_;
    int captureProgressPid_ = 0;
    bool filterActive_ = false;
};
