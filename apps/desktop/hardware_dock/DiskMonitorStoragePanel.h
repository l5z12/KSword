#pragma once

// ============================================================
// DiskMonitorStoragePanel.h
// Purpose:
// 1) Provides a 'storage' area with a resource monitor style for the disk monitoring page;
// 2) Collect fixed volume capacity and raw counters from IOCTL_DISK_PERFORMANCE in the background;
// 3) Calculate active time, throughput, response time, and queue length in the UI thread.
// ============================================================

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

class QTableWidget;
struct DiskMonitorStoragePerformanceState;

// DiskMonitorStorageSample：
// - Input: collectSamples() reads from Windows fixed volumes and disk performance interfaces;
// - Processing: Retain cumulative counters to avoid accessing any Qt controls from background threads.
// - Output: Converted to per-second rate by DiskMonitorStoragePanel::applySamples().
struct DiskMonitorStorageSample
{
    QString driveRoot;                       // driveRoot: Volume root directory, e.g., C:\.
    QString volumeGuidName;                  // volumeGuidName: Normalized volume GUID path.
    QString volumeLabel;                     // volumeLabel: Volume label; empty if not provided by the system.
    QString fileSystemName;                  // fileSystemName: file system name, e.g., NTFS.
    QString storageManagerName;              // storageManagerName: Performance provider identifier.
    std::array<std::uint16_t, 8> storageManagerIdentity{}; // storageManagerIdentity: Original 8 WCHAR identity.
    std::uint64_t availableBytes = 0U;       // availableBytes: available space for the current user.
    std::uint64_t totalBytes = 0U;           // totalBytes: Total volume capacity.
    std::uint64_t sampleTickMs = 0U;         // sampleTickMs: Monotonic time near IOCTL completion.
    std::uint64_t bytesRead = 0U;            // bytesRead: Cumulative disk read bytes.
    std::uint64_t bytesWritten = 0U;         // bytesWritten: Cumulative bytes written to disk.
    std::uint32_t readCount = 0U;            // readCount: cumulative disk read count
    std::uint32_t writeCount = 0U;           // writeCount: Cumulative number of disk writes.
    std::uint64_t readTime100ns = 0U;        // readTime100ns: Cumulative read time, unit 100ns.
    std::uint64_t writeTime100ns = 0U;       // writeTime100ns: Cumulative write time, unit 100ns.
    std::uint64_t idleTime100ns = 0U;        // idleTime100ns: Accumulated idle time, unit 100ns.
    std::uint64_t queryTime100ns = 0U;       // queryTime100ns: System query timestamp returned by the IOCTL.
    std::uint32_t volumeSerialNumber = 0U;   // volumeSerialNumber: Volume serial number, used to assist in detecting disk replacement.
    std::uint32_t storageDeviceNumber = 0U;  // storageDeviceNumber: Performance provider device number.
    std::uint32_t queueDepth = 0U;           // queueDepth: disk queue depth at the sampling instant.
    std::uint32_t performanceError = 0U;     // performanceError: Performance query error code for this round.
    bool capacityAvailable = false;          // capacityAvailable: indicates whether the capacity query succeeded.
    bool volumeSerialAvailable = false;      // volumeSerialAvailable: Whether the volume serial number query was successful.
    bool performanceAvailable = false;       // performanceAvailable: Indicates whether disk performance counters are available.
    bool baselinePending = false;            // baselinePending: A new identity baseline was established only in this round.
};

// DiskMonitorStorageBatch：
// - Sampling results and enumeration completeness must be submitted to the UI together;
// - Only when enumerationSucceeded is true and fixedVolumeCount is 0 does it indicate that there are indeed no fixed volumes.
struct DiskMonitorStorageBatch
{
    std::vector<DiskMonitorStorageSample> sampleList;
    QStringList invalidatedBaselineKeys;
    std::uint32_t enumerationError = 0U;
    int fixedVolumeCount = 0;
    int performanceAvailableCount = 0;
    int baselinePendingCount = 0;
    int failedPerformanceCount = 0;
    bool enumerationSucceeded = false;
};

// DiskMonitorStoragePanel：
// - Display the fixed volume storage table after construction;
// - collectSamples() can be called from a background thread.
// - applySamples() must be called on the UI thread and maintains a cross-cycle counter baseline.
class DiskMonitorStoragePanel final : public QWidget
{
public:
    // Constructor:
    // - parent: Qt parent control;
    // - Returns: creates a read-only storage table without starting a separate thread or timer.
    explicit DiskMonitorStoragePanel(QWidget* parent = nullptr);
    ~DiskMonitorStoragePanel() override;

    // collectSamples：
    // - Input: optional destruction stop flag
    // - Processing: enumerate local fixed volumes and read capacity, volume label, file system, and disk performance cumulative values.
    // - Returns: Movable pure data list; failed volumes retain available fields and degrade safely.
    DiskMonitorStorageBatch collectSamples(
        const std::atomic_bool* stopRequested = nullptr);

    // retirePerformanceCountersAsync：
    // - Processing: Transfer the active lease to the background retirement coordinator unique to the process lifetime.
    // - Does not execute IOCTL/OFF on the GUI thread; can be executed repeatedly.
    void retirePerformanceCountersAsync(const QString& reason);

    // applySamples：
    // - Input: Raw samples obtained from the background thread;
    // - Processing: Calculate rate, active time, and response time using the previous baseline, then refresh the table.
    // - Return: None. Displays an explicit placeholder row when samples are empty.
    void applySamples(DiskMonitorStorageBatch sampleBatch);

    // summaryText：
    // - Inputs: None;
    // - Returns: Summary of the highest activity time in the latest round, total throughput, and volume count.
    QString summaryText() const;

private:
    // StorageBaseline：
    // - Purpose: Save the cumulative value of the previous round for a single volume;
    // - Key: Volume GUID + Volume Serial Number + StorageManagerName + StorageDeviceNumber.
    struct StorageBaseline
    {
        std::uint64_t sampleTickMs = 0U;     // sampleTickMs: Monotonic sample time near IOCTL completion.
        std::uint64_t bytesRead = 0U;        // bytesRead: Cumulative bytes read in the previous round.
        std::uint64_t bytesWritten = 0U;     // bytesWritten: Cumulative bytes written in the previous round.
        std::uint32_t readCount = 0U;        // readCount: Cumulative read count from the previous round.
        std::uint32_t writeCount = 0U;       // writeCount: Cumulative write count from the previous round.
        std::uint64_t readTime100ns = 0U;    // readTime100ns: Cumulative read time from the previous round.
        std::uint64_t writeTime100ns = 0U;   // writeTime100ns: cumulative write latency from the previous round.
        std::uint64_t idleTime100ns = 0U;    // idleTime100ns: Cumulative idle time from the previous round.
        std::uint64_t queryTime100ns = 0U;   // queryTime100ns: timestamp of the previous system query.
        bool performanceAvailable = false;   // performanceAvailable: Whether the performance value from the previous round is valid.
    };

    // formatBytes：
    // - Input: byte count
    // - Return: Automatically selects readable capacity units (B/KB/MB/GB/TB).
    static QString formatBytes(double byteCount);

    // formatRate：
    // - Input: bytes per second;
    // - Returns: a human-readable throughput value with a /s suffix.
    static QString formatRate(double bytesPerSecond);

    QTableWidget* table_ = nullptr;         // m_table: Fixed volume storage status table.
    std::unique_ptr<DiskMonitorStoragePerformanceState> performanceState_;
    QHash<QString, StorageBaseline> baselineByIdentity_; // m_baselineByIdentity: Stable volume identity to historical baseline.
    QString summaryText_;                   // m_summaryText: Summary from the most recent resource monitor iteration.
};
