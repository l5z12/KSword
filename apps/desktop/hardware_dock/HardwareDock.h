#pragma once

// ============================================================
// HardwareDock.h
// Purpose:
// 1) Provide top-level tabs for 'Performance Monitoring / Hardware Overview / Processor / GPU / Memory / Disk Activity / Device Check', with Performance Monitoring having the highest priority;
// 2) Utilization page implements a "left thumbnail card + right detail page" layout in the style of Task Manager;
// 3) The newly added device audit page is read-only by default, targeting DevNode, USB, HID, PCI, ACPI, and display link cross-views.
// ============================================================

#include "../Framework.h"

#include <QStringList>
#include <QVector>
#include <QWidget>

#include <atomic>   // std::atomic_bool: Asynchronous probe task mutual exclusion.
#include <cstdint>  // std::uint64_t: Stores accumulated sampling values and timestamps.
#include <vector>   // std::vector: Store per-core charts and sampling data.

class CodeEditorWidget;
class DiskMonitorPage;
class MemoryCompositionHistoryWidget;
class HardwarePowerPage;
class HardwareR0EvidencePage;
class HardwareDeviceManagerPage;
class HardwareOtherDevicesPage;
class HardwareHwidDispatchPage;
class HardwareI8042AuditPage;
class PerformanceNavCard;
class QChartView;
class QAreaSeries;
class QEvent;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineSeries;
class QListWidget;
class QResizeEvent;
class QScrollArea;
class QSplitter;
class QShowEvent;
class QStackedWidget;
class QTabWidget;
class QTableWidget;
class QTimer;
class QValueAxis;
class QVBoxLayout;
class QWidget;

class HardwareDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent control;
    // - Purpose: initialize all hardware tabs and start periodic sampling.
    explicit HardwareDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop the sampling timer and release the PDH query handle.
    ~HardwareDock() override;

    // startPerformanceSampling: starts the initial sampling and periodic refresh for reuse by WelcomeDock.
    // When includeDriverHealth=false, only user-mode performance sampling is enabled; R0 hardware health IOCTLs are not accessed.
    void startPerformanceSampling(bool includeDriverHealth = true);

signals:
    // performanceSnapshotChanged: Publishes aggregated sampling results identical to those on the performance monitoring page.
    // Disk, network, and GPU parameters are displayed by the caller as aggregated device values; no separate sampler is duplicated.
    void performanceSnapshotChanged(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);

    // staticOverviewChanged: Publishes the asynchronously collected static hardware summary text for the Hardware Dock.
    void staticOverviewChanged(const QString& overviewText);

protected:
    // eventFilter purpose: Synchronize card width only after the performance page splitter is released; do not re-layout content during dragging.
    bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    // resizeEvent:
    // - Dynamically adjust the height of the 'Utilization' page chart when the window size changes.
    // - Ensure the task manager-style page has no scrollbars as much as possible.
    void resizeEvent(QResizeEvent* resizeEventPointer) override;

    // showEvent:
    // - Dock triggers layout re-layout after its first display;
    // - Fix the core chart squeezing issue caused by 'Utilization -> CPU first entry height not yet ready'.
    void showEvent(QShowEvent* showEventPointer) override;

private:
    // CoreChartEntry：
    // - Purpose: Store the control required for a single logical processor mini-chart.
    // - Quickly updates the corresponding curve by index during subsequent refreshes.
    struct CoreChartEntry
    {
        QWidget* containerWidget = nullptr; // containerWidget: Single-core graph container.
        QLabel* titleLabel = nullptr;       // titleLabel: Displays the 'CPU n' title.
        QChartView* chartView = nullptr;    // chartView: Line chart view.
        QLineSeries* lineSeries = nullptr;  // lineSeries: This core utilization curve.
        QLineSeries* baselineSeries = nullptr; // baselineSeries: The 0% baseline along the X-axis, used to fill the area under the curve.
        QAreaSeries* areaSeries = nullptr;   // areaSeries: The filled area enclosed by the line chart and the X-axis.
        QValueAxis* axisX = nullptr;        // axisX: Time axis (hidden labels).
        QValueAxis* axisY = nullptr;        // axisY: Percentage axis (hidden labels).
    };

    // GpuEngineChartEntry：
    // - Purpose: Stores controls and engine keys required for the GPU engine mini-chart;
    // - Used to update during the refresh phase by '3D/Copy/Video Encode/Video Decode'.
    struct GpuEngineChartEntry
    {
        QString engineKeyText;          // engineKeyText: Internal engine key name (for case-insensitive matching).
        QString displayNameText;        // displayNameText: Interface title text.
        QLabel* titleLabel = nullptr;   // titleLabel: Title label for each engine thumbnail.
        QChartView* chartView = nullptr; // chartView: View for each engine thumbnail.
        QLineSeries* lineSeries = nullptr; // lineSeries: Engine utilization curve.
        QLineSeries* baselineSeries = nullptr; // baselineSeries: engine chart X-axis baseline, used to close the area fill.
        QAreaSeries* areaSeries = nullptr; // areaSeries: Filled area below the engine utilization line chart.
        QValueAxis* axisX = nullptr;    // axisX: Engine chart X-axis.
        QValueAxis* axisY = nullptr;    // axisY: Engine chart Y-axis.
    };

    // CpuPowerSnapshot：
    // - Purpose: Saves per-core frequency information returned by CallNtPowerInformation;
    // - Field used for column-by-column display in the CPU details table.
    struct CpuPowerSnapshot
    {
        std::uint32_t coreIndex = 0;  // coreIndex: Logical processor index.
        std::uint32_t currentMhz = 0; // currentMhz: Current frequency (MHz).
        std::uint32_t maxMhz = 0;     // maxMhz: Maximum frequency (MHz).
        std::uint32_t limitMhz = 0;   // limitMhz: Current frequency limit upper bound (MHz).
    };

    // SystemPerformanceSnapshot：
    // - Purpose: Consolidate system-wide performance statistics to avoid redundant Win32 API calls;
    // - Field used for parameter display below the CPU/Memory detail page.
    struct SystemPerformanceSnapshot
    {
        std::uint32_t processCount = 0;        // processCount: Total system process count.
        std::uint32_t threadCount = 0;         // threadCount: Total system thread count.
        std::uint32_t handleCount = 0;         // handleCount: Total number of system handles.
        std::uint64_t commitTotalBytes = 0;    // commitTotalBytes: Committed memory in bytes.
        std::uint64_t commitLimitBytes = 0;    // commitLimitBytes: Maximum bytes allowed for commit.
        std::uint64_t cachedBytes = 0;         // cachedBytes: System cache bytes.
        std::uint64_t pagedPoolBytes = 0;      // pagedPoolBytes: Paged pool bytes.
        std::uint64_t nonPagedPoolBytes = 0;   // nonPagedPoolBytes: Non-paged pool bytes.
    };

    // UtilizationStatisticSnapshot：
    // - Purpose: Save statistical results for a historical window;
    // - Handling: Composed of current value, mean, peak, minimum, and trend difference.
    // - Return behavior: carries statistical data only; performs no sampling.
    struct UtilizationStatisticSnapshot
    {
        double currentValue = 0.0;   // currentValue: Most recent sample value.
        double averageValue = 0.0;   // averageValue: window mean value.
        double peakValue = 0.0;      // peakValue: Window peak value.
        double minValue = 0.0;       // minValue: Window minimum value.
        double trendDelta = 0.0;    // trendDelta: Difference between the current value and the window start value.
        int sampleCount = 0;         // sampleCount: number of samples involved in statistics.
    };

    // DeviceAuditViewSnapshot：
    // - Purpose: Simultaneously save the text summary and full structured rows of the hardware device audit page.
    // - Processing logic: Query ArkDriverClient wrapper once in the background thread, then generate two UI models;
    // - Return behavior: The struct itself has no function return value; fields are consumed by refreshStaticHardwareTexts.
    struct DeviceAuditViewSnapshot
    {
        QString summaryText;          // summaryText: Human-readable summary from CodeEditorWidget.
        QVector<QStringList> rows;    // rows: All R0 device audit rows displayed in the QTableWidget.
    };

    // UtilizationDeviceKind：
    // - Purpose: Identify the detail page type corresponding to the "Utilization" left card.
    // - Processing logic: CPU and memory are fixed; disk, network interface, and GPU are dynamically expanded based on the device.
    // - Return behavior: The enum itself has no return value; it is used solely for navigation state synchronization.
    enum class UtilizationDeviceKind
    {
        kCpu,     // Cpu: Fixed CPU detail page.
        kMemory,  // Memory: Fixed memory detail page.
        kDisk,    // Disk: Detail page for a single physical disk.
        kNetwork, // Network: Single network interface detail page.
        kGpu      // Gpu: Details page for a single DXGI graphics adapter.
    };

    // UtilizationNavEntry：
    // - Purpose: Bind the left-side PerformanceNavCard to the right-side QStackedWidget page.
    // - Input source: initializeUtilizationSidebarCards and dynamic device discovery logic;
    // - Return behavior: The structure only stores pointers and indices, and is not responsible for freeing Qt objects.
    struct UtilizationNavEntry
    {
        PerformanceNavCard* navCard = nullptr;       // navCard: Left navigation card control.
        QWidget* detailPage = nullptr;               // detailPage: Control for the right-side detail page.
        UtilizationDeviceKind kind = UtilizationDeviceKind::kCpu; // kind: Device type.
        int deviceIndex = -1;                        // deviceIndex: Index in the array of similar devices.
    };

    // DiskRateSample：
    // - Purpose: Store a single-disk PDH read/write rate sample.
    // - Usage: sampleDiskRates fills the list, and the refresh phase matches pages by instanceNameText;
    // - Return behavior: struct has no methods; all fields are output data.
    struct DiskRateSample
    {
        QString instanceNameText;       // instanceNameText: PDH PhysicalDisk instance name.
        QString displayNameText;        // displayNameText: Display name shown in the UI, e.g., "Disk 0 (C:)".
        double readBytesPerSec = 0.0;   // readBytesPerSec: read bytes per second.
        double writeBytesPerSec = 0.0;  // writeBytesPerSec: Write bytes per second.
    };

    // NetworkRateSample：
    // - Purpose: Save a single network interface transmit/receive rate sample.
    // - Usage: sampleNetworkRates reads GetIfTable2 and calculates increments by interface LUID;
    // - Return behavior: fields are used directly to refresh UI cards and detail pages.
    struct NetworkRateSample
    {
        std::uint64_t interfaceKey = 0;             // interfaceKey: Network interface LUID packing key.
        QString displayNameText;                   // displayNameText: Network adapter alias or description.
        std::uint64_t linkBitsPerSecond = 0;        // linkBitsPerSecond: Link rate in bit/s.
        double rxBytesPerSec = 0.0;                 // rxBytesPerSec: bytes received per second.
        double txBytesPerSec = 0.0;                 // txBytesPerSec: Bytes sent per second.
        std::uint64_t totalRxBytes = 0;             // totalRxBytes: System cumulative received bytes.
        std::uint64_t totalTxBytes = 0;             // totalTxBytes: System cumulative transmitted bytes.
    };

    // GpuUsageSample：
    // - Purpose: Save engine utilization and VRAM samples for a single GPU instance.
    // - Invocation: sampleGpuUsages first enumerates DXGI adapters, then merges PDH GPU Engine data.
    // - Returns behavior: updates the corresponding GPU page by adapterKey during the refresh phase.
    struct GpuUsageSample
    {
        std::uint64_t adapterKey = 0;              // adapterKey: DXGI LUID packed key.
        int adapterIndex = 0;                      // adapterIndex: DXGI enumeration index.
        QString displayNameText;                  // displayNameText: Graphics card name.
        double overallUsagePercent = 0.0;         // overallUsagePercent: Overall approximate utilization.
        double usage3DPercent = 0.0;              // usage3DPercent: 3D engine utilization.
        double usageCopyPercent = 0.0;            // usageCopyPercent: Copy engine utilization.
        double usageVideoEncodePercent = 0.0;     // usageVideoEncodePercent: video encode utilization.
        double usageVideoDecodePercent = 0.0;     // usageVideoDecodePercent: video decode utilization.
        double currentCoreClockMhz = 0.0;         // currentCoreClockMhz: Current 3D core frequency in MHz.
        double maxCoreClockMhz = 0.0;             // maxCoreClockMhz: the maximum 3D core frequency in MHz reported by the driver.
        double currentMemoryClockMhz = 0.0;       // currentMemoryClockMhz: Current VRAM frequency in MHz.
        double maxMemoryClockMhz = 0.0;           // maxMemoryClockMhz: Maximum memory clock frequency in MHz reported by the driver.
        double dedicatedMemoryGiB = 0.0;          // dedicatedMemoryGiB: Total dedicated VRAM in GiB.
        double sharedMemoryGiB = 0.0;             // sharedMemoryGiB: Total shared system VRAM in GiB.
        double dedicatedUsedGiB = 0.0;            // dedicatedUsedGiB: Used dedicated video memory in GiB.
        bool dedicatedUsageAvailable = false;     // dedicatedUsageAvailable: Whether the system-level dedicated video memory counter is valid.
        double dedicatedBudgetGiB = 0.0;          // dedicatedBudgetGiB: Dedicated VRAM budget in GiB.
        double sharedUsedGiB = 0.0;               // sharedUsedGiB: Shared video memory used in GiB.
        bool sharedUsageAvailable = false;        // sharedUsageAvailable: Whether the system-level shared video memory counter is valid.
        double sharedBudgetGiB = 0.0;             // sharedBudgetGiB: Shared VRAM budget in GiB.
    };

    // DiskUtilizationDevice：
    // - Purpose: Stores the state of a disk card, detail page, and history thumbnail;
    // - Invocation: ensureDiskUtilizationDevice creates the object when a new PDH instance is discovered;
    // - Return behavior: The struct is owned by HardwareDock, while Qt objects are still released via the parent-child tree.
    struct DiskUtilizationDevice
    {
        QString instanceNameText;                 // instanceNameText: PDH PhysicalDisk instance name.
        QString displayNameText;                  // displayNameText: left card title.
        QWidget* pageWidget = nullptr;            // pageWidget: Right detail page.
        QLabel* summaryLabel = nullptr;           // summaryLabel: Read/write summary.
        QChartView* chartView = nullptr;          // chartView: Read/write trend chart.
        QLineSeries* readLineSeries = nullptr;    // readLineSeries: read rate line chart.
        QLineSeries* readBaselineSeries = nullptr; // readBaselineSeries: Read the 0-axis baseline for the line chart.
        QAreaSeries* readAreaSeries = nullptr;    // readAreaSeries: Area series for reading the filled area under the line.
        QLineSeries* writeLineSeries = nullptr;   // writeLineSeries: Write rate line series.
        QLineSeries* writeBaselineSeries = nullptr; // writeBaselineSeries: 0-axis baseline for the write line series.
        QAreaSeries* writeAreaSeries = nullptr;   // writeAreaSeries: Filled area below the write line chart.
        QValueAxis* axisX = nullptr;              // axisX: Trend chart X-axis.
        QValueAxis* axisY = nullptr;              // axisY: Trend chart Y-axis.
        QLabel* detailLabel = nullptr;            // detailLabel: Parameter details.
        PerformanceNavCard* navCard = nullptr;    // navCard: Left navigation card.
        double navAutoScaleBytesPerSec = 1024.0 * 1024.0; // navAutoScaleBytesPerSec: Dynamic upper limit for thumbnails.
        std::vector<double> readHistoryBytesPerSec;  // readHistoryBytesPerSec: Thumbnail read history.
        std::vector<double> writeHistoryBytesPerSec; // writeHistoryBytesPerSec: Thumbnail write history.
    };

    // NetworkUtilizationDevice：
    // - Purpose: Save a NIC page, rate history, and last cumulative count;
    // - Invocation: sampleNetworkRates finds or creates entries by LUID within the UI thread;
    // - Return behavior: The struct does not return data; the refresh function reads fields to update the UI.
    struct NetworkUtilizationDevice
    {
        std::uint64_t interfaceKey = 0;           // interfaceKey: Network interface LUID packing key.
        QString displayNameText;                 // displayNameText: Network adapter display name.
        std::uint64_t linkBitsPerSecond = 0;      // linkBitsPerSecond: Link rate in bit/s.
        std::uint64_t lastRxBytes = 0;            // lastRxBytes: Cumulative received bytes up to the last update.
        std::uint64_t lastTxBytes = 0;            // lastTxBytes: Cumulative transmitted bytes up to the last update.
        qint64 lastSampleMs = 0;                  // lastSampleMs: timestamp of the last sample (milliseconds).
        bool hasPreviousSample = false;           // hasPreviousSample: Whether an incremental baseline already exists.
        QWidget* pageWidget = nullptr;            // pageWidget: Right detail page.
        QLabel* summaryLabel = nullptr;           // summaryLabel: Send/receive summary.
        QChartView* chartView = nullptr;          // chartView: Send/receive trend chart.
        QLineSeries* rxLineSeries = nullptr;      // rxLineSeries: Receive rate line series.
        QLineSeries* rxBaselineSeries = nullptr;  // rxBaselineSeries: 0-axis baseline for the receive line chart.
        QAreaSeries* rxAreaSeries = nullptr;      // rxAreaSeries: filled area below the receive line chart.
        QLineSeries* txLineSeries = nullptr;      // txLineSeries: Line chart for transmission rate.
        QLineSeries* txBaselineSeries = nullptr;  // txBaselineSeries: 0-axis baseline for the transmission line series.
        QAreaSeries* txAreaSeries = nullptr;      // txAreaSeries: Filled area below the transmit line chart.
        QValueAxis* axisX = nullptr;              // axisX: Trend chart X-axis.
        QValueAxis* axisY = nullptr;              // axisY: Trend chart Y-axis.
        QLabel* detailLabel = nullptr;            // detailLabel: Parameter details.
        PerformanceNavCard* navCard = nullptr;    // navCard: Left navigation card.
        double navAutoScaleBytesPerSec = 1024.0 * 1024.0; // navAutoScaleBytesPerSec: Dynamic upper limit for thumbnails.
        std::vector<double> rxHistoryBytesPerSec; // rxHistoryBytesPerSec: Thumbnail receive history.
        std::vector<double> txHistoryBytesPerSec; // txHistoryBytesPerSec: Thumbnail transmission history.
    };

    // GpuUtilizationDevice：
    // - Purpose: Store controls for a GPU adapter's detail page, engine graph, and VRAM graph;
    // - Invocation: ensureGpuUtilizationDevice creates the entry when DXGI discovers a new adapter.
    // - Return behavior: The field is read and refreshed by updateGpuUtilizationDevice.
    struct GpuUtilizationDevice
    {
        std::uint64_t adapterKey = 0;             // adapterKey: DXGI LUID packed key.
        bool adapterKeyAssigned = false;          // adapterKeyAssigned: whether adapterKey has been bound to a real device.
        int adapterIndex = 0;                     // adapterIndex: DXGI enumeration index.
        QString displayNameText;                 // displayNameText: Graphics card name.
        QWidget* pageWidget = nullptr;            // pageWidget: Right detail page.
        QLabel* adapterTitleLabel = nullptr;      // adapterTitleLabel: Adapter name in the title area.
        QLabel* summaryLabel = nullptr;           // summaryLabel: Utilization summary.
        QWidget* engineHostWidget = nullptr;      // engineHostWidget: Engine thumbnail host.
        QGridLayout* engineGridLayout = nullptr;  // engineGridLayout: Engine thumbnail grid.
        std::vector<GpuEngineChartEntry> engineCharts; // engineCharts: Four types of engine charts.
        QChartView* dedicatedMemoryChartView = nullptr; // dedicatedMemoryChartView: dedicated VRAM chart.
        QLineSeries* dedicatedMemoryLineSeries = nullptr; // dedicatedMemoryLineSeries: Dedicated VRAM line series.
        QLineSeries* dedicatedMemoryBaselineSeries = nullptr; // dedicatedMemoryBaselineSeries: Dedicated memory baseline on the 0-axis.
        QAreaSeries* dedicatedMemoryAreaSeries = nullptr; // dedicatedMemoryAreaSeries: Dedicated video memory line fill area.
        QValueAxis* dedicatedMemoryAxisX = nullptr; // dedicatedMemoryAxisX: Dedicated VRAM X-axis.
        QValueAxis* dedicatedMemoryAxisY = nullptr; // dedicatedMemoryAxisY: Dedicated VRAM Y-axis.
        QChartView* sharedMemoryChartView = nullptr; // sharedMemoryChartView: Shared memory chart.
        QLineSeries* sharedMemoryLineSeries = nullptr; // sharedMemoryLineSeries: Line series for shared video memory.
        QLineSeries* sharedMemoryBaselineSeries = nullptr; // sharedMemoryBaselineSeries: Shared VRAM 0-axis baseline series.
        QAreaSeries* sharedMemoryAreaSeries = nullptr; // sharedMemoryAreaSeries: Shared video memory polyline fill area.
        QValueAxis* sharedMemoryAxisX = nullptr;  // sharedMemoryAxisX: Shared VRAM X-axis.
        QValueAxis* sharedMemoryAxisY = nullptr;  // sharedMemoryAxisY: Shared VRAM Y-axis.
        QLabel* detailLabel = nullptr;            // detailLabel: Parameter details.
        PerformanceNavCard* navCard = nullptr;    // navCard: Left navigation card.
    };

private:
    // ===================== UI Initialization =====================
    void initializeUi();
    void initializeOverviewTab();
    void initializeUtilizationTab();
    void initializeUtilizationSidebarCards();
    void initializeUtilizationCpuSubTab();
    void initializeUtilizationMemorySubTab();
    void initializeUtilizationDiskSubTab();
    void initializeUtilizationNetworkSubTab();
    void initializeUtilizationGpuSubTab();
    void initializeCpuTab();
    void initializePowerTab();
    void initializeR0EvidenceTab();
    void initializeGpuTab();
    void initializeMemoryTab();
    void initializeDiskMonitorTab();
    void initializeDeviceManagerTab();
    void initializeHwidDispatchTab();
    void initializeOtherDevicesTab();
    void initializeDeviceStackTab();
    void initializeKeyboardMouseHidTab();
    void initializeI8042AuditTab();
    void initializeUsbTopologyTab();
    void initializePnpAcpiPciTab();

    // ensureDiskMonitorTabInitialized:
    // - Input: none; reads m_diskMonitorHostPage and m_diskMonitorPage;
    // - Processing: Create the DiskMonitorPage when first entering the 'Disk Monitor' sub-tab and replace placeholder content.
    // - Return: None. Real pages are automatically released when added to the Qt parent-child tree.
    void ensureDiskMonitorTabInitialized();

    // ensureOtherDevicesTabInitialized:
    // - Input: None; reads m_otherDevicesHostPage and m_otherDevicesPage;
    // - Processing: Create HardwareOtherDevicesPage when first entering the 'Other Devices' sub-tab.
    // - Return: None. Page content is displayed directly in the host layout.
    void ensureOtherDevicesTabInitialized();

    // startInitialSamplingAfterFirstPaint:
    // - Input: none; depends on being called after the first display via showEvent;
    // - Processing: Defer PDH/device sampling until after the first frame render to avoid blocking the UI when clicking the Hardware Dock.
    // - Returns: none. Starts the periodic refresh timer upon completion.
    void startInitialSamplingAfterFirstPaint();
    void initializeCoreCharts();
    void initializeConnections();
    void scheduleUtilizationLayoutRefresh();
    void applyInitialUtilizationSplitterSize();
    void syncUtilizationSidebarCardWidths();
    void syncUtilizationSidebarSelection(int selectedRowIndex);
    void adjustUtilizationChartHeights();
    PerformanceNavCard* addUtilizationSidebarCard(
        QWidget* detailPage,
        const QString& titleText,
        const QColor& accentColor,
        UtilizationDeviceKind kind,
        int deviceIndex);
    int findDiskUtilizationDeviceIndexByInstance(const QString& instanceNameText) const;
    int ensureDiskUtilizationDevice(const DiskRateSample& sample, int ordinalIndex);
    int findNetworkUtilizationDeviceIndexByKey(std::uint64_t interfaceKey) const;
    int ensureNetworkUtilizationDevice(const NetworkRateSample& sample, int ordinalIndex);
    int findGpuUtilizationDeviceIndexByKey(std::uint64_t adapterKey) const;
    int ensureGpuUtilizationDevice(const GpuUsageSample& sample, int ordinalIndex);
    void createDiskUtilizationDevicePage(DiskUtilizationDevice* devicePointer);
    void createNetworkUtilizationDevicePage(NetworkUtilizationDevice* devicePointer);
    void createGpuUtilizationDevicePage(GpuUtilizationDevice* devicePointer);

    // ===================== Sampling and Refreshing =====================
    void initializePerformanceCounters();
    void refreshAllViews();
    bool samplePerCoreUsage(
        std::vector<double>* coreUsageOut,
        double* totalUsageOut);
    bool sampleCpuEffectiveSpeed(double* speedGhzOut) const;
    bool sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut);
    bool sampleMemoryUsage(double* memoryUsagePercentOut);
    bool sampleDiskRates(std::vector<DiskRateSample>* sampleListOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRates(std::vector<NetworkRateSample>* sampleListOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    bool sampleGpuUsages(std::vector<GpuUsageSample>* sampleListOut);
    bool sampleGpuUsage(double* gpuUsagePercentOut);
    bool sampleGpuMemoryInfoByDxgi();
    bool sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const;
    void updateOverviewText(double cpuUsagePercent, double memoryUsagePercent);
    void updateUtilizationView(
        const std::vector<double>& coreUsageList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateUtilizationSidebarCards(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateAdditionalDiskUtilizationDevices(const std::vector<DiskRateSample>& sampleList);
    void updateAdditionalNetworkUtilizationDevices(const std::vector<NetworkRateSample>& sampleList);
    void updateAdditionalGpuUtilizationDevices(const std::vector<GpuUsageSample>& sampleList);
    void updateDiskUtilizationDevice(DiskUtilizationDevice& device, const DiskRateSample& sample);
    void updateNetworkUtilizationDevice(NetworkUtilizationDevice& device, const NetworkRateSample& sample);
    void updateGpuUtilizationDevice(GpuUtilizationDevice& device, const GpuUsageSample& sample);
    void updateTaskManagerDetailLabels(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateCpuDetailTable(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList);
    void appendCoreSeriesPoint(
        CoreChartEntry& chartEntry,
        double usagePercent);
    void appendGeneralSeriesPoint(
        QLineSeries* lineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0);
    // appendFilledSeriesPoint:
    // - Synchronously appends line sampling and 0-axis baseline sampling.
    // - Ensure the QAreaSeries fill area translates with the history window.
    void appendFilledSeriesPoint(
        QLineSeries* lineSeries,
        QLineSeries* baselineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0);
    // updateSharedSeriesAxisRange:
    // Unified calculation of X/Y visible ranges for two line series sharing the same coordinate axis.
    // - Synchronize the vertical scale using the visible historical peaks of both curves.
    void updateSharedSeriesAxisRange(
        QLineSeries* primaryLineSeries,
        QLineSeries* secondaryLineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double minAxisYValue = 0.0);
    // rebuildDualRateNavCard:
    // - Record the raw history of disk and network dual rates.
    // - Recalculate the thumbnail scale based on the current visible historical peak and redraw the entire section.
    void rebuildDualRateNavCard(
        PerformanceNavCard* navCard,
        std::vector<double>* primaryHistoryOut,
        std::vector<double>* secondaryHistoryOut,
        double primaryBytesPerSecond,
        double secondaryBytesPerSecond,
        double* upperBoundBytesPerSecondOut,
        const QString& subtitleText);
    QString formatRateText(double bytesPerSecondValue) const;
    void pushBoundedHistorySample(std::vector<double>* historyList, double sampleValue) const;
    UtilizationStatisticSnapshot buildStatisticSnapshot(const std::vector<double>& historyList) const;
    QString buildPercentStatisticLine(const QString& labelText, const UtilizationStatisticSnapshot& snapshot) const;
    QString buildRateStatisticLine(const QString& labelText, const UtilizationStatisticSnapshot& snapshot) const;
    QString buildTrendText(const UtilizationStatisticSnapshot& snapshot, bool percentUnit) const;
    QString buildPressureLevelText(double percentValue) const;
    QString buildR0CpuFeatureBadgeText(std::uint64_t featureMask) const;
    void refreshStaticHardwareTexts(bool forceRefresh);
    void requestAsyncStaticInfoRefresh();
    // requestAsyncDeviceAuditRefresh:
    // - Request the current visible device stack/input stack/USB/PnP pages by bit to avoid periodic full-query refreshes;
    // - Re-entrant requests are merged into the pending mask; there is always only one device audit worker thread.
    void requestAsyncDeviceAuditRefresh(std::uint32_t refreshMask);
    // applyDeviceAuditRefreshResult:
    // - Atomically replace the three sets of device audit caches and refresh the associated table in the GUI thread.
    // - Delay full results when any associated table menu is open to avoid cache and table row generation mismatches.
    void applyDeviceAuditRefreshResult(
        std::uint32_t requestedMask,
        DeviceAuditViewSnapshot deviceStackSnapshot,
        DeviceAuditViewSnapshot inputStackSnapshot,
        DeviceAuditViewSnapshot usbTopologySnapshot,
        QString pnpAcpiPciText);
    void requestAsyncSensorRefresh();
    void requestAsyncR0HardwareHealthRefresh();
    void refreshCpuTopologyStaticInfo();
    void refreshSystemVolumeInfo();

    // ===================== Text Collection =====================
    QString buildOverviewStaticText() const;
    QString buildGpuStaticText() const;
    QString buildMemoryStaticText() const;
    QString buildCpuSensorText(bool forceRefresh);
    QString buildDeviceStackStaticText() const;
    QString buildKeyboardMouseHidStaticText() const;
    QString buildUsbTopologyStaticText() const;
    static DeviceAuditViewSnapshot buildDeviceStackAuditViewSnapshot();
    static DeviceAuditViewSnapshot buildKeyboardMouseHidAuditViewSnapshot();
    static DeviceAuditViewSnapshot buildUsbTopologyAuditViewSnapshot();
    static QString buildPnpAcpiPciStaticText();

private:
    // DeviceAuditRefreshFlag: Static diagnostic page refresh bits for on-demand updates, used to merge requests during rapid page switching.
    enum DeviceAuditRefreshFlag : std::uint32_t
    {
        kDeviceStackAuditRefresh = 0x00000001U, // DeviceStackAuditRefresh: Device stack page.
        kInputStackAuditRefresh = 0x00000002U,  // InputStackAuditRefresh: Keyboard/mouse/HID input stack page.
        kUsbTopologyAuditRefresh = 0x00000004U, // UsbTopologyAuditRefresh: USB topology page.
        kPnpAcpiPciRefresh = 0x00000008U,       // PnpAcpiPciRefresh: PnP/ACPI/PCI text page.
        kAllDeviceAuditRefresh = kDeviceStackAuditRefresh |
            kInputStackAuditRefresh |
            kUsbTopologyAuditRefresh |
            kPnpAcpiPciRefresh
    };

    // Top-level structure.
    QVBoxLayout* rootLayout_ = nullptr;    // m_rootLayout: Root layout.
    QTabWidget* sideTabWidget_ = nullptr;  // m_sideTabWidget: Top horizontal hardware tab container (retains old member name to avoid unrelated refactoring).
    QTimer* refreshTimer_ = nullptr;       // m_refreshTimer: 1-second sampling timer.

    // Overview page.
    QWidget* overviewPage_ = nullptr;           // m_overviewPage: Overview tab.
    QVBoxLayout* overviewLayout_ = nullptr;     // m_overviewLayout: Overview layout.
    QLabel* overviewSummaryLabel_ = nullptr;    // m_overviewSummaryLabel: Real-time summary label.
    CodeEditorWidget* overviewEditor_ = nullptr; // m_overviewEditor: Static hardware inventory text.

    // Utilization page (Task Manager style).
    QWidget* utilizationPage_ = nullptr;          // m_utilizationPage: Utilization tab.
    QVBoxLayout* utilizationLayout_ = nullptr;    // m_utilizationLayout: Outer layout for utilization.
    QSplitter* utilizationBodySplitter_ = nullptr; // m_utilizationBodySplitter: Draggable left-right splitter.
    bool utilizationSplitterInitialSizeApplied_ = false; // m_utilizationSplitterInitialSizeApplied: Indicates whether the 300px default left column has been applied.
    QListWidget* utilizationSidebarList_ = nullptr; // m_utilizationSidebarList: Left-side performance card list.
    QStackedWidget* utilizationDetailStack_ = nullptr; // m_utilizationDetailStack: Right-side detail page stack.
    std::vector<UtilizationNavEntry> utilizationNavEntries_; // m_utilizationNavEntries: Mapping from the left card to the right page.

    // Left performance card.
    PerformanceNavCard* cpuNavCard_ = nullptr;      // m_cpuNavCard: CPU navigation card.
    PerformanceNavCard* memoryNavCard_ = nullptr;   // m_memoryNavCard: Memory navigation card.
    PerformanceNavCard* diskNavCard_ = nullptr;     // m_diskNavCard: Compatible with legacy aggregated disk cards; null in current dynamic device mode.
    PerformanceNavCard* networkNavCard_ = nullptr;  // m_networkNavCard: Compatible with legacy aggregated network card; null in current dynamic device mode.
    PerformanceNavCard* gpuNavCard_ = nullptr;      // m_gpuNavCard: Compatible with legacy aggregated GPU cards; null in current dynamic device mode.

    // Utilization detail page: CPU.
    QWidget* utilizationCpuSubPage_ = nullptr;    // m_utilizationCpuSubPage: CPU detail page.
    QLabel* cpuModelLabel_ = nullptr;             // m_cpuModelLabel: CPU model label.
    QLabel* utilizationSummaryLabel_ = nullptr;   // m_utilizationSummaryLabel: Text description for the CPU chart.
    QScrollArea* coreChartScrollArea_ = nullptr;  // m_coreChartScrollArea: CPU core chart scroll container.
    QWidget* coreChartHostWidget_ = nullptr;      // m_coreChartHostWidget: CPU core chart host.
    QGridLayout* coreChartGridLayout_ = nullptr;  // m_coreChartGridLayout: CPU core chart matrix layout.
    QLabel* cpuUtilPrimaryDetailLabel_ = nullptr; // m_cpuUtilPrimaryDetailLabel: Large key metric label on the left side of the CPU display.
    QLabel* cpuUtilSecondaryDetailLabel_ = nullptr; // m_cpuUtilSecondaryDetailLabel: First column of hardware parameters to the right of CPU.
    QLabel* cpuUtilTertiaryDetailLabel_ = nullptr; // m_cpuUtilTertiaryDetailLabel: Cache and R0 summary in the second column to the right of the CPU.

    // Utilization detail page: Memory.
    QWidget* utilizationMemorySubPage_ = nullptr;   // m_utilizationMemorySubPage: Memory details page.
    QLabel* memoryCapacityLabel_ = nullptr;         // m_memoryCapacityLabel: Total memory capacity label.
    QLabel* memoryUtilSummaryLabel_ = nullptr;      // m_memoryUtilSummaryLabel: Memory summary text.
    MemoryCompositionHistoryWidget* memoryCompositionHistoryWidget_ = nullptr; // m_memoryCompositionHistoryWidget: Memory history and composition merge chart.
    QLabel* memoryUtilPrimaryDetailLabel_ = nullptr; // m_memoryUtilPrimaryDetailLabel: Text for the primary memory usage parameter on the left.
    QLabel* memoryUtilSecondaryDetailLabel_ = nullptr; // m_memoryUtilSecondaryDetailLabel: Text for the secondary memory parameter on the right.

    // Utilization detail page: Disk.
    QWidget* utilizationDiskSubPage_ = nullptr;   // m_utilizationDiskSubPage: Disk detail page.
    QLabel* diskUtilSummaryLabel_ = nullptr;      // m_diskUtilSummaryLabel: Disk summary text.
    QChartView* diskUtilChartView_ = nullptr;     // m_diskUtilChartView: View for the disk utilization trend chart.
    QLineSeries* diskReadLineSeries_ = nullptr;   // m_diskReadLineSeries: Disk read rate line series.
    QLineSeries* diskReadBaselineSeries_ = nullptr; // m_diskReadBaselineSeries: Disk read rate 0-axis baseline.
    QAreaSeries* diskReadAreaSeries_ = nullptr;   // m_diskReadAreaSeries: Disk read throughput fill area.
    QLineSeries* diskWriteLineSeries_ = nullptr;  // m_diskWriteLineSeries: Disk write rate line series.
    QLineSeries* diskWriteBaselineSeries_ = nullptr; // m_diskWriteBaselineSeries: Disk write rate 0-axis baseline.
    QAreaSeries* diskWriteAreaSeries_ = nullptr;  // m_diskWriteAreaSeries: Disk write rate fill area.
    QValueAxis* diskUtilAxisX_ = nullptr;         // m_diskUtilAxisX: Disk chart X-axis.
    QValueAxis* diskUtilAxisY_ = nullptr;         // m_diskUtilAxisY: Disk chart Y-axis.
    QLabel* diskUtilDetailLabel_ = nullptr;       // m_diskUtilDetailLabel: Disk parameter text.

    // Utilization detail page: Network.
    QWidget* utilizationNetworkSubPage_ = nullptr; // m_utilizationNetworkSubPage: Network details page.
    QLabel* networkUtilSummaryLabel_ = nullptr;    // m_networkUtilSummaryLabel: Network summary text.
    QChartView* networkUtilChartView_ = nullptr;   // m_networkUtilChartView: Network trend chart view.
    QLineSeries* networkRxLineSeries_ = nullptr;   // m_networkRxLineSeries: Network download line series.
    QLineSeries* networkRxBaselineSeries_ = nullptr; // m_networkRxBaselineSeries: Network receive 0-axis baseline.
    QAreaSeries* networkRxAreaSeries_ = nullptr;   // m_networkRxAreaSeries: Network receive area series.
    QLineSeries* networkTxLineSeries_ = nullptr;   // m_networkTxLineSeries: Network upload line series.
    QLineSeries* networkTxBaselineSeries_ = nullptr; // m_networkTxBaselineSeries: Network transmit 0-axis baseline.
    QAreaSeries* networkTxAreaSeries_ = nullptr;   // m_networkTxAreaSeries: Network upload fill area.
    QValueAxis* networkUtilAxisX_ = nullptr;       // m_networkUtilAxisX: Network graph X-axis.
    QValueAxis* networkUtilAxisY_ = nullptr;       // m_networkUtilAxisY: Network graph Y-axis.
    QLabel* networkUtilDetailLabel_ = nullptr;     // m_networkUtilDetailLabel: Network parameter text.

    // Utilization detail page: GPU.
    QWidget* utilizationGpuSubPage_ = nullptr;    // m_utilizationGpuSubPage: GPU detail page.
    QLabel* gpuAdapterTitleLabel_ = nullptr;      // m_gpuAdapterTitleLabel: GPU title area adapter text.
    QLabel* gpuUtilSummaryLabel_ = nullptr;       // m_gpuUtilSummaryLabel: GPU summary text.
    QWidget* gpuEngineHostWidget_ = nullptr;      // m_gpuEngineHostWidget: GPU engine thumbnail host widget.
    QGridLayout* gpuEngineGridLayout_ = nullptr;  // m_gpuEngineGridLayout: GPU engine thumbnail grid layout.
    std::vector<GpuEngineChartEntry> gpuEngineCharts_; // m_gpuEngineCharts: List of GPU engine charts.
    QChartView* gpuDedicatedMemoryChartView_ = nullptr; // m_gpuDedicatedMemoryChartView: Dedicated VRAM curve chart.
    QLineSeries* gpuDedicatedMemoryLineSeries_ = nullptr; // m_gpuDedicatedMemoryLineSeries: Dedicated GPU memory usage curve.
    QLineSeries* gpuDedicatedMemoryBaselineSeries_ = nullptr; // m_gpuDedicatedMemoryBaselineSeries: Dedicated video memory baseline on the 0-axis.
    QAreaSeries* gpuDedicatedMemoryAreaSeries_ = nullptr; // m_gpuDedicatedMemoryAreaSeries: Dedicated GPU memory fill area.
    QValueAxis* gpuDedicatedMemoryAxisX_ = nullptr; // m_gpuDedicatedMemoryAxisX: Dedicated memory graph X-axis.
    QValueAxis* gpuDedicatedMemoryAxisY_ = nullptr; // m_gpuDedicatedMemoryAxisY: Dedicated memory graph Y-axis.
    QChartView* gpuSharedMemoryChartView_ = nullptr; // m_gpuSharedMemoryChartView: Shared video memory chart.
    QLineSeries* gpuSharedMemoryLineSeries_ = nullptr; // m_gpuSharedMemoryLineSeries: Shared video memory usage curve.
    QLineSeries* gpuSharedMemoryBaselineSeries_ = nullptr; // m_gpuSharedMemoryBaselineSeries: Shared memory 0-axis baseline series.
    QAreaSeries* gpuSharedMemoryAreaSeries_ = nullptr; // m_gpuSharedMemoryAreaSeries: Shared video memory fill area.
    QValueAxis* gpuSharedMemoryAxisX_ = nullptr;   // m_gpuSharedMemoryAxisX: Shared VRAM graph X-axis.
    QValueAxis* gpuSharedMemoryAxisY_ = nullptr;   // m_gpuSharedMemoryAxisY: Shared VRAM graph Y-axis.
    QLabel* gpuUtilDetailLabel_ = nullptr;        // m_gpuUtilDetailLabel: GPU parameter text.

    // Per-core GPU cache.
    std::vector<CoreChartEntry> coreChartEntries_; // m_coreChartEntries: Per-core chart control cache.
    int cpuCoreGridColumnCount_ = 1;             // m_cpuCoreGridColumnCount: Number of columns in the CPU core grid.
    int cpuCoreGridRowCount_ = 1;                // m_cpuCoreGridRowCount: Number of rows in the CPU small chart grid.

    // CPU details page (original text/table page).
    QWidget* cpuPage_ = nullptr;             // m_cpuPage：CPU Tab。
    QVBoxLayout* cpuLayout_ = nullptr;       // m_cpuLayout: CPU layout.
    QLabel* cpuDetailLabel_ = nullptr;       // m_cpuDetailLabel: Summary label for temperature, voltage, etc.
    QTableWidget* cpuDetailTable_ = nullptr; // m_cpuDetailTable: Table showing details per core.
    HardwarePowerPage* powerPage_ = nullptr; // m_powerPage: CPU power and performance adjustment tab.
    HardwareR0EvidencePage* r0EvidencePage_ = nullptr; // m_r0EvidencePage: R0 hardware evidence page.

    // GPU and memory pages (original text page).
    QWidget* gpuPage_ = nullptr;               // m_gpuPage: GPU tab.
    QVBoxLayout* gpuLayout_ = nullptr;         // m_gpuLayout: GPU layout.
    CodeEditorWidget* gpuEditor_ = nullptr;    // m_gpuEditor: GPU details text.
    QWidget* memoryPage_ = nullptr;            // m_memoryPage: Memory tab.
    QVBoxLayout* memoryLayout_ = nullptr;      // m_memoryLayout: Memory layout.
    CodeEditorWidget* memoryEditor_ = nullptr; // m_memoryEditor: Memory details text.
    QWidget* diskMonitorHostPage_ = nullptr;      // m_diskMonitorHostPage: Lazy-loaded host page for disk monitoring.
    HardwareDeviceManagerPage* deviceManagerPage_ = nullptr; // m_deviceManagerPage: SetupAPI/CfgMgr device management page.
    HardwareHwidDispatchPage* hwidDispatchPage_ = nullptr; // m_hwidDispatchPage: HWID Dispatch page.
    QWidget* otherDevicesHostPage_ = nullptr;     // m_otherDevicesHostPage: Other devices host page for lazy loading.
    DiskMonitorPage* diskMonitorPage_ = nullptr;  // m_diskMonitorPage: Actual disk monitoring page, created upon first entry into the sub-tab.
    HardwareOtherDevicesPage* otherDevicesPage_ = nullptr; // m_otherDevicesPage: Real page for other hardware devices, created upon first entry to the sub-tab.
    QWidget* deviceStackPage_ = nullptr;          // m_deviceStackPage: DevNode/device stack read-only page.
    CodeEditorWidget* deviceStackEditor_ = nullptr; // m_deviceStackEditor: DevNode/device stack text.
    QTableWidget* deviceStackTable_ = nullptr;     // m_deviceStackTable: DevNode/device stack R0 detail table.
    QWidget* keyboardMouseHidPage_ = nullptr;     // m_keyboardMouseHidPage: Read-only page for keyboard/mouse and HID devices.
    CodeEditorWidget* keyboardMouseHidEditor_ = nullptr; // m_keyboardMouseHidEditor: Keyboard/mouse and HID text editor.
    QTableWidget* keyboardMouseHidTable_ = nullptr; // m_keyboardMouseHidTable: R0 detail table for input devices.
    HardwareI8042AuditPage* i8042AuditPage_ = nullptr; // m_i8042AuditPage: i8042prt/keyboard-mouse driver combination audit page.
    QWidget* usbTopologyPage_ = nullptr;          // m_usbTopologyPage: USB topology read-only page.
    CodeEditorWidget* usbTopologyEditor_ = nullptr; // m_usbTopologyEditor: USB topology text editor.
    QTableWidget* usbTopologyTable_ = nullptr;     // m_usbTopologyTable: USB topology R0 detail table.
    QWidget* pnpAcpiPciPage_ = nullptr;           // m_pnpAcpiPciPage: PnP/ACPI/PCI read-only page.
    CodeEditorWidget* pnpAcpiPciEditor_ = nullptr; // m_pnpAcpiPciEditor: PnP/ACPI/PCI text editor.

    // Runtime status cache.
    int historyLength_ = 60;                 // m_historyLength: Number of points retained in the curve.
    int sampleCounter_ = 60;                 // m_sampleCounter: Sample index (starts from historical length to avoid empty initial segment).
    QString cachedSensorText_;               // m_cachedSensorText: CPU temperature/voltage cache.
    QString lastSensorLogSignatureText_;     // m_lastSensorLogSignatureText: Deduplicated signature of the most recent sensor log.
    QString cachedOverviewStaticText_;       // m_cachedOverviewStaticText: Cached overview static text.
    QString cachedGpuStaticText_;            // m_cachedGpuStaticText: GPU static text cache.
    QString cachedMemoryStaticText_;         // m_cachedMemoryStaticText: Cached static text for memory.
    QString cachedDeviceStackStaticText_;     // m_cachedDeviceStackStaticText: DevNode/device stack cache.
    QString cachedKeyboardMouseHidStaticText_; // m_cachedKeyboardMouseHidStaticText: Keyboard/mouse and HID cache.
    QString cachedUsbTopologyStaticText_;     // m_cachedUsbTopologyStaticText: USB topology cache.
    QVector<QStringList> cachedDeviceStackRows_; // m_cachedDeviceStackRows: Cache for DevNode/device stack table rows.
    QVector<QStringList> cachedKeyboardMouseHidRows_; // m_cachedKeyboardMouseHidRows: Cached rows for keyboard/mouse/HID tables.
    QVector<QStringList> cachedUsbTopologyRows_; // m_cachedUsbTopologyRows: Cached USB topology table rows.
    QString cachedPnpAcpiPciStaticText_;      // m_cachedPnpAcpiPciStaticText: PnP/ACPI/PCI cache.
    std::atomic_bool staticInfoRefreshing_{ false }; // m_staticInfoRefreshing: Static info asynchronous refresh flag.
    std::atomic_bool deviceAuditRefreshing_{ false }; // m_deviceAuditRefreshing: Lock for asynchronous device audit refresh.
    std::atomic<std::uint32_t> pendingDeviceAuditRefreshMask_{ 0U }; // m_pendingDeviceAuditRefreshMask: Merged page refresh mask during re-entry.
    std::atomic_bool sensorRefreshing_{ false };     // m_sensorRefreshing: Sensor asynchronous refresh lock.
    std::atomic_bool r0HardwareHealthRefreshing_{ false }; // m_r0HardwareHealthRefreshing: R0 hardware health asynchronous refresh lock.
    bool initialSamplingStarted_ = false;            // m_initialSamplingStarted: Whether the initial sampling started upon first display.
    bool driverHealthSamplingEnabled_ = false;        // m_driverHealthSamplingEnabled: Whether to allow periodic triggering of R0 health queries.
    std::uint64_t lastNetworkRxBytes_ = 0;           // m_lastNetworkRxBytes: Cumulative received bytes compatible with legacy aggregated network sampling.
    std::uint64_t lastNetworkTxBytes_ = 0;           // m_lastNetworkTxBytes: Cumulative sent bytes compatible with legacy aggregated network sampling.
    qint64 lastNetworkSampleMs_ = 0;                 // m_lastNetworkSampleMs: Compatible with legacy aggregated network sample timestamp (ms).
    QString primaryNetworkAdapterName_;              // m_primaryNetworkAdapterName: Current primary active network adapter name.
    std::uint64_t primaryNetworkLinkBitsPerSecond_ = 0; // m_primaryNetworkLinkBitsPerSecond: Primary network link speed.

    // Task Manager details view cache.
    QString cpuModelText_;                  // m_cpuModelText: CPU model text.
    int cpuPackageCount_ = 0;               // m_cpuPackageCount: Number of CPU packages.
    int cpuPhysicalCoreCount_ = 0;          // m_cpuPhysicalCoreCount: Number of physical cores.
    int cpuLogicalCoreCount_ = 0;           // m_cpuLogicalCoreCount: Number of logical cores.
    std::uint64_t cpuL1CacheBytes_ = 0;     // m_cpuL1CacheBytes: Total L1 cache size in bytes.
    std::uint64_t cpuL2CacheBytes_ = 0;     // m_cpuL2CacheBytes: Total L2 cache size in bytes.
    std::uint64_t cpuL3CacheBytes_ = 0;     // m_cpuL3CacheBytes: Total L3 cache size in bytes.
    double lastCpuSpeedGhz_ = 0.0;          // m_lastCpuSpeedGhz: Last recorded CPU speed (GHz).
    qint64 lastR0HardwareHealthRefreshMs_ = 0; // m_lastR0HardwareHealthRefreshMs: timestamp of the last R0 hardware health refresh.
    QString r0HardwareHealthSummaryText_ = QStringLiteral("R0硬件健康: 等待采样"); // m_r0HardwareHealthSummaryText: Utilization page R0 health summary.
    QString r0HardwareHealthDetailText_ = QStringLiteral("R0 CPU/MSR/IDT 证据尚未采样。"); // m_r0HardwareHealthDetailText: Summary of R0 evidence details on the CPU detail page.
    QString r0CpuHardwareSummaryText_ = QStringLiteral("R0 CPU硬件: 等待采样"); // m_r0CpuHardwareSummaryText: R0 CPUID summary.
    QString r0CpuHardwareDetailText_ = QStringLiteral("R0 CPUID 硬件快照尚未采样。"); // m_r0CpuHardwareDetailText: R0 CPU feature details.
    QString r0PhysicalMemorySummaryText_ = QStringLiteral("R0物理内存: 等待采样"); // m_r0PhysicalMemorySummaryText: R0 physical memory layout summary.
    QString r0PhysicalMemoryDetailText_ = QStringLiteral("R0 物理内存布局尚未采样。"); // m_r0PhysicalMemoryDetailText: R0 memory range statistics details.

    int memorySpeedMhz_ = 0;                // m_memorySpeedMhz: Memory clock speed (MHz).
    int memorySlotUsed_ = 0;                // m_memorySlotUsed: Number of used memory slots.
    int memorySlotTotal_ = 0;               // m_memorySlotTotal: The total number of memory slots.
    QString memoryFormFactorText_;          // m_memoryFormFactorText: Memory form factor text.

    QString gpuAdapterNameText_;            // m_gpuAdapterNameText: GPU adapter name.
    QString gpuDriverVersionText_;          // m_gpuDriverVersionText: GPU driver version.
    QString gpuDriverDateText_;             // m_gpuDriverDateText: GPU driver date text.
    QString gpuPnpDeviceIdText_;            // m_gpuPnpDeviceIdText: GPU PNP device ID.
    double gpuCurrentCoreClockMhz_ = 0.0;    // m_gpuCurrentCoreClockMhz: Current GPU 3D core frequency in MHz.
    double gpuMaxCoreClockMhz_ = 0.0;        // m_gpuMaxCoreClockMhz: Maximum GPU 3D core frequency in MHz.
    double gpuCurrentMemoryClockMhz_ = 0.0;  // m_gpuCurrentMemoryClockMhz: Current VRAM frequency in MHz.
    double gpuMaxMemoryClockMhz_ = 0.0;      // m_gpuMaxMemoryClockMhz: Maximum GPU memory clock frequency in MHz.
    double gpuDedicatedMemoryGiB_ = 0.0;    // m_gpuDedicatedMemoryGiB: GPU dedicated VRAM (GiB).
    double gpuSharedMemoryGiB_ = 0.0;       // m_gpuSharedMemoryGiB: GPU available shared system memory (GiB).
    double gpuUsage3DPercent_ = 0.0;        // m_gpuUsage3DPercent: 3D engine utilization.
    double gpuUsageCopyPercent_ = 0.0;      // m_gpuUsageCopyPercent: Copy engine utilization percentage.
    double gpuUsageVideoEncodePercent_ = 0.0; // m_gpuUsageVideoEncodePercent: Video encode engine utilization.
    double gpuUsageVideoDecodePercent_ = 0.0; // m_gpuUsageVideoDecodePercent: Video decode engine utilization.
    double gpuDedicatedUsedGiB_ = 0.0;      // m_gpuDedicatedUsedGiB: Current usage of dedicated GPU memory.
    bool gpuDedicatedUsageAvailable_ = false; // m_gpuDedicatedUsageAvailable: Whether dedicated memory system usage sampling is valid.
    double gpuDedicatedBudgetGiB_ = 0.0;    // m_gpuDedicatedBudgetGiB: Dedicated video memory budget limit.
    double gpuSharedUsedGiB_ = 0.0;         // m_gpuSharedUsedGiB: Current usage of shared video memory.
    bool gpuSharedUsageAvailable_ = false;  // m_gpuSharedUsageAvailable: Whether shared GPU memory system usage sampling is valid.
    double gpuSharedBudgetGiB_ = 0.0;       // m_gpuSharedBudgetGiB: Shared GPU memory budget limit.

    QString systemVolumeText_;              // m_systemVolumeText: System volume label text.
    std::uint64_t systemVolumeTotalBytes_ = 0; // m_systemVolumeTotalBytes: Total capacity of the system volume in bytes.
    std::uint64_t systemVolumeFreeBytes_ = 0;  // m_systemVolumeFreeBytes: Remaining capacity of the system volume in bytes.

    double diskNavAutoScaleBytesPerSec_ = 1024.0 * 1024.0; // m_diskNavAutoScaleBytesPerSec: Compatibility upper limit for dynamic scaling of the legacy aggregated disk page.
    double networkNavAutoScaleBytesPerSec_ = 1024.0 * 1024.0; // m_networkNavAutoScaleBytesPerSec: Compatibility with the dynamic scaling upper limit of legacy aggregated network pages.
    std::vector<double> cpuUsageHistoryPercent_; // m_cpuUsageHistoryPercent: Historical CPU overall utilization, used for window statistics.
    std::vector<double> memoryUsageHistoryPercent_; // m_memoryUsageHistoryPercent: Memory utilization history for window statistics.
    std::vector<double> gpuUsageHistoryPercent_; // m_gpuUsageHistoryPercent: Historical GPU overall utilization for window statistics.
    std::vector<double> diskAggregateHistoryBytesPerSec_; // m_diskAggregateHistoryBytesPerSec: Historical disk aggregate throughput.
    std::vector<double> networkAggregateHistoryBytesPerSec_; // m_networkAggregateHistoryBytesPerSec: Network aggregate throughput history.
    std::vector<double> memoryNavUsedHistoryPercent_; // m_memoryNavUsedHistoryPercent: History of memory usage percentage for the thumbnail view.
    std::vector<double> memoryNavCachedHistoryPercent_; // m_memoryNavCachedHistoryPercent: Memory cache/pool thumbnail history.
    std::vector<double> diskNavReadHistoryBytesPerSec_; // m_diskNavReadHistoryBytesPerSec: Compatibility for the legacy aggregated disk card read history.
    std::vector<double> diskNavWriteHistoryBytesPerSec_; // m_diskNavWriteHistoryBytesPerSec: Compatible with legacy aggregated disk card write history.
    std::vector<double> networkNavRxHistoryBytesPerSec_; // m_networkNavRxHistoryBytesPerSec: Compatible with historical data for old aggregated network cards (downlink).
    std::vector<double> networkNavTxHistoryBytesPerSec_; // m_networkNavTxHistoryBytesPerSec: Compatible with historical data for old aggregated network cards (uplink).
    std::vector<DiskUtilizationDevice> diskUtilDevices_; // m_diskUtilDevices: Multi-device page for disk utilization.
    std::vector<NetworkUtilizationDevice> networkUtilDevices_; // m_networkUtilDevices: Network utilization multi-device page.
    std::vector<GpuUtilizationDevice> gpuUtilDevices_; // m_gpuUtilDevices: GPU utilization multi-device page.

    // PDH performance counter handle (using void* to avoid including Windows-specific headers).
    void* cpuPerfQueryHandle_ = nullptr;     // m_cpuPerfQueryHandle: PDH query handle.
    std::vector<void*> coreCounterHandles_;  // m_coreCounterHandles: Per-core utilization counter handles.
    void* cpuPerformanceCounterHandle_ = nullptr; // m_cpuPerformanceCounterHandle: CPU overall performance percentage counter.
    void* cpuFrequencyCounterHandle_ = nullptr; // m_cpuFrequencyCounterHandle: CPU base frequency counter.
    void* diskPerfQueryHandle_ = nullptr;    // m_diskPerfQueryHandle: Disk throughput query handle.
    void* diskReadCounterHandle_ = nullptr;  // m_diskReadCounterHandle: Disk read rate counter handle.
    void* diskWriteCounterHandle_ = nullptr; // m_diskWriteCounterHandle: Disk write rate counter handle.
    void* gpuPerfQueryHandle_ = nullptr;     // m_gpuPerfQueryHandle: GPU utilization query handle.
    void* gpuCounterHandle_ = nullptr;       // m_gpuCounterHandle: GPU engine utilization counter handle.
    void* gpuDedicatedMemoryCounterHandle_ = nullptr; // m_gpuDedicatedMemoryCounterHandle: Handle to the system dedicated video memory usage counter.
    void* gpuSharedMemoryCounterHandle_ = nullptr; // m_gpuSharedMemoryCounterHandle: System shared video memory usage counter handle.
};
