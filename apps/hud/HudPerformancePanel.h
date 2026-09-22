#pragma once

#include <QWidget>
#include <QFutureWatcher>
#include <QMutex>

#include <atomic>
#include <cstdint>
#include <vector>

class PerformanceNavCard;
class QChartView;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineSeries;
class QListWidget;
class QResizeEvent;
class QScrollArea;
class QShowEvent;
class QStackedWidget;
class QTimer;
class QValueAxis;

class HudPerformancePanel final : public QWidget
{
public:
    explicit HudPerformancePanel(QWidget* parent = nullptr);
    ~HudPerformancePanel() override;

protected:
    void resizeEvent(QResizeEvent* resizeEventPointer) override;
    void showEvent(QShowEvent* showEventPointer) override;

private:
    struct CoreChartEntry
    {
        QWidget* containerWidget = nullptr;
        QLabel* titleLabel = nullptr;
        QWidget* chartWidget = nullptr;
    };

    struct GpuEngineChartEntry
    {
        QString engineKeyText;
        QString displayNameText;
        QLabel* titleLabel = nullptr;
        QChartView* chartView = nullptr;
        QLineSeries* lineSeries = nullptr;
        QValueAxis* axisX = nullptr;
        QValueAxis* axisY = nullptr;
    };

    struct CpuPowerSnapshot
    {
        std::uint32_t coreIndex = 0;
        std::uint32_t currentMhz = 0;
        std::uint32_t maxMhz = 0;
        std::uint32_t limitMhz = 0;
    };

    struct SystemPerformanceSnapshot
    {
        std::uint32_t processCount = 0;
        std::uint32_t threadCount = 0;
        std::uint32_t handleCount = 0;
        std::uint64_t commitTotalBytes = 0;
        std::uint64_t commitLimitBytes = 0;
        std::uint64_t cachedBytes = 0;
        std::uint64_t pagedPoolBytes = 0;
        std::uint64_t nonPagedPoolBytes = 0;
    };

    struct LiveSampleResult
    {
        bool perCoreOk = false;
        std::vector<double> coreUsageList;
        double totalCpuUsage = 0.0;
        bool powerInfoOk = false;
        std::vector<CpuPowerSnapshot> powerInfoList;
        bool memoryOk = false;
        double memoryUsagePercent = 0.0;
        std::uint64_t totalPhysBytes = 0;
        std::uint64_t availPhysBytes = 0;
        bool diskOk = false;
        double diskReadBytesPerSec = 0.0;
        double diskWriteBytesPerSec = 0.0;
        bool networkOk = false;
        double networkRxBytesPerSec = 0.0;
        double networkTxBytesPerSec = 0.0;
        bool gpuOk = false;
        double gpuUsagePercent = 0.0;
        bool systemPerfOk = false;
        SystemPerformanceSnapshot systemPerfSnapshot;
        QString primaryNetworkAdapterName;
        std::uint64_t primaryNetworkLinkBitsPerSecond = 0;
        double gpuUsage3DPercent = 0.0;
        double gpuUsageCopyPercent = 0.0;
        double gpuUsageVideoEncodePercent = 0.0;
        double gpuUsageVideoDecodePercent = 0.0;
        double gpuDedicatedUsedGiB = 0.0;
        double gpuDedicatedBudgetGiB = 0.0;
        double gpuSharedUsedGiB = 0.0;
        double gpuSharedBudgetGiB = 0.0;
        QString systemVolumeText;
        std::uint64_t systemVolumeTotalBytes = 0;
        std::uint64_t systemVolumeFreeBytes = 0;
    };

    void initializeUi();
    void initializeSidebarCards();
    void initializeCpuPage();
    void initializeMemoryPage();
    void initializeDiskPage();
    void initializeNetworkPage();
    void initializeGpuPage();
    void initializeCoreCharts();
    void syncSidebarSelection(int selectedRowIndex);
    void adjustChartHeights();

    void initializePerformanceCounters();
    void refreshAllViews();
    void requestLiveRefresh();
    LiveSampleResult collectLiveSampleResult();
    void applyLiveSampleResult(const LiveSampleResult& liveSampleResult);
    bool samplePerCoreUsage(std::vector<double>* coreUsageOut, double* totalUsageOut);
    bool sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut);
    bool sampleMemoryUsage(double* memoryUsagePercentOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    bool sampleGpuUsage(double* gpuUsagePercentOut);
    bool sampleGpuMemoryInfoByDxgi();
    bool sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const;

    void updateView(
        const std::vector<double>& coreUsageList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateSidebarCards(
        double cpuUsagePercent,
        double memoryUsagePercent,
        std::uint64_t totalPhysBytes,
        std::uint64_t availPhysBytes,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateTaskManagerDetailLabels(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent,
        const SystemPerformanceSnapshot* systemPerfSnapshotPointer,
        bool systemPerfOk);
    void appendCoreSeriesPoint(CoreChartEntry& chartEntry, double usagePercent);
    void appendGeneralSeriesPoint(
        QLineSeries* lineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0);
    QString formatRateText(double bytesPerSecondValue) const;

    void requestAsyncStaticInfoRefresh();
    void requestAsyncSensorRefresh();
    void refreshCpuTopologyStaticInfo();
    void refreshSystemVolumeInfo();
    QString buildCpuSensorText(bool forceRefresh);

private:
    QHBoxLayout* bodyLayout_ = nullptr;
    QListWidget* sidebarList_ = nullptr;
    QStackedWidget* detailStack_ = nullptr;
    QTimer* refreshTimer_ = nullptr;
    QFutureWatcher<LiveSampleResult>* liveSampleWatcher_ = nullptr;
    QMutex liveSampleMutex_;
    bool liveSampleInProgress_ = false;

    PerformanceNavCard* cpuNavCard_ = nullptr;
    PerformanceNavCard* memoryNavCard_ = nullptr;
    PerformanceNavCard* diskNavCard_ = nullptr;
    PerformanceNavCard* networkNavCard_ = nullptr;
    PerformanceNavCard* gpuNavCard_ = nullptr;

    QWidget* cpuPage_ = nullptr;
    QLabel* cpuModelLabel_ = nullptr;
    QLabel* cpuSummaryLabel_ = nullptr;
    QScrollArea* coreChartScrollArea_ = nullptr;
    QWidget* coreChartHostWidget_ = nullptr;
    QGridLayout* coreChartGridLayout_ = nullptr;
    QLabel* cpuPrimaryDetailLabel_ = nullptr;
    QLabel* cpuSecondaryDetailLabel_ = nullptr;

    QWidget* memoryPage_ = nullptr;
    QLabel* memoryCapacityLabel_ = nullptr;
    QLabel* memorySummaryLabel_ = nullptr;
    QChartView* memoryChartView_ = nullptr;
    QLineSeries* memoryLineSeries_ = nullptr;
    QValueAxis* memoryAxisX_ = nullptr;
    QValueAxis* memoryAxisY_ = nullptr;
    QLabel* memoryPrimaryDetailLabel_ = nullptr;
    QLabel* memorySecondaryDetailLabel_ = nullptr;

    QWidget* diskPage_ = nullptr;
    QLabel* diskSummaryLabel_ = nullptr;
    QChartView* diskChartView_ = nullptr;
    QLineSeries* diskReadLineSeries_ = nullptr;
    QLineSeries* diskWriteLineSeries_ = nullptr;
    QValueAxis* diskAxisX_ = nullptr;
    QValueAxis* diskAxisY_ = nullptr;
    QLabel* diskDetailLabel_ = nullptr;

    QWidget* networkPage_ = nullptr;
    QLabel* networkSummaryLabel_ = nullptr;
    QChartView* networkChartView_ = nullptr;
    QLineSeries* networkRxLineSeries_ = nullptr;
    QLineSeries* networkTxLineSeries_ = nullptr;
    QValueAxis* networkAxisX_ = nullptr;
    QValueAxis* networkAxisY_ = nullptr;
    QLabel* networkDetailLabel_ = nullptr;

    QWidget* gpuPage_ = nullptr;
    QLabel* gpuAdapterTitleLabel_ = nullptr;
    QLabel* gpuSummaryLabel_ = nullptr;
    QWidget* gpuEngineHostWidget_ = nullptr;
    QGridLayout* gpuEngineGridLayout_ = nullptr;
    std::vector<GpuEngineChartEntry> gpuEngineCharts_;
    QChartView* gpuDedicatedMemoryChartView_ = nullptr;
    QLineSeries* gpuDedicatedMemoryLineSeries_ = nullptr;
    QValueAxis* gpuDedicatedMemoryAxisX_ = nullptr;
    QValueAxis* gpuDedicatedMemoryAxisY_ = nullptr;
    QChartView* gpuSharedMemoryChartView_ = nullptr;
    QLineSeries* gpuSharedMemoryLineSeries_ = nullptr;
    QValueAxis* gpuSharedMemoryAxisX_ = nullptr;
    QValueAxis* gpuSharedMemoryAxisY_ = nullptr;
    QLabel* gpuDetailLabel_ = nullptr;

    std::vector<CoreChartEntry> coreChartEntries_;
    int cpuCoreGridColumnCount_ = 1;
    int cpuCoreGridRowCount_ = 1;

    int historyLength_ = 60;
    int sampleCounter_ = 60;
    QString cachedSensorText_;
    std::atomic_bool staticInfoRefreshing_{ false };
    std::atomic_bool sensorRefreshing_{ false };
    std::uint64_t lastNetworkRxBytes_ = 0;
    std::uint64_t lastNetworkTxBytes_ = 0;
    qint64 lastNetworkSampleMs_ = 0;
    QString primaryNetworkAdapterName_;
    std::uint64_t primaryNetworkLinkBitsPerSecond_ = 0;

    QString cpuModelText_;
    int cpuPackageCount_ = 0;
    int cpuPhysicalCoreCount_ = 0;
    int cpuLogicalCoreCount_ = 0;
    std::uint64_t cpuL1CacheBytes_ = 0;
    std::uint64_t cpuL2CacheBytes_ = 0;
    std::uint64_t cpuL3CacheBytes_ = 0;
    double lastCpuSpeedGhz_ = 0.0;

    int memorySpeedMhz_ = 0;
    int memorySlotUsed_ = 0;
    int memorySlotTotal_ = 0;
    QString memoryFormFactorText_;

    QString gpuAdapterNameText_;
    QString gpuDriverVersionText_;
    QString gpuDriverDateText_;
    QString gpuPnpDeviceIdText_;
    double gpuDedicatedMemoryGiB_ = 0.0;
    double gpuUsage3DPercent_ = 0.0;
    double gpuUsageCopyPercent_ = 0.0;
    double gpuUsageVideoEncodePercent_ = 0.0;
    double gpuUsageVideoDecodePercent_ = 0.0;
    double gpuDedicatedUsedGiB_ = 0.0;
    double gpuDedicatedBudgetGiB_ = 0.0;
    double gpuSharedUsedGiB_ = 0.0;
    double gpuSharedBudgetGiB_ = 0.0;

    QString systemVolumeText_;
    std::uint64_t systemVolumeTotalBytes_ = 0;
    std::uint64_t systemVolumeFreeBytes_ = 0;
    std::uint64_t lastTotalPhysBytes_ = 0;
    std::uint64_t lastAvailPhysBytes_ = 0;

    double diskNavAutoScaleBytesPerSec_ = 1024.0 * 1024.0;
    double networkNavAutoScaleBytesPerSec_ = 1024.0 * 1024.0;

    void* cpuPerfQueryHandle_ = nullptr;
    std::vector<void*> coreCounterHandles_;
    void* diskPerfQueryHandle_ = nullptr;
    void* diskReadCounterHandle_ = nullptr;
    void* diskWriteCounterHandle_ = nullptr;
    void* gpuPerfQueryHandle_ = nullptr;
    void* gpuCounterHandle_ = nullptr;
};
