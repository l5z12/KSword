#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::initializeUi()
{
    // Root layout and total Tab:
    // - The monitoring page body contains four tabs: Process-oriented, WinAPI, WMI, and ETW.
    // - The performance four-quadrant chart has been moved to the 'Monitor Panel' Dock in the bottom-left corner.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    sideTabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(sideTabWidget_, 1);

    processTraceWidget_ = new ProcessTraceMonitorWidget(sideTabWidget_);
    sideTabWidget_->addTab(
        processTraceWidget_,
        QIcon(QStringLiteral(":/Icon/process_main.svg")),
        QStringLiteral("进程定向"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, processTraceWidget_, QStringLiteral("monitor.tab.process_trace"), QStringLiteral("进程定向"));

    kernelCallbackHostPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* kernelCallbackHostLayout = new QVBoxLayout(kernelCallbackHostPage_);
    kernelCallbackHostLayout->setContentsMargins(0, 0, 0, 0);
    kernelCallbackHostLayout->setSpacing(0);
    kernelCallbackHostLayout->addWidget(
        createMonitorDeferredPlaceholder(
            kernelCallbackHostPage_,
            QStringLiteral("内核回调监控待加载"),
            QStringLiteral("切换到本页后再连接驱动并创建回调事件界面。")),
        1);
    sideTabWidget_->addTab(
        kernelCallbackHostPage_,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        QStringLiteral("内核回调"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        kernelCallbackHostPage_,
        QStringLiteral("monitor.tab.kernel_callback"),
        QStringLiteral("内核回调"));

    directKernelCallHostPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* directKernelCallHostLayout = new QVBoxLayout(directKernelCallHostPage_);
    directKernelCallHostLayout->setContentsMargins(0, 0, 0, 0);
    directKernelCallHostLayout->setSpacing(0);
    directKernelCallHostLayout->addWidget(
        createMonitorDeferredPlaceholder(
            directKernelCallHostPage_,
            QStringLiteral("直接内核调用待加载"),
            QStringLiteral("切换到本页后再解析 syscall 映射并创建 ETW 采集界面。")),
        1);
    sideTabWidget_->addTab(
        directKernelCallHostPage_,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        QStringLiteral("直接内核调用"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        directKernelCallHostPage_,
        QStringLiteral("monitor.tab.direct_kernel_call"),
        QStringLiteral("直接内核调用"));

    winApiPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* winApiPageLayout = new QVBoxLayout(winApiPage_);
    winApiPageLayout->setContentsMargins(0, 0, 0, 0);
    winApiPageLayout->setSpacing(0);
    sideTabWidget_->addTab(
        winApiPage_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("WinAPI"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, winApiPage_, QStringLiteral("monitor.tab.winapi"), QStringLiteral("WinAPI"));

    initializeWmiTab();
    initializeEtwTab();
    initializeArkRiskCenterTab();
}

void MonitorDock::initializePerformancePanel()
{
    // Top performance panel: 2x2 layout displaying CPU/memory bar charts and disk/network line charts.
    perfPanel_ = new QWidget(this);
    perfPanelLayout_ = new QGridLayout(perfPanel_);
    perfPanelLayout_->setContentsMargins(0, 0, 0, 0);
    perfPanelLayout_->setHorizontalSpacing(6);
    perfPanelLayout_->setVerticalSpacing(6);
    rootLayout_->addWidget(perfPanel_, 0);

    auto createBarChartView = [this](const QString& titleText, const QColor& barColor, QBarSet** barSetOut, QChartView** chartViewOut) {
        QBarSet* barSet = new QBarSet(QStringLiteral("Usage"));
        barSet->append(0.0);
        barSet->setColor(barColor);
        barSet->setBorderColor(barColor);

        QBarSeries* barSeries = new QBarSeries();
        barSeries->append(barSet);

        QChart* chart = new QChart();
        chart->addSeries(barSeries);
        chart->setTitle(titleText);
        chart->legend()->hide();
        chart->setBackgroundRoundness(0);
        chart->setBackgroundVisible(false);
        chart->setMargins(QMargins(0, 0, 0, 0));

        QBarCategoryAxis* axisX = new QBarCategoryAxis(chart);
        axisX->append(QStringList{ ks::i18n::sourceText(QStringLiteral("当前")) });
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 100.0);
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        barSeries->attachAxis(axisX);
        barSeries->attachAxis(axisY);

        QChartView* chartView = new QChartView(chart, perfPanel_);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setMinimumHeight(140);
        chartView->setFrameShape(QFrame::NoFrame);

        if (barSetOut != nullptr)
        {
            *barSetOut = barSet;
        }
        if (chartViewOut != nullptr)
        {
            *chartViewOut = chartView;
        }
    };

    auto createLineChartView =
        [this](const QString& titleText,
            const QColor& firstColor,
            const QColor& secondColor,
            const QString& firstSeriesName,
            const QString& secondSeriesName,
            QLineSeries** firstSeriesOut,
            QLineSeries** secondSeriesOut,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut) {
        QLineSeries* firstSeries = new QLineSeries();
        firstSeries->setName(firstSeriesName);
        firstSeries->setColor(firstColor);

        QLineSeries* secondSeries = new QLineSeries();
        secondSeries->setName(secondSeriesName);
        secondSeries->setColor(secondColor);

        QChart* chart = new QChart();
        chart->addSeries(firstSeries);
        chart->addSeries(secondSeries);
        chart->setAnimationOptions(QChart::kAllAnimations);
        chart->setAnimationDuration(260);
        chart->setAnimationEasingCurve(QEasingCurve::OutCubic);
        chart->setTitle(titleText);
        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignTop);
        chart->setBackgroundRoundness(0);
        chart->setBackgroundVisible(false);
        chart->setMargins(QMargins(0, 0, 0, 0));

        QValueAxis* axisX = new QValueAxis(chart);
        axisX->setRange(0, perfHistoryLength_ - 1);
        axisX->setLabelFormat(QStringLiteral("%d"));
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);
        axisX->setMinorGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 1.0);
        axisY->setLabelFormat(QStringLiteral("%.0f"));
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        firstSeries->attachAxis(axisX);
        firstSeries->attachAxis(axisY);
        secondSeries->attachAxis(axisX);
        secondSeries->attachAxis(axisY);

        QChartView* chartView = new QChartView(chart, perfPanel_);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setMinimumHeight(140);
        chartView->setFrameShape(QFrame::NoFrame);

        if (firstSeriesOut != nullptr)
        {
            *firstSeriesOut = firstSeries;
        }
        if (secondSeriesOut != nullptr)
        {
            *secondSeriesOut = secondSeries;
        }
        if (axisXOut != nullptr)
        {
            *axisXOut = axisX;
        }
        if (axisYOut != nullptr)
        {
            *axisYOut = axisY;
        }
        if (chartViewOut != nullptr)
        {
            *chartViewOut = chartView;
        }
    };

    createBarChartView(
        ks::i18n::sourceText(QStringLiteral("CPU 占用率")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu),
        &cpuBarSet_,
        &cpuChartView_);
    createBarChartView(
        ks::i18n::sourceText(QStringLiteral("内存利用率")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory),
        &memoryBarSet_,
        &memoryChartView_);
    createLineChartView(
        ks::i18n::sourceText(QStringLiteral("系统盘读写速率")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kRead),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kWrite),
        ks::i18n::sourceText(QStringLiteral("读取")),
        ks::i18n::sourceText(QStringLiteral("写入")),
        &diskReadSeries_,
        &diskWriteSeries_,
        &diskAxisX_,
        &diskAxisY_,
        &diskChartView_);
    createLineChartView(
        ks::i18n::sourceText(QStringLiteral("网络收发速率")),
        ksword_theme::successColor(),
        ksword_theme::errorColor(),
        ks::i18n::sourceText(QStringLiteral("下载")),
        ks::i18n::sourceText(QStringLiteral("上传")),
        &networkRxSeries_,
        &networkTxSeries_,
        &networkAxisX_,
        &networkAxisY_,
        &networkChartView_);

    // Pre-fill the line chart with 0 values so the curve scrolls smoothly from left to right after startup.
    for (int indexValue = 0; indexValue < perfHistoryLength_; ++indexValue)
    {
        diskReadSeries_->append(indexValue, 0.0);
        diskWriteSeries_->append(indexValue, 0.0);
        networkRxSeries_->append(indexValue, 0.0);
        networkTxSeries_->append(indexValue, 0.0);
    }

    perfPanelLayout_->addWidget(cpuChartView_, 0, 0);
    perfPanelLayout_->addWidget(memoryChartView_, 0, 1);
    perfPanelLayout_->addWidget(diskChartView_, 1, 0);
    perfPanelLayout_->addWidget(networkChartView_, 1, 1);
}

void MonitorDock::appendLineSample(
    QLineSeries* series,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double value)
{
    if (series == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    series->append(perfSampleCounter_, value);
    while (series->count() > perfHistoryLength_)
    {
        series->remove(0);
    }

    const QList<QPointF> kPointList = series->points();
    if (kPointList.isEmpty())
    {
        return;
    }

    const double kMinX = kPointList.first().x();
    const double kMaxX = kPointList.last().x();
    axisX->setRange(kMinX, std::max(kMaxX, kMinX + 1.0));

    double yMaxValue = 1.0;
    for (const QPointF& pointValue : kPointList)
    {
        yMaxValue = std::max(yMaxValue, pointValue.y());
    }
    axisY->setRange(0.0, yMaxValue * 1.2);
}

bool MonitorDock::sampleCpuUsage(double* cpuUsageOut)
{
    if (cpuUsageOut == nullptr)
    {
        return false;
    }

    FILETIME idleTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (::GetSystemTimes(&idleTime, &kernelTime, &userTime) == FALSE)
    {
        return false;
    }

    const std::uint64_t kIdleValue = fileTimeToUint64(idleTime);
    const std::uint64_t kKernelValue = fileTimeToUint64(kernelTime);
    const std::uint64_t kUserValue = fileTimeToUint64(userTime);

    if (!cpuSampleValid_)
    {
        lastCpuIdleTime_ = kIdleValue;
        lastCpuKernelTime_ = kKernelValue;
        lastCpuUserTime_ = kUserValue;
        cpuSampleValid_ = true;
        *cpuUsageOut = 0.0;
        return true;
    }

    const std::uint64_t kDeltaIdle = kIdleValue - lastCpuIdleTime_;
    const std::uint64_t kDeltaKernel = kKernelValue - lastCpuKernelTime_;
    const std::uint64_t kDeltaUser = kUserValue - lastCpuUserTime_;
    const std::uint64_t kDeltaTotal = kDeltaKernel + kDeltaUser;

    lastCpuIdleTime_ = kIdleValue;
    lastCpuKernelTime_ = kKernelValue;
    lastCpuUserTime_ = kUserValue;

    if (kDeltaTotal == 0)
    {
        *cpuUsageOut = 0.0;
        return true;
    }

    const double kUsagePercent = (1.0 - static_cast<double>(kDeltaIdle) / static_cast<double>(kDeltaTotal)) * 100.0;
    *cpuUsageOut = std::clamp(kUsagePercent, 0.0, 100.0);
    return true;
}

bool MonitorDock::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (diskPerfQueryHandle_ == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER readCounter = nullptr;
        PDH_HCOUNTER writeCounter = nullptr;
        const PDH_STATUS kAddReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
            0,
            &readCounter);
        const PDH_STATUS kAddWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
            0,
            &writeCounter);

        if (kAddReadStatus != ERROR_SUCCESS || kAddWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        diskPerfQueryHandle_ = queryHandle;
        diskReadCounterHandle_ = readCounter;
        diskWriteCounterHandle_ = writeCounter;

        // Perform an initial collect on the first sample, then retrieve stable data on the next sample.
        ::PdhCollectQueryData(queryHandle);
        return false;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_);
    const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(kQueryHandle);
    if (kCollectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    PDH_FMT_COUNTERVALUE readValue{};
    PDH_FMT_COUNTERVALUE writeValue{};
    const PDH_STATUS kReadStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(diskReadCounterHandle_),
        PDH_FMT_DOUBLE,
        nullptr,
        &readValue);
    const PDH_STATUS kWriteStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(diskWriteCounterHandle_),
        PDH_FMT_DOUBLE,
        nullptr,
        &writeValue);

    if (kReadStatus != ERROR_SUCCESS || kWriteStatus != ERROR_SUCCESS)
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeValue.doubleValue);
    return true;
}

bool MonitorDock::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    const DWORD kTableStatus = ::GetIfTable2(&tablePointer);
    if (kTableStatus != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }
        totalRxBytes += static_cast<std::uint64_t>(rowValue.InOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.OutOctets);
    }
    ::FreeMibTable(tablePointer);

    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    if (lastNetworkSampleMs_ <= 0)
    {
        lastNetworkSampleMs_ = kNowMs;
        lastNetworkRxBytes_ = totalRxBytes;
        lastNetworkTxBytes_ = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 kElapsedMs = kNowMs - lastNetworkSampleMs_;
    if (kElapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t kDeltaRx = totalRxBytes >= lastNetworkRxBytes_
        ? (totalRxBytes - lastNetworkRxBytes_)
        : 0;
    const std::uint64_t kDeltaTx = totalTxBytes >= lastNetworkTxBytes_
        ? (totalTxBytes - lastNetworkTxBytes_)
        : 0;

    lastNetworkSampleMs_ = kNowMs;
    lastNetworkRxBytes_ = totalRxBytes;
    lastNetworkTxBytes_ = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(kDeltaRx) * 1000.0 / static_cast<double>(kElapsedMs);
    *txBytesPerSecOut = static_cast<double>(kDeltaTx) * 1000.0 / static_cast<double>(kElapsedMs);
    return true;
}

void MonitorDock::refreshPerformanceCharts()
{
    // Sample CPU and memory: the bar chart displays only the current instantaneous value.
    double cpuUsagePercent = 0.0;
    if (!sampleCpuUsage(&cpuUsagePercent))
    {
        cpuUsagePercent = 0.0;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool kMemoryOk = ::GlobalMemoryStatusEx(&memoryStatus) != FALSE;
    const double kMemoryUsagePercent = kMemoryOk ? static_cast<double>(memoryStatus.dwMemoryLoad) : 0.0;

    if (cpuBarSet_ != nullptr)
    {
        cpuBarSet_->replace(0, cpuUsagePercent);
    }
    if (memoryBarSet_ != nullptr)
    {
        memoryBarSet_->replace(0, kMemoryUsagePercent);
    }

    if (cpuChartView_ != nullptr && cpuChartView_->chart() != nullptr)
    {
        cpuChartView_->chart()->setTitle(
            ks::i18n::sourceText(QStringLiteral("CPU 占用率 %1%"))
                .arg(cpuUsagePercent, 0, 'f', 1));
    }
    if (memoryChartView_ != nullptr && memoryChartView_->chart() != nullptr)
    {
        memoryChartView_->chart()->setTitle(
            ks::i18n::sourceText(QStringLiteral("内存利用率 %1%"))
                .arg(kMemoryUsagePercent, 0, 'f', 1));
    }

    // The legend is not part of the QWidget translation tree; rewrite it on every sampling cycle according to the current language.
    if (diskReadSeries_ != nullptr)
    {
        diskReadSeries_->setName(ks::i18n::sourceText(QStringLiteral("读取")));
    }
    if (diskWriteSeries_ != nullptr)
    {
        diskWriteSeries_->setName(ks::i18n::sourceText(QStringLiteral("写入")));
    }
    if (networkRxSeries_ != nullptr)
    {
        networkRxSeries_->setName(ks::i18n::sourceText(QStringLiteral("下载")));
    }
    if (networkTxSeries_ != nullptr)
    {
        networkTxSeries_->setName(ks::i18n::sourceText(QStringLiteral("上传")));
    }

    // Sample disk and network: Line chart displays the last m_perfHistoryLength sample points.
    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
    if (!sampleDiskRate(&diskReadBytesPerSec, &diskWriteBytesPerSec))
    {
        diskReadBytesPerSec = 0.0;
        diskWriteBytesPerSec = 0.0;
    }

    double networkRxBytesPerSec = 0.0;
    double networkTxBytesPerSec = 0.0;
    if (!sampleNetworkRate(&networkRxBytesPerSec, &networkTxBytesPerSec))
    {
        networkRxBytesPerSec = 0.0;
        networkTxBytesPerSec = 0.0;
    }

    ++perfSampleCounter_;
    appendLineSample(diskReadSeries_, diskAxisX_, diskAxisY_, diskReadBytesPerSec);
    appendLineSample(diskWriteSeries_, diskAxisX_, diskAxisY_, diskWriteBytesPerSec);
    appendLineSample(networkRxSeries_, networkAxisX_, networkAxisY_, networkRxBytesPerSec);
    appendLineSample(networkTxSeries_, networkAxisX_, networkAxisY_, networkTxBytesPerSec);

    // The axis range is set to the maximum of both lines to ensure complete display of read/write and up/down traffic.
    auto updateAxisRangeByPair = [this](QLineSeries* firstSeries, QLineSeries* secondSeries, QValueAxis* axisY) {
        if (firstSeries == nullptr || secondSeries == nullptr || axisY == nullptr)
        {
            return;
        }
        double maxValue = 1.0;
        const QList<QPointF> kFirstPoints = firstSeries->points();
        const QList<QPointF> kSecondPoints = secondSeries->points();
        for (const QPointF& pointValue : kFirstPoints)
        {
            maxValue = std::max(maxValue, pointValue.y());
        }
        for (const QPointF& pointValue : kSecondPoints)
        {
            maxValue = std::max(maxValue, pointValue.y());
        }
        axisY->setRange(0.0, maxValue * 1.2);
    };
    updateAxisRangeByPair(diskReadSeries_, diskWriteSeries_, diskAxisY_);
    updateAxisRangeByPair(networkRxSeries_, networkTxSeries_, networkAxisY_);

    if (diskChartView_ != nullptr && diskChartView_->chart() != nullptr)
    {
        diskChartView_->chart()->setTitle(ks::i18n::sourceText(
            QStringLiteral("系统盘读写速率  读:%1  写:%2"))
            .arg(bytesPerSecondToText(diskReadBytesPerSec))
            .arg(bytesPerSecondToText(diskWriteBytesPerSec)));
    }
    if (networkChartView_ != nullptr && networkChartView_->chart() != nullptr)
    {
        networkChartView_->chart()->setTitle(ks::i18n::sourceText(
            QStringLiteral("网络收发速率  下:%1  上:%2"))
            .arg(bytesPerSecondToText(networkRxBytesPerSec))
            .arg(bytesPerSecondToText(networkTxBytesPerSec)));
    }
}
