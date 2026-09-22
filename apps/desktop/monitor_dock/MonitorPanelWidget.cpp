#include "MonitorPanelWidget.h"
#include "../internationalization/LanguageManager.h"
#include "../../../shared/ui/KsPainterChart.h"

// ============================================================
// MonitorPanelWidget.cpp
// Purpose:
// 1) Implement the 'Monitor Panel' 2x2 performance charts (CPU/Memory/Disk/Network);
// 2) Displays CPU usage with separate bar charts for each logical core.
// 3) Decouples sampling logic from MonitorDock to avoid bloating the WMI/ETW page.
// ============================================================

#include "../Theme.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGridLayout>
#include <QFont>
#include <QLabel>
#include <QList>
#include <QMetaObject>
#include <QPainter>
#include <QPointer>
#include <QResizeEvent>
#include <QShowEvent>
#include <QSizePolicy>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Pdh.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    // bytesPerSecondToText:
    // - Convert the bytes-per-second rate to human-readable text;
    // - Used to display the instantaneous rate of 'read/write, up/down' in the line chart title.
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double kSafeValue = std::max(0.0, bytesPerSecondValue);
        if (kSafeValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(kSafeValue, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(kSafeValue / 1024.0, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(kSafeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(kSafeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // createNoFrameChartView:
    // - Create a borderless, anti-aliased chart view;
    // - Unify the visual style of the monitor panel to avoid overly heavy default frame edges.
    QChartView* createNoFrameChartView(QChart* chartPtr, QWidget* parentWidget)
    {
        QChartView* chartView = new QChartView(chartPtr, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        chartView->setMinimumHeight(0);
        chartView->setMaximumHeight(QWIDGETSIZE_MAX);
        chartView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
        return chartView;
    }

    // cpuBarColor: Returns the primary color for the per-core CPU bar chart.
    QColor cpuBarColor()
    {
        return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu);
    }

    // memoryBarColor function: Returns the primary color for the memory history line chart.
    QColor memoryBarColor()
    {
        return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory);
    }

    // translucentAreaColor purpose: generates the fill color for the memory composition area based on theme and transparency.
    QColor translucentAreaColor(const QColor& baseColor, const int alphaValue)
    {
        return ksword_theme::withAlpha(baseColor, alphaValue);
    }

    // monitorPanelTextColor: Returns the color for the monitor chart title, legend, and axis labels.
    QColor monitorPanelTextColor()
    {
        return ksword_theme::isDarkModeEnabled()
            ? ksword_theme::whiteColor()
            : ksword_theme::textPrimaryColor();
    }

    // monitorPanelMutedTextColor purpose: Return the secondary axis text color for the monitor panel.
    QColor monitorPanelMutedTextColor()
    {
        return ksword_theme::isDarkModeEnabled()
            ? ksword_theme::whiteColor()
            : ksword_theme::textSecondaryColor();
    }

    // MonitorPanelPdhCounterBundle:
    // - Holds PDH query and counter handles created by the background thread;
    // - Only store void* values to facilitate full re-injection to the UI thread for ownership, without involving any QWidget.
    struct MonitorPanelPdhCounterBundle
    {
        void* cpuQueryHandle = nullptr;         // cpuQueryHandle: CPU query handle.
        std::vector<void*> coreCounterHandles;  // coreCounterHandles: Handles for the counter of each logical core.
        void* diskQueryHandle = nullptr;        // diskQueryHandle: disk query handle.
        void* diskReadCounterHandle = nullptr;  // diskReadCounterHandle: Handle for the disk read rate counter.
        void* diskWriteCounterHandle = nullptr; // diskWriteCounterHandle: handle for the disk write rate counter.
    };

    // monitorPanelCounterInitializing:
    // - Mark whether a background PDH initialization round is currently in progress.
    // - Prevent duplicate task dispatching during the per-second refresh while initialization is incomplete;
    std::atomic_bool monitorPanelCounterInitializing{ false };

    // createMonitorPanelPdhCounters:
    // - Input parameter coreCount: number of logical cores, determining how many \Processor(n) counters to register;
    // - Input parameters needCpuCounters/needDiskCounters: Re-create only when the control does not yet hold the corresponding handles to avoid futile retry loops.
    // - Handling: After the calling thread completes PdhOpenQueryW/PdhAddEnglishCounterW and the initial baseline
    //         collection, the first in-process call also loads the perflib counter name index, concentrating the latency here.
    // - Return: Handle collection; failure fields remain nullptr for caller fallback on null handles.
    MonitorPanelPdhCounterBundle createMonitorPanelPdhCounters(
        const int coreCount,
        const bool needCpuCounters,
        const bool needDiskCounters)
    {
        MonitorPanelPdhCounterBundle counterBundle;

        // CPU per-core counters: Add \Processor(n)\% Processor Time for each core.
        PDH_HQUERY cpuQueryHandle = nullptr;
        if (needCpuCounters
            && ::PdhOpenQueryW(nullptr, 0, &cpuQueryHandle) == ERROR_SUCCESS
            && cpuQueryHandle != nullptr)
        {
            const int kSafeCoreCount = std::max(0, coreCount);
            counterBundle.coreCounterHandles.reserve(static_cast<std::size_t>(kSafeCoreCount));
            for (int coreIndex = 0; coreIndex < kSafeCoreCount; ++coreIndex)
            {
                const QString kCounterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
                PDH_HCOUNTER cpuCounterHandle = nullptr;
                const PDH_STATUS kAddCounterStatus = ::PdhAddEnglishCounterW(
                    cpuQueryHandle,
                    reinterpret_cast<LPCWSTR>(kCounterPath.utf16()),
                    0,
                    &cpuCounterHandle);
                if (kAddCounterStatus != ERROR_SUCCESS || cpuCounterHandle == nullptr)
                {
                    // Retain nullptr when a core counter creation fails, acting as a placeholder to be filled with 0 later.
                    counterBundle.coreCounterHandles.push_back(nullptr);
                    continue;
                }
                counterBundle.coreCounterHandles.push_back(cpuCounterHandle);
            }

            // The first collection establishes a baseline; subsequent samples yield stable data.
            ::PdhCollectQueryData(cpuQueryHandle);
            counterBundle.cpuQueryHandle = cpuQueryHandle;
        }

        // Disk counters: read the system's total disk read/write bytes per second rate; discard the entire operation on failure.
        PDH_HQUERY diskQueryHandle = nullptr;
        if (needDiskCounters
            && ::PdhOpenQueryW(nullptr, 0, &diskQueryHandle) == ERROR_SUCCESS
            && diskQueryHandle != nullptr)
        {
            PDH_HCOUNTER readCounterHandle = nullptr;
            PDH_HCOUNTER writeCounterHandle = nullptr;

            const PDH_STATUS kAddReadStatus = ::PdhAddEnglishCounterW(
                diskQueryHandle,
                L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                0,
                &readCounterHandle);
            const PDH_STATUS kAddWriteStatus = ::PdhAddEnglishCounterW(
                diskQueryHandle,
                L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                0,
                &writeCounterHandle);

            if (kAddReadStatus == ERROR_SUCCESS
                && kAddWriteStatus == ERROR_SUCCESS
                && readCounterHandle != nullptr
                && writeCounterHandle != nullptr)
            {
                ::PdhCollectQueryData(diskQueryHandle);
                counterBundle.diskQueryHandle = diskQueryHandle;
                counterBundle.diskReadCounterHandle = readCounterHandle;
                counterBundle.diskWriteCounterHandle = writeCounterHandle;
            }
            else
            {
                ::PdhCloseQuery(diskQueryHandle);
            }
        }

        return counterBundle;
    }

    // closeMonitorPanelPdhCounters:
    // - Input counterBundle: The collection of handles to be released.
    // - Processing: Close PDH queries; discard results if the control is destroyed or the handle was dropped in an earlier round.
    // - Returns: Nothing.
    void closeMonitorPanelPdhCounters(const MonitorPanelPdhCounterBundle& counterBundle)
    {
        if (counterBundle.cpuQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.cpuQueryHandle));
        }
        if (counterBundle.diskQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.diskQueryHandle));
        }
    }
}

MonitorPanelWidget::MonitorPanelWidget(QWidget* parent)
    : QWidget(parent)
{
    // Use the same KLogEvent for construction logs to facilitate tracking the entire initialization flow by GUID.
    KLogEvent event;
    info << event << "[MonitorPanelWidget] 构造开始。" << eol;

    initializeUi();
    // Counter initialization and the first-frame sampling occur in the background thread. The construction phase only builds the chart skeleton, allowing the main window to render immediately.
    initializeCounters();

    // Sampling timer:
    // - Updates the performance graph every second;
    // - Use a UI thread timer to avoid cross-thread access to chart objects.
    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(1000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshMetrics();
    });
    refreshTimer_->start();

    info << event << "[MonitorPanelWidget] 构造完成。" << eol;
}

MonitorPanelWidget::~MonitorPanelWidget()
{
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }

    // Release CPU query handle and per-core counter handles.
    if (cpuPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_));
        cpuPerfQueryHandle_ = nullptr;
        coreCounterHandles_.clear();
    }

    // Release the disk query handle and the read/write counter handle.
    if (diskPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_));
        diskPerfQueryHandle_ = nullptr;
        diskReadCounterHandle_ = nullptr;
        diskWriteCounterHandle_ = nullptr;
    }
}

void MonitorPanelWidget::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    updateCompactVisibility();
    adjustChartCellHeights();
}

void MonitorPanelWidget::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
    applyChartTextTheme();
    updateCompactVisibility();
    // Defer re-layout to the end of the event loop to ensure stable geometry dimensions are available even for the first frame.
    QTimer::singleShot(0, this, [this]()
    {
        adjustChartCellHeights();
    });
    // Dock layout may continue adjusting after show; add a frame delay to prevent the bottom two charts from being clipped in the first frame.
    QTimer::singleShot(80, this, [this]()
    {
        adjustChartCellHeights();
    });
}

void MonitorPanelWidget::changeEvent(QEvent* eventPointer)
{
    QWidget::changeEvent(eventPointer);
    if (eventPointer == nullptr)
    {
        return;
    }

    const QEvent::Type kEventType = eventPointer->type();
    if (kEventType == QEvent::PaletteChange ||
        kEventType == QEvent::ApplicationPaletteChange ||
        kEventType == QEvent::StyleChange)
    {
        applyChartTextTheme();
    }
}

void MonitorPanelWidget::initializeUi()
{
    // Root layout:
    // - The four-panel chart fills the entire monitoring panel;
    // - Unify spacing to 6 to match the Dock style across the entire project.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(2, 2, 2, 2);
    rootLayout_->setSpacing(2);

    compactSummaryLabel_ = new QLabel(this);
    compactSummaryLabel_->setAlignment(Qt::AlignCenter);
    compactSummaryLabel_->setWordWrap(true);
    compactSummaryLabel_->setVisible(false);
    compactSummaryLabel_->setText(ks::i18n::contextText(
        QStringLiteral("monitor.panel.compact.hidden"), QStringLiteral("监视面板高度过低，已隐藏图表。")));
    rootLayout_->addWidget(compactSummaryLabel_, 1);

    chartGridLayout_ = new QGridLayout();
    chartGridLayout_->setContentsMargins(0, 0, 0, 0);
    chartGridLayout_->setHorizontalSpacing(2);
    chartGridLayout_->setVerticalSpacing(2);
    rootLayout_->addLayout(chartGridLayout_, 1);

    // ===================== CPU per-core bar chart =====================
    const int kLogicalCoreCount = static_cast<int>(
        std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));
    QStringList cpuCategoryTextList;
    cpuCategoryTextList.reserve(kLogicalCoreCount);

    cpuCoreHistoryBarSet_ = new QBarSet(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.history"), QStringLiteral("历史")));
    QColor cpuHistoryColor = cpuBarColor();
    cpuHistoryColor.setAlpha(86);
    cpuCoreHistoryBarSet_->setColor(cpuHistoryColor);
    cpuCoreHistoryBarSet_->setBorderColor(Qt::transparent);

    cpuCoreBarSet_ = new QBarSet(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.current"), QStringLiteral("当前")));
    cpuCoreBarSet_->setColor(cpuBarColor());
    cpuCoreBarSet_->setBorderColor(cpuBarColor());

    for (int coreIndex = 0; coreIndex < kLogicalCoreCount; ++coreIndex)
    {
        cpuCoreHistoryBarSet_->append(0.0);
        cpuCoreBarSet_->append(0.0);
        cpuCategoryTextList.push_back(QString::number(coreIndex));
    }
    cpuCoreHistoryPercentList_.assign(static_cast<std::size_t>(kLogicalCoreCount), 0.0);

    QBarSeries* cpuBarSeries = new QBarSeries(this);
    cpuBarSeries->append(cpuCoreHistoryBarSet_);
    cpuBarSeries->append(cpuCoreBarSet_);

    QChart* cpuChart = new QChart();
    cpuChart->addSeries(cpuBarSeries);
    cpuChart->legend()->hide();
    cpuChart->setBackgroundVisible(false);
    cpuChart->setBackgroundRoundness(0);
    cpuChart->setMargins(QMargins(0, 0, 0, 0));
    cpuChart->setTitle(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.title"), QStringLiteral("CPU 每核心利用率")));

    QBarCategoryAxis* cpuAxisX = new QBarCategoryAxis(cpuChart);
    cpuAxisX->append(cpuCategoryTextList);
    cpuAxisX->setGridLineVisible(false);
    cpuAxisX->setLabelsVisible(kLogicalCoreCount <= 24);

    QValueAxis* cpuAxisY = new QValueAxis(cpuChart);
    cpuAxisY->setRange(0.0, 100.0);
    cpuAxisY->setLabelsVisible(false);
    cpuAxisY->setGridLineVisible(false);
    cpuAxisY->setMinorGridLineVisible(false);

    cpuChart->addAxis(cpuAxisX, Qt::AlignBottom);
    cpuChart->addAxis(cpuAxisY, Qt::AlignLeft);
    cpuBarSeries->attachAxis(cpuAxisX);
    cpuBarSeries->attachAxis(cpuAxisY);
    cpuChartView_ = createNoFrameChartView(cpuChart, this);

    // ===================== Memory Usage and Composition Merged Trend Chart =====================
    memoryUsedSeries_ = new QLineSeries(this);
    memoryStandbyTopSeries_ = new QLineSeries(this);
    memoryStandbyBaseSeries_ = new QLineSeries(this);
    memoryAvailableTopSeries_ = new QLineSeries(this);
    memoryAvailableBaseSeries_ = new QLineSeries(this);
    memoryUsageSeries_ = new QLineSeries(this);

    memoryUsedSeries_->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.used"), QStringLiteral("已用")));
    memoryStandbyTopSeries_->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.cached"), QStringLiteral("提交/缓存")));
    memoryAvailableTopSeries_->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.available"), QStringLiteral("可用")));
    memoryUsageSeries_->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.usage"), QStringLiteral("占用")));

    // Color composition retains the semantics 'Used=Blue / Commit Cache=Orange / Available=Green', but now
    // derives colors from theme roles. The offset matches the Read/Write/Disk charts for disk and network,
    // ensuring all four charts remain consistent across light/dark themes and custom accent colors.
    const QColor kMemoryUsedColor =
        ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, 30, 4);
    const QColor kMemoryStandbyColor =
        ksword_theme::accentColor(ksword_theme::AccentRole::kOrange, 40, 14);
    const QColor kMemoryAvailableColor =
        ksword_theme::accentColor(ksword_theme::AccentRole::kGreen, 40, 14);
    QPen memoryUsedPen(kMemoryUsedColor);
    QPen memoryStandbyPen(kMemoryStandbyColor);
    QPen memoryAvailablePen(kMemoryAvailableColor);
    QPen memoryTrendPen(memoryBarColor());
    memoryUsedPen.setWidthF(1.0);
    memoryStandbyPen.setWidthF(1.0);
    memoryAvailablePen.setWidthF(1.0);
    memoryTrendPen.setWidthF(2.6);
    memoryUsedSeries_->setPen(memoryUsedPen);
    memoryStandbyTopSeries_->setPen(memoryStandbyPen);
    memoryStandbyBaseSeries_->setPen(QPen(Qt::transparent));
    memoryAvailableTopSeries_->setPen(memoryAvailablePen);
    memoryAvailableBaseSeries_->setPen(QPen(Qt::transparent));
    memoryUsageSeries_->setPen(memoryTrendPen);

    QAreaSeries* usedAreaSeries = new QAreaSeries(memoryUsedSeries_);
    usedAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.used"), QStringLiteral("已用")));
    usedAreaSeries->setPen(memoryUsedPen);
    usedAreaSeries->setBrush(QBrush(translucentAreaColor(kMemoryUsedColor, 82)));

    QAreaSeries* standbyAreaSeries = new QAreaSeries(memoryStandbyTopSeries_, memoryStandbyBaseSeries_);
    standbyAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.cached"), QStringLiteral("提交/缓存")));
    standbyAreaSeries->setPen(memoryStandbyPen);
    standbyAreaSeries->setBrush(QBrush(translucentAreaColor(kMemoryStandbyColor, 76)));

    QAreaSeries* availableAreaSeries = new QAreaSeries(memoryAvailableTopSeries_, memoryAvailableBaseSeries_);
    availableAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.available"), QStringLiteral("可用")));
    availableAreaSeries->setPen(memoryAvailablePen);
    availableAreaSeries->setBrush(QBrush(translucentAreaColor(kMemoryAvailableColor, 58)));

    QChart* memoryTrendChart = new QChart();
    memoryTrendChart->addSeries(usedAreaSeries);
    memoryTrendChart->addSeries(standbyAreaSeries);
    memoryTrendChart->addSeries(availableAreaSeries);
    memoryTrendChart->addSeries(memoryUsageSeries_);
    memoryTrendChart->legend()->hide();
    memoryTrendChart->setBackgroundVisible(false);
    memoryTrendChart->setBackgroundRoundness(0);
    memoryTrendChart->setMargins(QMargins(0, 0, 0, 0));
    memoryTrendChart->setTitle(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.title"), QStringLiteral("内存占用与组成")));

    memoryTrendAxisX_ = new QValueAxis(memoryTrendChart);
    memoryTrendAxisX_->setRange(0, historyLength_);
    memoryTrendAxisX_->setLabelsVisible(false);
    memoryTrendAxisX_->setGridLineVisible(false);
    memoryTrendAxisX_->setMinorGridLineVisible(false);
    memoryTrendAxisY_ = new QValueAxis(memoryTrendChart);
    memoryTrendAxisY_->setRange(0.0, 100.0);
    memoryTrendAxisY_->setLabelsVisible(false);
    memoryTrendAxisY_->setGridLineVisible(false);
    memoryTrendAxisY_->setMinorGridLineVisible(false);

    memoryTrendChart->addAxis(memoryTrendAxisX_, Qt::AlignBottom);
    memoryTrendChart->addAxis(memoryTrendAxisY_, Qt::AlignLeft);
    usedAreaSeries->attachAxis(memoryTrendAxisX_);
    usedAreaSeries->attachAxis(memoryTrendAxisY_);
    standbyAreaSeries->attachAxis(memoryTrendAxisX_);
    standbyAreaSeries->attachAxis(memoryTrendAxisY_);
    availableAreaSeries->attachAxis(memoryTrendAxisX_);
    availableAreaSeries->attachAxis(memoryTrendAxisY_);
    memoryUsageSeries_->attachAxis(memoryTrendAxisX_);
    memoryUsageSeries_->attachAxis(memoryTrendAxisY_);
    memoryTrendChartView_ = createNoFrameChartView(memoryTrendChart, this);

    // ===================== Line chart creator (shared by disk/network) =====================
    auto createLineChartView =
        [this](
            const QString& titleText,
            const QColor& firstColor,
            const QColor& secondColor,
            const QString& firstSeriesName,
            const QString& secondSeriesName,
            QLineSeries** firstSeriesOut,
            QLineSeries** secondSeriesOut,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut) {
        QLineSeries* firstSeries = new QLineSeries(this);
        firstSeries->setName(firstSeriesName);
        firstSeries->setColor(firstColor);
        QPen firstPen(firstColor);
        firstPen.setWidthF(2.6);
        firstSeries->setPen(firstPen);

        QLineSeries* secondSeries = new QLineSeries(this);
        secondSeries->setName(secondSeriesName);
        secondSeries->setColor(secondColor);
        QPen secondPen(secondColor);
        secondPen.setWidthF(2.6);
        secondSeries->setPen(secondPen);

        // Area coloring:
        // - Add fill areas to the 'disk read/write' and 'network send/receive' curves per user request;
        // - Enhances visibility in both light and dark themes using a semi-transparent primary color.
        QAreaSeries* firstAreaSeries = new QAreaSeries(firstSeries);
        firstAreaSeries->setName(firstSeriesName);
        firstAreaSeries->setPen(firstPen);
        QColor firstBrushColor = firstColor;
        firstBrushColor.setAlpha(52);
        firstAreaSeries->setBrush(QBrush(firstBrushColor));

        QAreaSeries* secondAreaSeries = new QAreaSeries(secondSeries);
        secondAreaSeries->setName(secondSeriesName);
        secondAreaSeries->setPen(secondPen);
        QColor secondBrushColor = secondColor;
        secondBrushColor.setAlpha(52);
        secondAreaSeries->setBrush(QBrush(secondBrushColor));

        QChart* chart = new QChart();
        chart->addSeries(firstAreaSeries);
        chart->addSeries(secondAreaSeries);
        chart->setBackgroundVisible(false);
        chart->setBackgroundRoundness(0);
        chart->setMargins(QMargins(0, 0, 0, 0));
        chart->setTitle(titleText);
        chart->legend()->hide();

        QValueAxis* axisX = new QValueAxis(chart);
        axisX->setRange(0, historyLength_);
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);
        axisX->setMinorGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 1.0);
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        firstAreaSeries->attachAxis(axisX);
        firstAreaSeries->attachAxis(axisY);
        secondAreaSeries->attachAxis(axisX);
        secondAreaSeries->attachAxis(axisY);

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
            *chartViewOut = createNoFrameChartView(chart, this);
        }
    };

    // Disk line chart: read/write dual lines.
    createLineChartView(
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.title"), QStringLiteral("磁盘读写速率")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kRead),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kWrite),
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.read"), QStringLiteral("读取")),
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.write"), QStringLiteral("写入")),
        &diskReadSeries_,
        &diskWriteSeries_,
        &diskAxisX_,
        &diskAxisY_,
        &diskChartView_);

    // Network line chart: dual lines for download/upload.
    createLineChartView(
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.title"), QStringLiteral("网络收发速率")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kNetwork),
        ksword_theme::accentColor(ksword_theme::AccentRole::kOrange, 48, 22),
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.down"), QStringLiteral("下行")),
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.up"), QStringLiteral("上行")),
        &networkRxSeries_,
        &networkTxSeries_,
        &networkAxisX_,
        &networkAxisY_,
        &networkChartView_);

    // Place four charts into a 2x2 grid: memory history uses area color to directly express composition proportions.
    chartGridLayout_->addWidget(cpuChartView_, 0, 0);
    chartGridLayout_->addWidget(memoryTrendChartView_, 0, 1);
    chartGridLayout_->addWidget(diskChartView_, 1, 0);
    chartGridLayout_->addWidget(networkChartView_, 1, 1);
    chartGridLayout_->setRowStretch(0, 1);
    chartGridLayout_->setRowStretch(1, 1);
    chartGridLayout_->setColumnStretch(0, 1);
    chartGridLayout_->setColumnStretch(1, 1);

    // During initialization, apply the text theme and perform one height compression pass to prevent dark text from becoming too dim and to avoid outer scrollbars.
    applyChartTextTheme();
    adjustChartCellHeights();
}

void MonitorPanelWidget::initializeCounters()
{
    // Asynchronous initialization of counters:
    // - The first PdhAddEnglishCounterW call within the process requires loading and resolving perflib counter name indices.
    //   Executing this synchronously in the main window construction chain would freeze the entire UI during startup.
    // - UI thread only reads core count here; PDH calls are offloaded to the thread pool, and handles are re-acquired upon completion.
    if (cpuPerfQueryHandle_ != nullptr && diskPerfQueryHandle_ != nullptr)
    {
        return;
    }

    // expectedInitializingValue usage: CAS expected value (false = no initialization task is currently running).
    bool expectedInitializingValue = false;
    if (!monitorPanelCounterInitializing.compare_exchange_strong(expectedInitializingValue, true))
    {
        return;
    }

    // coreCount must be read on the UI thread: QBarSet belongs to chart controls and cannot be accessed from background threads.
    const int kCoreCount = cpuCoreBarSet_ != nullptr ? std::max(0, cpuCoreBarSet_->count()) : 0;
    const bool kNeedCpuCounters = cpuPerfQueryHandle_ == nullptr;
    const bool kNeedDiskCounters = diskPerfQueryHandle_ == nullptr;

    // guardedSelf usage: background tasks may outlive the widget; verify lifecycle before callback.
    const QPointer<MonitorPanelWidget> kGuardedSelf(this);
    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kCoreCount, kNeedCpuCounters, kNeedDiskCounters]()
        {
            // The background thread performs pure data collection, producing handle values that can be safely transferred across threads.
            const MonitorPanelPdhCounterBundle kCounterBundle = createMonitorPanelPdhCounters(
                kCoreCount,
                kNeedCpuCounters,
                kNeedDiskCounters);

            // applicationInstance shares the lifetime of the event loop; worker threads must not dereference control pointers.
            QCoreApplication* const kApplicationInstance = QCoreApplication::instance();
            if (kApplicationInstance == nullptr)
            {
                closeMonitorPanelPdhCounters(kCounterBundle);
                monitorPanelCounterInitializing.store(false);
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                kApplicationInstance,
                [kGuardedSelf, kCounterBundle]()
                {
                    if (kGuardedSelf.isNull())
                    {
                        closeMonitorPanelPdhCounters(kCounterBundle);
                        monitorPanelCounterInitializing.store(false);
                        return;
                    }

                    // The control already holds the handle, indicating the previous initialization round completed; discard the current result to avoid a leak.
                    if (kGuardedSelf->cpuPerfQueryHandle_ == nullptr)
                    {
                        kGuardedSelf->cpuPerfQueryHandle_ = kCounterBundle.cpuQueryHandle;
                        kGuardedSelf->coreCounterHandles_ = kCounterBundle.coreCounterHandles;
                    }
                    else if (kCounterBundle.cpuQueryHandle != nullptr)
                    {
                        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(kCounterBundle.cpuQueryHandle));
                    }

                    if (kGuardedSelf->diskPerfQueryHandle_ == nullptr)
                    {
                        kGuardedSelf->diskPerfQueryHandle_ = kCounterBundle.diskQueryHandle;
                        kGuardedSelf->diskReadCounterHandle_ = kCounterBundle.diskReadCounterHandle;
                        kGuardedSelf->diskWriteCounterHandle_ = kCounterBundle.diskWriteCounterHandle;
                    }
                    else if (kCounterBundle.diskQueryHandle != nullptr)
                    {
                        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(kCounterBundle.diskQueryHandle));
                    }

                    // Immediately render one frame after the handle is ready to prevent the chart from staying at 0 for a long time during the initialization window;
                    // Clear the flag after the refresh to prevent the refresh logic from immediately dispatching another initialization task.
                    kGuardedSelf->refreshMetrics();
                    monitorPanelCounterInitializing.store(false);
                },
                Qt::QueuedConnection);

            if (!kInvokeOk)
            {
                closeMonitorPanelPdhCounters(kCounterBundle);
                monitorPanelCounterInitializing.store(false);
            }
        });
}

void MonitorPanelWidget::refreshMetrics()
{
    // Sample per-core CPU usage and the total average usage.
    std::vector<double> perCoreUsageList;
    double totalCpuUsage = 0.0;
    if (!samplePerCoreCpuUsage(&perCoreUsageList, &totalCpuUsage))
    {
        perCoreUsageList.assign(static_cast<std::size_t>(
            cpuCoreBarSet_ != nullptr ? std::max(0, cpuCoreBarSet_->count()) : 0), 0.0);
        totalCpuUsage = 0.0;
    }

    // Update CPU core bar data.
    if (cpuCoreBarSet_ != nullptr)
    {
        const int kCoreBarCount = cpuCoreBarSet_->count();
        for (int indexValue = 0; indexValue < kCoreBarCount; ++indexValue)
        {
            const double kUsageValue =
                indexValue < static_cast<int>(perCoreUsageList.size())
                ? perCoreUsageList[static_cast<std::size_t>(indexValue)]
                : 0.0;
            const double kPreviousHistoryValue =
                indexValue < static_cast<int>(cpuCoreHistoryPercentList_.size())
                ? cpuCoreHistoryPercentList_[static_cast<std::size_t>(indexValue)]
                : 0.0;
            const double kHistoryValue = kPreviousHistoryValue <= 0.0
                ? kUsageValue
                : kPreviousHistoryValue * 0.88 + kUsageValue * 0.12;
            if (indexValue < static_cast<int>(cpuCoreHistoryPercentList_.size()))
            {
                cpuCoreHistoryPercentList_[static_cast<std::size_t>(indexValue)] = kHistoryValue;
            }
            if (cpuCoreHistoryBarSet_ != nullptr && indexValue < cpuCoreHistoryBarSet_->count())
            {
                cpuCoreHistoryBarSet_->replace(indexValue, kHistoryValue);
            }
            cpuCoreBarSet_->replace(indexValue, kUsageValue);
        }
    }
    if (cpuChartView_ != nullptr && cpuChartView_->chart() != nullptr)
    {
        cpuChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.cpu.title.dynamic"),
                QStringLiteral("CPU 每核心利用率（总体 %1%）"))
            .arg(totalCpuUsage, 0, 'f', 1));
    }

    // Sample and update the memory composition chart: the line represents total usage, and the area color represents the composition ratio at the current moment.
    MemoryCompositionSample memorySample{};
    if (!sampleMemoryUsage(&memorySample))
    {
        memorySample = MemoryCompositionSample{};
    }
    const double kMemoryUsedTopPercent = memorySample.usedPercent;
    const double kMemoryStandbyTopPercent = std::clamp(
        memorySample.usedPercent + memorySample.standbyPercent,
        0.0,
        100.0);
    const double kMemoryAvailableTopPercent = std::clamp(
        kMemoryStandbyTopPercent + memorySample.availablePercent,
        0.0,
        100.0);
    if (memoryTrendChartView_ != nullptr && memoryTrendChartView_->chart() != nullptr)
    {
        memoryTrendChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.memory.title.dynamic"),
                QStringLiteral("内存占用/组成  占用:%1%  缓存:%2%  可用:%3%"))
            .arg(memorySample.usedPercent, 0, 'f', 1)
            .arg(memorySample.standbyPercent, 0, 'f', 1)
            .arg(memorySample.availablePercent, 0, 'f', 1));
    }

    // Sample and update the disk/network line chart.
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

    ++sampleCounter_;
    appendLineSample(memoryUsedSeries_, memoryTrendAxisX_, memoryTrendAxisY_, kMemoryUsedTopPercent);
    appendLineSample(memoryStandbyTopSeries_, memoryTrendAxisX_, memoryTrendAxisY_, kMemoryStandbyTopPercent);
    appendLineSample(memoryStandbyBaseSeries_, memoryTrendAxisX_, memoryTrendAxisY_, kMemoryUsedTopPercent);
    appendLineSample(memoryAvailableTopSeries_, memoryTrendAxisX_, memoryTrendAxisY_, kMemoryAvailableTopPercent);
    appendLineSample(memoryAvailableBaseSeries_, memoryTrendAxisX_, memoryTrendAxisY_, kMemoryStandbyTopPercent);
    appendLineSample(memoryUsageSeries_, memoryTrendAxisX_, memoryTrendAxisY_, memorySample.usedPercent);
    if (memoryTrendAxisY_ != nullptr)
    {
        memoryTrendAxisY_->setRange(0.0, 100.0);
    }
    appendLineSample(diskReadSeries_, diskAxisX_, diskAxisY_, diskReadBytesPerSec);
    appendLineSample(diskWriteSeries_, diskAxisX_, diskAxisY_, diskWriteBytesPerSec);
    appendLineSample(networkRxSeries_, networkAxisX_, networkAxisY_, networkRxBytesPerSec);
    appendLineSample(networkTxSeries_, networkAxisX_, networkAxisY_, networkTxBytesPerSec);

    // Dual series share the Y-axis; the Y-range must be adjusted based on the combined maximum of both lines.
    auto updateAxisRangeByPair = [](
        QLineSeries* firstSeries,
        QLineSeries* secondSeries,
        QValueAxis* axisY) {
        if (firstSeries == nullptr || secondSeries == nullptr || axisY == nullptr)
        {
            return;
        }

        double maxYValue = 1.0;
        const QList<QPointF> kFirstPointList = firstSeries->points();
        const QList<QPointF> kSecondPointList = secondSeries->points();
        for (const QPointF& pointValue : kFirstPointList)
        {
            maxYValue = std::max(maxYValue, pointValue.y());
        }
        for (const QPointF& pointValue : kSecondPointList)
        {
            maxYValue = std::max(maxYValue, pointValue.y());
        }
        axisY->setRange(0.0, maxYValue * 1.2);
    };
    updateAxisRangeByPair(diskReadSeries_, diskWriteSeries_, diskAxisY_);
    updateAxisRangeByPair(networkRxSeries_, networkTxSeries_, networkAxisY_);

    if (diskChartView_ != nullptr && diskChartView_->chart() != nullptr)
    {
        diskChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.disk.title.dynamic"),
                QStringLiteral("磁盘读写速率  读:%1  写:%2"))
            .arg(bytesPerSecondToText(diskReadBytesPerSec))
            .arg(bytesPerSecondToText(diskWriteBytesPerSec)));
    }
    if (networkChartView_ != nullptr && networkChartView_->chart() != nullptr)
    {
        networkChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.network.title.dynamic"),
                QStringLiteral("网络收发速率  下:%1  上:%2"))
            .arg(bytesPerSecondToText(networkRxBytesPerSec))
            .arg(bytesPerSecondToText(networkTxBytesPerSec)));
    }

    lastCompactSummaryText_ = ks::i18n::contextText(
        QStringLiteral("monitor.panel.compact.summary"),
        QStringLiteral("CPU %1% | 内存 %2% | 磁盘 读 %3 / 写 %4 | 网络 下 %5 / 上 %6"))
        .arg(totalCpuUsage, 0, 'f', 1)
        .arg(memorySample.usedPercent, 0, 'f', 1)
        .arg(bytesPerSecondToText(diskReadBytesPerSec))
        .arg(bytesPerSecondToText(diskWriteBytesPerSec))
        .arg(bytesPerSecondToText(networkRxBytesPerSec))
        .arg(bytesPerSecondToText(networkTxBytesPerSec));
    if (compactSummaryLabel_ != nullptr)
    {
        compactSummaryLabel_->setText(lastCompactSummaryText_);
    }
    updateCompactVisibility();
}

bool MonitorPanelWidget::samplePerCoreCpuUsage(
    std::vector<double>* coreUsagesOut,
    double* totalUsageOut)
{
    if (coreUsagesOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }

    if (cpuPerfQueryHandle_ == nullptr)
    {
        initializeCounters();
    }
    if (cpuPerfQueryHandle_ == nullptr)
    {
        return false;
    }

    const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(
        reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_));
    if (kCollectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    coreUsagesOut->clear();
    coreUsagesOut->reserve(coreCounterHandles_.size());

    double usageSum = 0.0;
    int validCoreCount = 0;
    for (void* counterHandleVoid : coreCounterHandles_)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsagesOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE counterValue{};
        const PDH_STATUS kReadStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &counterValue);
        if (kReadStatus != ERROR_SUCCESS)
        {
            coreUsagesOut->push_back(0.0);
            continue;
        }

        const double kUsageValue = std::clamp(counterValue.doubleValue, 0.0, 100.0);
        coreUsagesOut->push_back(kUsageValue);
        usageSum += kUsageValue;
        ++validCoreCount;
    }

    *totalUsageOut = validCoreCount > 0
        ? usageSum / static_cast<double>(validCoreCount)
        : 0.0;
    return true;
}

bool MonitorPanelWidget::sampleMemoryUsage(MemoryCompositionSample* memorySampleOut) const
{
    if (memorySampleOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memorySampleOut = MemoryCompositionSample{};
        return false;
    }

    const double kTotalPhysBytes = static_cast<double>(memoryStatus.ullTotalPhys);
    const double kAvailablePhysBytes = static_cast<double>(memoryStatus.ullAvailPhys);
    const double kUsedPhysBytes = std::max(0.0, kTotalPhysBytes - kAvailablePhysBytes);
    const double kTotalCommitBytes = static_cast<double>(memoryStatus.ullTotalPageFile);
    const double kAvailableCommitBytes = static_cast<double>(memoryStatus.ullAvailPageFile);
    const double kUsedCommitBytes = std::max(0.0, kTotalCommitBytes - kAvailableCommitBytes);

    MemoryCompositionSample sample{};
    if (kTotalPhysBytes > 0.0)
    {
        sample.usedPercent = std::clamp(kUsedPhysBytes * 100.0 / kTotalPhysBytes, 0.0, 100.0);
        sample.availablePercent = std::clamp(kAvailablePhysBytes * 100.0 / kTotalPhysBytes, 0.0, 100.0);
    }
    sample.commitPercent = kTotalCommitBytes > 0.0
        ? std::clamp(kUsedCommitBytes * 100.0 / kTotalCommitBytes, 0.0, 100.0)
        : sample.usedPercent;
    sample.standbyPercent = std::clamp(sample.commitPercent - sample.usedPercent, 0.0, 100.0);
    const double kTotalStackPercent = sample.usedPercent + sample.standbyPercent + sample.availablePercent;
    if (kTotalStackPercent > 100.0 && kTotalStackPercent > 0.0)
    {
        sample.availablePercent = std::max(0.0, 100.0 - sample.usedPercent - sample.standbyPercent);
    }

    *memorySampleOut = sample;
    return true;
}

bool MonitorPanelWidget::sampleDiskRate(
    double* readBytesPerSecOut,
    double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (diskPerfQueryHandle_ == nullptr)
    {
        initializeCounters();
    }
    if (diskPerfQueryHandle_ == nullptr
        || diskReadCounterHandle_ == nullptr
        || diskWriteCounterHandle_ == nullptr)
    {
        return false;
    }

    const PDH_HQUERY kDiskQueryHandle = reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_);
    const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(kDiskQueryHandle);
    if (kCollectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    PDH_FMT_COUNTERVALUE readCounterValue{};
    PDH_FMT_COUNTERVALUE writeCounterValue{};
    const PDH_STATUS kReadStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(diskReadCounterHandle_),
        PDH_FMT_DOUBLE,
        nullptr,
        &readCounterValue);
    const PDH_STATUS kWriteStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(diskWriteCounterHandle_),
        PDH_FMT_DOUBLE,
        nullptr,
        &writeCounterValue);
    if (kReadStatus != ERROR_SUCCESS || kWriteStatus != ERROR_SUCCESS)
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readCounterValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeCounterValue.doubleValue);
    return true;
}

bool MonitorPanelWidget::sampleNetworkRate(
    double* rxBytesPerSecOut,
    double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* ifTablePointer = nullptr;
    const DWORD kTableStatus = ::GetIfTable2(&ifTablePointer);
    if (kTableStatus != NO_ERROR || ifTablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    for (ULONG rowIndex = 0; rowIndex < ifTablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = ifTablePointer->Table[rowIndex];
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
    ::FreeMibTable(ifTablePointer);

    const qint64 kCurrentSampleMs = QDateTime::currentMSecsSinceEpoch();
    if (lastNetworkSampleMs_ <= 0)
    {
        lastNetworkSampleMs_ = kCurrentSampleMs;
        lastNetworkRxBytes_ = totalRxBytes;
        lastNetworkTxBytes_ = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 kElapsedMs = kCurrentSampleMs - lastNetworkSampleMs_;
    if (kElapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t kDeltaRxBytes = totalRxBytes >= lastNetworkRxBytes_
        ? (totalRxBytes - lastNetworkRxBytes_)
        : 0;
    const std::uint64_t kDeltaTxBytes = totalTxBytes >= lastNetworkTxBytes_
        ? (totalTxBytes - lastNetworkTxBytes_)
        : 0;

    lastNetworkSampleMs_ = kCurrentSampleMs;
    lastNetworkRxBytes_ = totalRxBytes;
    lastNetworkTxBytes_ = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(kDeltaRxBytes) * 1000.0 / static_cast<double>(kElapsedMs);
    *txBytesPerSecOut = static_cast<double>(kDeltaTxBytes) * 1000.0 / static_cast<double>(kElapsedMs);
    return true;
}

void MonitorPanelWidget::appendLineSample(
    QLineSeries* series,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double value)
{
    if (series == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    // Line chart uses a fixed X-coordinate window:
    // 1) New points enter from the right;
    // 2) Shift all old points left to create a panning effect.
    // 3) Prevents QChart from re-animating the entire curve from the start on each update.
    QList<QPointF> pointList = series->points();
    pointList.push_back(QPointF(static_cast<double>(pointList.size()), value));
    while (pointList.size() > historyLength_)
    {
        pointList.removeFirst();
    }
    for (int pointIndex = 0; pointIndex < pointList.size(); ++pointIndex)
    {
        pointList[pointIndex].setX(static_cast<double>(pointIndex));
    }
    series->replace(pointList);


    if (pointList.isEmpty())
    {
        return;
    }

    const double kMinX = pointList.first().x();
    const double kMaxX = pointList.last().x();
    axisX->setRange(kMinX, std::max(kMaxX, kMinX + 1.0));

    double maxYValue = 1.0;
    for (const QPointF& pointValue : pointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(0.0, maxYValue * 1.2);
}

void MonitorPanelWidget::applyChartTextTheme()
{
    const QColor kPrimaryTextColor = monitorPanelTextColor();
    const QColor kMutedTextColor = monitorPanelMutedTextColor();
    const QBrush kPrimaryTextBrush(kPrimaryTextColor);
    const QBrush kMutedTextBrush(kMutedTextColor);
    if (compactSummaryLabel_ != nullptr)
    {
        compactSummaryLabel_->setStyleSheet(QStringLiteral(
            "QLabel{"
            "  color:%1;"
            "  background:transparent;"
            "  font-weight:600;"
            "  padding:4px;"
            "}")
            .arg(kPrimaryTextColor.name(QColor::HexRgb)));
    }

    // chartList variable: Uniformly enumerates the four charts to ensure titles and legends are readable in both light and dark themes.
    const QList<QChart*> kChartList{
        cpuChartView_ != nullptr ? cpuChartView_->chart() : nullptr,
        memoryTrendChartView_ != nullptr ? memoryTrendChartView_->chart() : nullptr,
        diskChartView_ != nullptr ? diskChartView_->chart() : nullptr,
        networkChartView_ != nullptr ? networkChartView_->chart() : nullptr
    };

    QFont titleFont = font();
    titleFont.setPointSizeF(std::max(10.0, titleFont.pointSizeF() + 1.0));
    titleFont.setWeight(QFont::DemiBold);

    QFont legendFont = font();
    legendFont.setPointSizeF(std::max(9.0, legendFont.pointSizeF()));

    for (QChart* chart : kChartList)
    {
        if (chart == nullptr)
        {
            continue;
        }

        const bool kIsCpuBarChart = chart == (cpuChartView_ != nullptr ? cpuChartView_->chart() : nullptr);

        chart->setTitleBrush(kPrimaryTextBrush);
        chart->setTitleFont(titleFont);
        chart->legend()->hide();
        chart->legend()->setLabelColor(kPrimaryTextColor);
        chart->legend()->setFont(legendFont);
        chart->setAnimationOptions(
            kIsCpuBarChart ? QChart::kSeriesAnimations : QChart::kAllAnimations);
        chart->setAnimationDuration(kIsCpuBarChart ? 120 : 260);
        chart->setAnimationEasingCurve(QEasingCurve::OutCubic);

        const QList<QAbstractAxis*> kAxisList = chart->axes();
        for (QAbstractAxis* axis : kAxisList)
        {
            if (axis == nullptr)
            {
                continue;
            }
            axis->setLabelsBrush(kMutedTextBrush);
            axis->setTitleBrush(kMutedTextBrush);
            axis->setLinePenColor(ksword_theme::borderStrongColor());
            axis->setGridLineColor(ksword_theme::borderColor());
        }
    }
}

void MonitorPanelWidget::updateCompactVisibility()
{
    // Low-height protection:
    // - At very small heights, the title, plotArea, legend, and axes lack sufficient drawable space.
    // - Directly hide all chart views and retain only a single-line summary to avoid layout oscillation or crashes.
    const bool kCompactTextOnly = height() > 0 && height() < 200;
    if (compactSummaryLabel_ != nullptr)
    {
        compactSummaryLabel_->setVisible(kCompactTextOnly);
        if (!lastCompactSummaryText_.isEmpty())
        {
            compactSummaryLabel_->setText(lastCompactSummaryText_);
        }
    }

    const QList<QChartView*> kChartViewList{
        cpuChartView_,
        memoryTrendChartView_,
        diskChartView_,
        networkChartView_
    };
    for (QChartView* chartView : kChartViewList)
    {
        if (chartView != nullptr)
        {
            chartView->setVisible(!kCompactTextOnly);
        }
    }
}

void MonitorPanelWidget::adjustChartCellHeights()
{
    if (height() > 0 && height() < 200)
    {
        updateCompactVisibility();
        return;
    }
    updateCompactVisibility();

    // applyMaxHeightIfChanged:
    // - Only tightens the chart's maximum height; the minimum height remains 0.
    // - Prevent child controls' minimumHeight from pushing the parent container to an infinite height.
    auto applyMaxHeightIfChanged =
        [](QChartView* chartViewPointer, const int heightValue)
        {
            if (chartViewPointer == nullptr || heightValue <= 0)
            {
                return;
            }
            if (chartViewPointer->minimumHeight() == 0
                && chartViewPointer->maximumHeight() == heightValue)
            {
                return;
            }
            chartViewPointer->setMinimumHeight(0);
            chartViewPointer->setMaximumHeight(heightValue);
        };

    // widgetInnerHeight usage: the actual available height after removing layout margins, to prevent double-counting margins in chart height.
    int widgetInnerHeight = height();
    if (rootLayout_ != nullptr)
    {
        const QMargins kRootMargins = rootLayout_->contentsMargins();
        widgetInnerHeight -= (kRootMargins.top() + kRootMargins.bottom());
    }
    if (chartGridLayout_ != nullptr)
    {
        const QMargins kGridMargins = chartGridLayout_->contentsMargins();
        widgetInnerHeight -= (kGridMargins.top() + kGridMargins.bottom());
    }

    // Fallback value purpose: use geometry/default values as a safeguard when the layout is not yet stable to prevent 0 height.
    if (widgetInnerHeight <= 0 && chartGridLayout_ != nullptr)
    {
        widgetInnerHeight = chartGridLayout_->geometry().height();
    }
    if (widgetInnerHeight <= 0)
    {
        widgetInnerHeight = 180;
    }

    // rowSpacingValue purpose: Vertical spacing between two rows of charts, used to calculate available height per row.
    const int kRowSpacingValue = chartGridLayout_ != nullptr
        ? std::max(0, chartGridLayout_->verticalSpacing())
        : 0;
    // availableRowsHeight usage: Total height available for two chart rows after deducting row spacing.
    const int kAvailableRowsHeight = std::max(2, widgetInnerHeight - kRowSpacingValue);
    // chartRowHeight purpose: Target maximum height for each chart row, keeping it compressible while preventing charts from disappearing.
    const int kChartRowHeight = std::max(18, kAvailableRowsHeight / 2);

    applyMaxHeightIfChanged(cpuChartView_, kChartRowHeight);
    applyMaxHeightIfChanged(memoryTrendChartView_, kChartRowHeight);
    applyMaxHeightIfChanged(diskChartView_, kChartRowHeight);
    applyMaxHeightIfChanged(networkChartView_, kChartRowHeight);

    // compactMode purpose: simplify title margins at low heights to reduce internal layout usage and avoid scrollbars.
    const bool kCompactMode = (kChartRowHeight < 92);
    auto applyChartCompactMode =
        [kCompactMode](QChartView* chartViewPointer)
        {
            if (chartViewPointer == nullptr || chartViewPointer->chart() == nullptr)
            {
                return;
            }
            QChart* chartPointer = chartViewPointer->chart();
            if (chartPointer->legend() != nullptr)
            {
                chartPointer->legend()->hide();
            }
            if (kCompactMode)
            {
                chartPointer->setMargins(QMargins(0, 0, 0, 0));
            }
        };
    applyChartCompactMode(memoryTrendChartView_);
    applyChartCompactMode(diskChartView_);
    applyChartCompactMode(networkChartView_);
}
