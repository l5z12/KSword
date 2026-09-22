#include "HudPerformancePanel.h"
#include "../../shared/ui/KsPainterChart.h"

#include "PerformanceNavCard.h"

#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QDateTime>
#include <QEasingCurve>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMutexLocker>
#include <QMetaObject>
#include <QPainterPath>
#include <QPainter>
#include <QPointer>
#include <QProcess>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShowEvent>
#include <QStackedWidget>
#include <QTimer>
#include <QVariantAnimation>
#include <QVector>
#include <QVBoxLayout>

#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <cmath>
#include <thread>

#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <intrin.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <Psapi.h>
#include <PowrProf.h>
#include <dxgi1_6.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    class CpuCoreSparklineWidget final : public QWidget
    {
    public:
        explicit CpuCoreSparklineWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setAttribute(Qt::WA_StyledBackground, true);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            sampleAnimation_ = new QVariantAnimation(this);
            sampleAnimation_->setDuration(260);
            sampleAnimation_->setEasingCurve(QEasingCurve::OutCubic);
            sampleAnimation_->setStartValue(0.0);
            sampleAnimation_->setEndValue(1.0);
            connect(sampleAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
                animationProgress_ = value.toDouble();
                update();
            });
        }

        void appendSample(const double usagePercent, const int historyLength)
        {
            const double kBoundedValue = qBound(0.0, usagePercent, 100.0);
            previousSample_ = samples_.isEmpty()
                ? kBoundedValue
                : samples_.back();
            previousSampleCount_ = static_cast<int>(samples_.size());
            historyWindowShifted_ = previousSampleCount_ >= historyLength;
            samples_.push_back(kBoundedValue);
            while (samples_.size() > historyLength)
            {
                samples_.pop_front();
            }
            animationProgress_ = 0.0;
            sampleAnimation_->stop();
            sampleAnimation_->start();
        }

    protected:
        void paintEvent(QPaintEvent* eventPointer) override
        {
            Q_UNUSED(eventPointer);

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);
            painter.fillRect(rect(), Qt::transparent);

            const QRectF kContentRect = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
            if (kContentRect.width() <= 4.0 || kContentRect.height() <= 4.0)
            {
                return;
            }

            painter.setPen(QPen(QColor(110, 168, 235, 48), 1.0));
            painter.setBrush(QColor(255, 255, 255, 8));
            painter.drawRoundedRect(kContentRect, 6.0, 6.0);

            painter.setPen(QPen(QColor(110, 168, 235, 28), 1.0));
            const double kMidY = kContentRect.top() + kContentRect.height() * 0.5;
            painter.drawLine(
                QPointF(kContentRect.left() + 4.0, kMidY),
                QPointF(kContentRect.right() - 4.0, kMidY));

            if (samples_.size() < 2)
            {
                return;
            }

            QPainterPath linePath;
            const double kUsableWidth = std::max(1.0, kContentRect.width() - 8.0);
            const double kUsableHeight = std::max(1.0, kContentRect.height() - 8.0);
            for (int indexValue = 0; indexValue < samples_.size(); ++indexValue)
            {
                const int kSampleCount = samples_.size();
                const double kTargetRatio =
                    static_cast<double>(indexValue) / static_cast<double>(kSampleCount - 1);
                double startRatio = kTargetRatio;
                if (animationProgress_ < 1.0)
                {
                    if (historyWindowShifted_ && previousSampleCount_ == kSampleCount)
                    {
                        startRatio = indexValue + 1 < kSampleCount
                            ? static_cast<double>(indexValue + 1) / static_cast<double>(kSampleCount - 1)
                            : 1.0;
                    }
                    else if (previousSampleCount_ + 1 == kSampleCount && previousSampleCount_ > 1)
                    {
                        startRatio = indexValue < previousSampleCount_
                            ? static_cast<double>(indexValue) / static_cast<double>(previousSampleCount_ - 1)
                            : 1.0;
                    }
                }
                const double kXRatio =
                    startRatio + (kTargetRatio - startRatio) * animationProgress_;
                const double kXValue = kContentRect.left() + 4.0 + kUsableWidth * kXRatio;
                double sampleValue = samples_.at(indexValue);
                if (indexValue == samples_.size() - 1 && animationProgress_ < 1.0)
                {
                    sampleValue = previousSample_
                        + (sampleValue - previousSample_) * animationProgress_;
                }
                const double kYValue =
                    kContentRect.bottom() - 4.0 - kUsableHeight * (sampleValue / 100.0);
                if (indexValue == 0)
                {
                    linePath.moveTo(kXValue, kYValue);
                }
                else
                {
                    linePath.lineTo(kXValue, kYValue);
                }
            }

            painter.setPen(QPen(QColor(72, 170, 255, 230), 1.5));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
        }

    private:
        QVector<double> samples_;
        int previousSampleCount_ = 0;
        bool historyWindowShifted_ = false;
        QVariantAnimation* sampleAnimation_ = nullptr;
        double previousSample_ = 0.0;
        double animationProgress_ = 1.0;
    };

    constexpr double kOneGiBInBytes = 1024.0 * 1024.0 * 1024.0;

    QColor textPrimaryColor()
    {
        return QColor(242, 246, 252);
    }

    QString queryPowerShellTextSync(const QString& scriptText, const int timeoutMs)
    {
        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments({
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
            });
        process.start();
        if (!process.waitForStarted(1200))
        {
            return QStringLiteral("PowerShell start failed.");
        }
        if (!process.waitForFinished(timeoutMs))
        {
            process.kill();
            process.waitForFinished(800);
            return QStringLiteral("PowerShell timeout.");
        }
        const QString kStandardOutputText =
            QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
        const QString kStandardErrorText =
            QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            return kStandardErrorText.isEmpty()
                ? QStringLiteral("PowerShell failed.")
                : kStandardErrorText;
        }
        return kStandardOutputText.isEmpty() ? QStringLiteral("<empty>") : kStandardOutputText;
    }

    QString extractSensorValueFromOutput(const QString& rawOutputText)
    {
        const QString kFirstLineText = rawOutputText
            .split('\n', Qt::SkipEmptyParts)
            .value(0)
            .trimmed();
        if (kFirstLineText.isEmpty()
            || kFirstLineText == QStringLiteral("<empty>")
            || kFirstLineText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive)
            || kFirstLineText.contains(QStringLiteral("failed"), Qt::CaseInsensitive)
            || kFirstLineText.contains(QStringLiteral("timeout"), Qt::CaseInsensitive))
        {
            return QStringLiteral("N/A");
        }
        return kFirstLineText;
    }

    QString queryCpuTemperatureText()
    {
        const QString kTemperatureScript = QStringLiteral(
            "$v=Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | "
            "Select-Object -First 1 -ExpandProperty CurrentTemperature; "
            "if($null -eq $v){'N/A'}else{([math]::Round(($v/10)-273.15,1)).ToString() + '°C'}");
        return extractSensorValueFromOutput(queryPowerShellTextSync(kTemperatureScript, 2200));
    }

    QString queryCpuVoltageText()
    {
        const QString kVoltageScript = QStringLiteral(
            "$v=Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty CurrentVoltage; "
            "if($null -eq $v -or $v -eq 0){'N/A'}else{([math]::Round($v*0.1,2)).ToString() + 'V'}");
        return extractSensorValueFromOutput(queryPowerShellTextSync(kVoltageScript, 2200));
    }

    QString queryCpuBrandTextByCpuid()
    {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0x80000000);
        const unsigned int kMaxExtendedLeaf = static_cast<unsigned int>(cpuInfo[0]);
        if (kMaxExtendedLeaf < 0x80000004)
        {
            return QStringLiteral("N/A");
        }

        char brandBuffer[49] = {};
        int* brandIntBuffer = reinterpret_cast<int*>(brandBuffer);
        __cpuid(brandIntBuffer, 0x80000002);
        __cpuid(brandIntBuffer + 4, 0x80000003);
        __cpuid(brandIntBuffer + 8, 0x80000004);

        const QString kBrandText = QString::fromLatin1(brandBuffer).trimmed();
        return kBrandText.isEmpty() ? QStringLiteral("N/A") : kBrandText;
    }

    int countBits(KAFFINITY affinityMask)
    {
        int count = 0;
        while (affinityMask != 0)
        {
            count += static_cast<int>(affinityMask & 1);
            affinityMask >>= 1;
        }
        return count;
    }

    void appendTransparentBackgroundStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);

        const QString kTransparentStyleText =
            QStringLiteral("background:transparent;background-color:transparent;border:none;");
        if (!widgetPointer->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            widgetPointer->setStyleSheet(widgetPointer->styleSheet() + kTransparentStyleText);
        }

        QAbstractScrollArea* abstractScrollAreaPointer =
            qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (abstractScrollAreaPointer == nullptr || abstractScrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        abstractScrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        abstractScrollAreaPointer->viewport()->setAutoFillBackground(false);
        if (!abstractScrollAreaPointer->viewport()->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            abstractScrollAreaPointer->viewport()->setStyleSheet(
                abstractScrollAreaPointer->viewport()->styleSheet() + kTransparentStyleText);
        }
    }

    void configureTransparentChart(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setPlotAreaBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
        chartPointer->setTitleBrush(QBrush(textPrimaryColor()));
        if (chartPointer->legend() != nullptr)
        {
            chartPointer->legend()->setLabelColor(textPrimaryColor());
        }
    }

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

    QString bytesToReadableText(const double bytesValue)
    {
        const double kSafeValue = std::max(0.0, bytesValue);
        if (kSafeValue < 1024.0)
        {
            return QStringLiteral("%1 B").arg(kSafeValue, 0, 'f', 0);
        }
        if (kSafeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(kSafeValue / 1024.0, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(kSafeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(kSafeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    QString resolveGpuEngineKeyFromCounter(const QString& counterNameText)
    {
        const QString kLowerText = counterNameText.toLower();
        if (kLowerText.contains(QStringLiteral("engtype_3d")))
        {
            return QStringLiteral("3d");
        }
        if (kLowerText.contains(QStringLiteral("engtype_copy")))
        {
            return QStringLiteral("copy");
        }
        if (kLowerText.contains(QStringLiteral("engtype_videoencode"))
            || kLowerText.contains(QStringLiteral("engtype_videncode")))
        {
            return QStringLiteral("video_encode");
        }
        if (kLowerText.contains(QStringLiteral("engtype_videodecode"))
            || kLowerText.contains(QStringLiteral("engtype_viddecode")))
        {
            return QStringLiteral("video_decode");
        }
        return QString();
    }

    QString formatDurationText(const std::uint64_t totalSeconds)
    {
        const std::uint64_t kDayCount = totalSeconds / 86400ULL;
        const std::uint64_t kHourCount = (totalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t kMinuteCount = (totalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t kSecondCount = totalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3:%4")
            .arg(kDayCount)
            .arg(kHourCount, 2, 10, QLatin1Char('0'))
            .arg(kMinuteCount, 2, 10, QLatin1Char('0'))
            .arg(kSecondCount, 2, 10, QLatin1Char('0'));
    }

    struct MemoryHardwareSummarySnapshot
    {
        int speedMhz = 0;
        int usedSlots = 0;
        int totalSlots = 0;
        QString formFactorText = QStringLiteral("N/A");
    };

    struct GpuHardwareSummarySnapshot
    {
        QString adapterNameText = QStringLiteral("N/A");
        QString driverVersionText = QStringLiteral("N/A");
        QString driverDateText = QStringLiteral("N/A");
        QString pnpDeviceIdText = QStringLiteral("N/A");
        double dedicatedMemoryGiB = 0.0;
    };

    MemoryHardwareSummarySnapshot queryMemoryHardwareSummarySnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$mods=Get-CimInstance Win32_PhysicalMemory; "
            "$arr=Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1 -ExpandProperty MemoryDevices; "
            "$speed=($mods | Select-Object -First 1 -ExpandProperty ConfiguredClockSpeed); "
            "$formCode=($mods | Select-Object -First 1 -ExpandProperty FormFactor); "
            "$formText=if([int]$formCode -eq 8){'DIMM'}elseif([int]$formCode -eq 12){'SODIMM'}elseif([int]$formCode -gt 0){'Code'+[string]$formCode}else{'N/A'}; "
            "\"$speed|$($mods.Count)|$arr|$formText\"");
        const QString kOutputText = queryPowerShellTextSync(kScriptText, 3200);
        const QStringList kFieldList = kOutputText.split('|');

        MemoryHardwareSummarySnapshot snapshot;
        if (kFieldList.size() >= 4)
        {
            snapshot.speedMhz = kFieldList.at(0).trimmed().toInt();
            snapshot.usedSlots = kFieldList.at(1).trimmed().toInt();
            snapshot.totalSlots = kFieldList.at(2).trimmed().toInt();
            snapshot.formFactorText = kFieldList.at(3).trimmed();
            if (snapshot.formFactorText.isEmpty())
            {
                snapshot.formFactorText = QStringLiteral("N/A");
            }
        }
        return snapshot;
    }

    GpuHardwareSummarySnapshot queryGpuHardwareSummarySnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1 Name,DriverVersion,DriverDate,AdapterRAM,PNPDeviceID; "
            "if($null -eq $gpu){'N/A|N/A|N/A|N/A|0'}else{\"$($gpu.Name)|$($gpu.DriverVersion)|$($gpu.DriverDate)|$($gpu.PNPDeviceID)|$($gpu.AdapterRAM)\"}");
        const QString kOutputText = queryPowerShellTextSync(kScriptText, 2800);
        const QStringList kFieldList = kOutputText.split('|');

        GpuHardwareSummarySnapshot snapshot;
        if (kFieldList.size() >= 5)
        {
            snapshot.adapterNameText = kFieldList.at(0).trimmed();
            snapshot.driverVersionText = kFieldList.at(1).trimmed();
            snapshot.driverDateText = kFieldList.at(2).trimmed();
            snapshot.pnpDeviceIdText = kFieldList.at(3).trimmed();
            const double kMemoryBytes = kFieldList.at(4).trimmed().toDouble();
            snapshot.dedicatedMemoryGiB = kMemoryBytes / kOneGiBInBytes;
        }
        return snapshot;
    }

    QChartView* createNoFrameChartView(QChart* chartPointer, QWidget* parentWidget)
    {
        chartPointer->setAnimationOptions(QChart::kAllAnimations);
        chartPointer->setAnimationDuration(260);
        chartPointer->setAnimationEasingCurve(QEasingCurve::OutCubic);
        configureTransparentChart(chartPointer);
        QChartView* chartView = new QChartView(chartPointer, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        chartView->setMinimumHeight(56);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }
}

HudPerformancePanel::HudPerformancePanel(QWidget* parent)
    : QWidget(parent)
{
    appendTransparentBackgroundStyle(this);
    initializeUi();
    refreshCpuTopologyStaticInfo();
    refreshSystemVolumeInfo();

    cachedSensorText_ = QStringLiteral("N/A|N/A");
    if (cpuModelLabel_ != nullptr)
    {
        cpuModelLabel_->setText(cpuModelText_);
    }

    requestAsyncStaticInfoRefresh();
    requestAsyncSensorRefresh();

    liveSampleWatcher_ = new QFutureWatcher<LiveSampleResult>(this);
    connect(liveSampleWatcher_, &QFutureWatcher<LiveSampleResult>::finished, this, [this]()
    {
        liveSampleInProgress_ = false;
        applyLiveSampleResult(liveSampleWatcher_->result());
    });

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(1000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]()
    {
        requestLiveRefresh();
    });
    refreshTimer_->start();

    requestLiveRefresh();
}

HudPerformancePanel::~HudPerformancePanel()
{
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }
    if (liveSampleWatcher_ != nullptr)
    {
        liveSampleWatcher_->waitForFinished();
    }

    if (cpuPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_));
        cpuPerfQueryHandle_ = nullptr;
        coreCounterHandles_.clear();
    }

    if (diskPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_));
        diskPerfQueryHandle_ = nullptr;
        diskReadCounterHandle_ = nullptr;
        diskWriteCounterHandle_ = nullptr;
    }

    if (gpuPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(gpuPerfQueryHandle_));
        gpuPerfQueryHandle_ = nullptr;
        gpuCounterHandle_ = nullptr;
    }
}

void HudPerformancePanel::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    adjustChartHeights();
}

void HudPerformancePanel::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
    QTimer::singleShot(0, this, [this]()
    {
        adjustChartHeights();
    });
    QTimer::singleShot(80, this, [this]()
    {
        adjustChartHeights();
    });
}

void HudPerformancePanel::initializeUi()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    bodyLayout_ = new QHBoxLayout();
    bodyLayout_->setContentsMargins(0, 0, 0, 0);
    bodyLayout_->setSpacing(8);
    rootLayout->addLayout(bodyLayout_, 1);

    sidebarList_ = new QListWidget(this);
    sidebarList_->setFrameShape(QFrame::NoFrame);
    sidebarList_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    sidebarList_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    sidebarList_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    sidebarList_->setSelectionMode(QAbstractItemView::SingleSelection);
    sidebarList_->setSpacing(3);
    sidebarList_->setFixedWidth(286);
    sidebarList_->setStyleSheet(QStringLiteral(
        "QListWidget{border:none;background:transparent;}"
        "QListWidget::item{border:none;padding:0px;margin:0px;}"
        "QListWidget::item:selected{background:transparent;}"));
    appendTransparentBackgroundStyle(sidebarList_);
    bodyLayout_->addWidget(sidebarList_, 0);

    detailStack_ = new QStackedWidget(this);
    appendTransparentBackgroundStyle(detailStack_);
    bodyLayout_->addWidget(detailStack_, 1);

    initializeCpuPage();
    initializeMemoryPage();
    initializeDiskPage();
    initializeNetworkPage();
    initializeGpuPage();
    initializeSidebarCards();

    connect(sidebarList_, &QListWidget::currentRowChanged, this, [this](const int rowIndex)
    {
        syncSidebarSelection(rowIndex);
    });

    sidebarList_->setCurrentRow(0);
    syncSidebarSelection(0);
}

void HudPerformancePanel::initializeSidebarCards()
{
    auto addCardItem =
        [this](PerformanceNavCard*& cardOut, const QString& titleText, const QColor& accentColor)
        {
            QListWidgetItem* itemPointer = new QListWidgetItem();
            cardOut = new PerformanceNavCard(sidebarList_);
            cardOut->setTitleText(titleText);
            cardOut->setSubtitleText(QStringLiteral("Sampling..."));
            cardOut->setAccentColor(accentColor);
            itemPointer->setSizeHint(cardOut->sizeHint());
            sidebarList_->addItem(itemPointer);
            sidebarList_->setItemWidget(itemPointer, cardOut);
        };

    addCardItem(cpuNavCard_, QStringLiteral("CPU"), QColor(90, 178, 255));
    addCardItem(memoryNavCard_, QStringLiteral("Memory"), QColor(184, 99, 255));
    addCardItem(diskNavCard_, QStringLiteral("Disk"), QColor(104, 204, 116));
    addCardItem(networkNavCard_, QStringLiteral("Ethernet"), QColor(230, 149, 76));
    addCardItem(gpuNavCard_, QStringLiteral("GPU"), QColor(105, 173, 255));
}

void HudPerformancePanel::initializeCpuPage()
{
    cpuPage_ = new QWidget(detailStack_);
    appendTransparentBackgroundStyle(cpuPage_);
    QVBoxLayout* pageLayout = new QVBoxLayout(cpuPage_);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("CPU"), cpuPage_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:#F2F6FC;"));
    cpuModelLabel_ = new QLabel(QStringLiteral("Detecting..."), cpuPage_);
    cpuModelLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    cpuModelLabel_->setStyleSheet(QStringLiteral("font-size:15px;font-weight:500;color:#F2F6FC;"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(cpuModelLabel_, 0);
    pageLayout->addLayout(headerLayout, 0);

    cpuSummaryLabel_ = new QLabel(QStringLiteral("30-second utilization history"), cpuPage_);
    cpuSummaryLabel_->setStyleSheet(QStringLiteral("color:#B9CDE1;font-size:14px;font-weight:600;"));
    pageLayout->addWidget(cpuSummaryLabel_, 0);

    coreChartScrollArea_ = new QScrollArea(cpuPage_);
    coreChartScrollArea_->setWidgetResizable(true);
    coreChartScrollArea_->setFrameShape(QFrame::NoFrame);
    coreChartScrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    coreChartScrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    coreChartScrollArea_->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    appendTransparentBackgroundStyle(coreChartScrollArea_);

    coreChartHostWidget_ = new QWidget(coreChartScrollArea_);
    appendTransparentBackgroundStyle(coreChartHostWidget_);
    coreChartGridLayout_ = new QGridLayout(coreChartHostWidget_);
    coreChartGridLayout_->setContentsMargins(0, 0, 0, 0);
    coreChartGridLayout_->setHorizontalSpacing(6);
    coreChartGridLayout_->setVerticalSpacing(6);
    coreChartScrollArea_->setWidget(coreChartHostWidget_);
    pageLayout->addWidget(coreChartScrollArea_, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    cpuPrimaryDetailLabel_ = new QLabel(QStringLiteral("Sampling..."), cpuPage_);
    cpuSecondaryDetailLabel_ = new QLabel(QStringLiteral("Loading hardware details..."), cpuPage_);
    cpuPrimaryDetailLabel_->setWordWrap(false);
    cpuSecondaryDetailLabel_->setWordWrap(false);
    cpuPrimaryDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    cpuSecondaryDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    detailLayout->addWidget(cpuPrimaryDetailLabel_, 1);
    detailLayout->addWidget(cpuSecondaryDetailLabel_, 1);
    pageLayout->addLayout(detailLayout, 0);

    initializeCoreCharts();
    detailStack_->addWidget(cpuPage_);
}

void HudPerformancePanel::initializeMemoryPage()
{
    memoryPage_ = new QWidget(detailStack_);
    appendTransparentBackgroundStyle(memoryPage_);
    QVBoxLayout* pageLayout = new QVBoxLayout(memoryPage_);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("Memory"), memoryPage_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:#F2F6FC;"));
    memoryCapacityLabel_ = new QLabel(QStringLiteral("Loading..."), memoryPage_);
    memoryCapacityLabel_->setStyleSheet(QStringLiteral("font-size:31px;font-weight:500;color:#F2F6FC;"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(memoryCapacityLabel_, 0);
    pageLayout->addLayout(headerLayout, 0);

    memorySummaryLabel_ = new QLabel(QStringLiteral("Memory utilization"), memoryPage_);
    memorySummaryLabel_->setStyleSheet(QStringLiteral("color:#B9CDE1;font-size:14px;font-weight:600;"));
    pageLayout->addWidget(memorySummaryLabel_, 0);

    memoryLineSeries_ = new QLineSeries(memoryPage_);
    memoryLineSeries_->setColor(QColor(184, 99, 255));
    for (int indexValue = 0; indexValue < historyLength_; ++indexValue)
    {
        memoryLineSeries_->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(memoryLineSeries_);
    chartPointer->legend()->hide();
    chartPointer->setTitle(QStringLiteral("Memory usage trend"));

    memoryAxisX_ = new QValueAxis(chartPointer);
    memoryAxisX_->setRange(0, historyLength_);
    memoryAxisX_->setLabelsVisible(false);
    memoryAxisX_->setGridLineVisible(true);
    memoryAxisX_->setGridLineColor(QColor(184, 99, 255, 35));

    memoryAxisY_ = new QValueAxis(chartPointer);
    memoryAxisY_->setRange(0.0, 100.0);
    memoryAxisY_->setLabelsVisible(false);
    memoryAxisY_->setGridLineVisible(true);
    memoryAxisY_->setGridLineColor(QColor(184, 99, 255, 35));

    chartPointer->addAxis(memoryAxisX_, Qt::AlignBottom);
    chartPointer->addAxis(memoryAxisY_, Qt::AlignLeft);
    memoryLineSeries_->attachAxis(memoryAxisX_);
    memoryLineSeries_->attachAxis(memoryAxisY_);

    memoryChartView_ = createNoFrameChartView(chartPointer, memoryPage_);
    pageLayout->addWidget(memoryChartView_, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    memoryPrimaryDetailLabel_ = new QLabel(QStringLiteral("Sampling..."), memoryPage_);
    memorySecondaryDetailLabel_ = new QLabel(QStringLiteral("Loading hardware details..."), memoryPage_);
    memoryPrimaryDetailLabel_->setWordWrap(false);
    memorySecondaryDetailLabel_->setWordWrap(false);
    memoryPrimaryDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    memorySecondaryDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    detailLayout->addWidget(memoryPrimaryDetailLabel_, 1);
    detailLayout->addWidget(memorySecondaryDetailLabel_, 1);
    pageLayout->addLayout(detailLayout, 0);

    detailStack_->addWidget(memoryPage_);
}

void HudPerformancePanel::initializeDiskPage()
{
    diskPage_ = new QWidget(detailStack_);
    appendTransparentBackgroundStyle(diskPage_);
    QVBoxLayout* pageLayout = new QVBoxLayout(diskPage_);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("Disk"), diskPage_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:#F2F6FC;"));
    pageLayout->addWidget(titleLabel, 0);

    diskSummaryLabel_ = new QLabel(QStringLiteral("Initializing..."), diskPage_);
    diskSummaryLabel_->setStyleSheet(QStringLiteral("color:#B9CDE1;font-size:14px;font-weight:600;"));
    pageLayout->addWidget(diskSummaryLabel_, 0);

    diskReadLineSeries_ = new QLineSeries(diskPage_);
    diskReadLineSeries_->setName(QStringLiteral("Read"));
    diskReadLineSeries_->setColor(QColor(80, 170, 255));
    diskWriteLineSeries_ = new QLineSeries(diskPage_);
    diskWriteLineSeries_->setName(QStringLiteral("Write"));
    diskWriteLineSeries_->setColor(QColor(255, 190, 105));
    for (int indexValue = 0; indexValue < historyLength_; ++indexValue)
    {
        diskReadLineSeries_->append(indexValue, 0.0);
        diskWriteLineSeries_->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(diskReadLineSeries_);
    chartPointer->addSeries(diskWriteLineSeries_);
    chartPointer->legend()->setVisible(true);
    chartPointer->legend()->setAlignment(Qt::AlignBottom);
    chartPointer->setTitle(QStringLiteral("Disk throughput trend"));

    diskAxisX_ = new QValueAxis(chartPointer);
    diskAxisX_->setRange(0, historyLength_);
    diskAxisX_->setLabelsVisible(false);
    diskAxisX_->setGridLineVisible(false);

    diskAxisY_ = new QValueAxis(chartPointer);
    diskAxisY_->setRange(0.0, 1.0);
    diskAxisY_->setLabelsVisible(false);
    diskAxisY_->setGridLineVisible(false);

    chartPointer->addAxis(diskAxisX_, Qt::AlignBottom);
    chartPointer->addAxis(diskAxisY_, Qt::AlignLeft);
    diskReadLineSeries_->attachAxis(diskAxisX_);
    diskReadLineSeries_->attachAxis(diskAxisY_);
    diskWriteLineSeries_->attachAxis(diskAxisX_);
    diskWriteLineSeries_->attachAxis(diskAxisY_);

    diskChartView_ = createNoFrameChartView(chartPointer, diskPage_);
    pageLayout->addWidget(diskChartView_, 1);

    diskDetailLabel_ = new QLabel(QStringLiteral("Sampling..."), diskPage_);
    diskDetailLabel_->setWordWrap(false);
    diskDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    pageLayout->addWidget(diskDetailLabel_, 0);

    detailStack_->addWidget(diskPage_);
}

void HudPerformancePanel::initializeNetworkPage()
{
    networkPage_ = new QWidget(detailStack_);
    appendTransparentBackgroundStyle(networkPage_);
    QVBoxLayout* pageLayout = new QVBoxLayout(networkPage_);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("Ethernet"), networkPage_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:#F2F6FC;"));
    pageLayout->addWidget(titleLabel, 0);

    networkSummaryLabel_ = new QLabel(QStringLiteral("Initializing..."), networkPage_);
    networkSummaryLabel_->setStyleSheet(QStringLiteral("color:#B9CDE1;font-size:14px;font-weight:600;"));
    pageLayout->addWidget(networkSummaryLabel_, 0);

    networkRxLineSeries_ = new QLineSeries(networkPage_);
    networkRxLineSeries_->setName(QStringLiteral("Receive"));
    networkRxLineSeries_->setColor(QColor(92, 190, 255));
    networkTxLineSeries_ = new QLineSeries(networkPage_);
    networkTxLineSeries_->setName(QStringLiteral("Send"));
    networkTxLineSeries_->setColor(QColor(153, 129, 255));
    for (int indexValue = 0; indexValue < historyLength_; ++indexValue)
    {
        networkRxLineSeries_->append(indexValue, 0.0);
        networkTxLineSeries_->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(networkRxLineSeries_);
    chartPointer->addSeries(networkTxLineSeries_);
    chartPointer->legend()->setVisible(true);
    chartPointer->legend()->setAlignment(Qt::AlignBottom);
    chartPointer->setTitle(QStringLiteral("Network throughput trend"));

    networkAxisX_ = new QValueAxis(chartPointer);
    networkAxisX_->setRange(0, historyLength_);
    networkAxisX_->setLabelsVisible(false);
    networkAxisX_->setGridLineVisible(false);

    networkAxisY_ = new QValueAxis(chartPointer);
    networkAxisY_->setRange(0.0, 1.0);
    networkAxisY_->setLabelsVisible(false);
    networkAxisY_->setGridLineVisible(false);

    chartPointer->addAxis(networkAxisX_, Qt::AlignBottom);
    chartPointer->addAxis(networkAxisY_, Qt::AlignLeft);
    networkRxLineSeries_->attachAxis(networkAxisX_);
    networkRxLineSeries_->attachAxis(networkAxisY_);
    networkTxLineSeries_->attachAxis(networkAxisX_);
    networkTxLineSeries_->attachAxis(networkAxisY_);

    networkChartView_ = createNoFrameChartView(chartPointer, networkPage_);
    pageLayout->addWidget(networkChartView_, 1);

    networkDetailLabel_ = new QLabel(QStringLiteral("Sampling..."), networkPage_);
    networkDetailLabel_->setWordWrap(false);
    networkDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    pageLayout->addWidget(networkDetailLabel_, 0);

    detailStack_->addWidget(networkPage_);
}

void HudPerformancePanel::initializeGpuPage()
{
    gpuPage_ = new QWidget(detailStack_);
    appendTransparentBackgroundStyle(gpuPage_);
    QVBoxLayout* pageLayout = new QVBoxLayout(gpuPage_);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("GPU"), gpuPage_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:#F2F6FC;"));
    gpuAdapterTitleLabel_ = new QLabel(QStringLiteral("Loading adapter..."), gpuPage_);
    gpuAdapterTitleLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    gpuAdapterTitleLabel_->setStyleSheet(QStringLiteral("font-size:18px;font-weight:500;color:#F2F6FC;"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(gpuAdapterTitleLabel_, 0);
    pageLayout->addLayout(headerLayout, 0);

    gpuSummaryLabel_ = new QLabel(QStringLiteral("Initializing..."), gpuPage_);
    gpuSummaryLabel_->setStyleSheet(QStringLiteral("color:#B9CDE1;font-size:14px;font-weight:600;"));
    pageLayout->addWidget(gpuSummaryLabel_, 0);

    gpuEngineHostWidget_ = new QWidget(gpuPage_);
    appendTransparentBackgroundStyle(gpuEngineHostWidget_);
    gpuEngineGridLayout_ = new QGridLayout(gpuEngineHostWidget_);
    gpuEngineGridLayout_->setContentsMargins(0, 0, 0, 0);
    gpuEngineGridLayout_->setHorizontalSpacing(6);
    gpuEngineGridLayout_->setVerticalSpacing(6);
    gpuEngineCharts_.clear();

    auto addGpuEngineChart =
        [this](const QString& engineKeyText, const QString& displayNameText, const QColor& lineColor, const int rowIndex, const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(gpuEngineHostWidget_);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(0, 0, 0, 0);
            cellLayout->setSpacing(2);

            QLabel* cellTitle = new QLabel(displayNameText, cellWidget);
            cellTitle->setStyleSheet(QStringLiteral("font-size:14px;font-weight:600;color:#F2F6FC;"));
            cellLayout->addWidget(cellTitle, 0);

            QLineSeries* lineSeries = new QLineSeries(cellWidget);
            lineSeries->setColor(lineColor);
            for (int historyIndex = 0; historyIndex < historyLength_; ++historyIndex)
            {
                lineSeries->append(historyIndex, 0.0);
            }

            QChart* chartPointer = new QChart();
            chartPointer->addSeries(lineSeries);
            chartPointer->legend()->hide();

            QValueAxis* axisX = new QValueAxis(chartPointer);
            axisX->setRange(0, historyLength_);
            axisX->setLabelsVisible(false);
            axisX->setGridLineVisible(true);
            axisX->setGridLineColor(QColor(lineColor.red(), lineColor.green(), lineColor.blue(), 40));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            axisY->setRange(0.0, 100.0);
            axisY->setLabelsVisible(false);
            axisY->setGridLineVisible(true);
            axisY->setGridLineColor(QColor(lineColor.red(), lineColor.green(), lineColor.blue(), 40));

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            lineSeries->attachAxis(axisX);
            lineSeries->attachAxis(axisY);

            QChartView* chartView = createNoFrameChartView(chartPointer, cellWidget);
            cellLayout->addWidget(chartView, 1);
            gpuEngineGridLayout_->addWidget(cellWidget, rowIndex, columnIndex);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = engineKeyText;
            chartEntry.displayNameText = displayNameText;
            chartEntry.titleLabel = cellTitle;
            chartEntry.chartView = chartView;
            chartEntry.lineSeries = lineSeries;
            chartEntry.axisX = axisX;
            chartEntry.axisY = axisY;
            gpuEngineCharts_.push_back(chartEntry);
        };

    addGpuEngineChart(QStringLiteral("3d"), QStringLiteral("3D"), QColor(105, 173, 255), 0, 0);
    addGpuEngineChart(QStringLiteral("copy"), QStringLiteral("Copy"), QColor(110, 196, 247), 0, 1);
    addGpuEngineChart(QStringLiteral("video_encode"), QStringLiteral("Video Encode"), QColor(125, 184, 255), 1, 0);
    addGpuEngineChart(QStringLiteral("video_decode"), QStringLiteral("Video Decode"), QColor(137, 178, 255), 1, 1);
    pageLayout->addWidget(gpuEngineHostWidget_, 1);

    gpuDedicatedMemoryLineSeries_ = new QLineSeries(gpuPage_);
    gpuDedicatedMemoryLineSeries_->setColor(QColor(92, 167, 255));
    gpuSharedMemoryLineSeries_ = new QLineSeries(gpuPage_);
    gpuSharedMemoryLineSeries_->setColor(QColor(113, 185, 255));
    for (int indexValue = 0; indexValue < historyLength_; ++indexValue)
    {
        gpuDedicatedMemoryLineSeries_->append(indexValue, 0.0);
        gpuSharedMemoryLineSeries_->append(indexValue, 0.0);
    }

    auto createGpuMemoryChart =
        [this](
            const QString& titleText,
            QLineSeries* lineSeries,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            QChart* chartPointer = new QChart();
            chartPointer->addSeries(lineSeries);
            chartPointer->legend()->hide();
            chartPointer->setTitle(titleText);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            axisX->setRange(0, historyLength_);
            axisX->setLabelsVisible(false);
            axisX->setGridLineVisible(true);
            axisX->setGridLineColor(QColor(92, 167, 255, 35));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            axisY->setRange(0.0, 1.0);
            axisY->setLabelsVisible(false);
            axisY->setGridLineVisible(true);
            axisY->setGridLineColor(QColor(92, 167, 255, 35));

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            lineSeries->attachAxis(axisX);
            lineSeries->attachAxis(axisY);

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
                *chartViewOut = createNoFrameChartView(chartPointer, gpuPage_);
            }
        };

    createGpuMemoryChart(
        QStringLiteral("Dedicated GPU memory"),
        gpuDedicatedMemoryLineSeries_,
        &gpuDedicatedMemoryAxisX_,
        &gpuDedicatedMemoryAxisY_,
        &gpuDedicatedMemoryChartView_);
    createGpuMemoryChart(
        QStringLiteral("Shared GPU memory"),
        gpuSharedMemoryLineSeries_,
        &gpuSharedMemoryAxisX_,
        &gpuSharedMemoryAxisY_,
        &gpuSharedMemoryChartView_);

    pageLayout->addWidget(gpuDedicatedMemoryChartView_, 0);
    pageLayout->addWidget(gpuSharedMemoryChartView_, 0);

    gpuDetailLabel_ = new QLabel(QStringLiteral("Sampling..."), gpuPage_);
    gpuDetailLabel_->setWordWrap(false);
    gpuDetailLabel_->setStyleSheet(QStringLiteral("font-size:14px;color:#F2F6FC;"));
    pageLayout->addWidget(gpuDetailLabel_, 0);

    detailStack_->addWidget(gpuPage_);
}

void HudPerformancePanel::initializeCoreCharts()
{
    const DWORD kLogicalProcessorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const int kCoreCount = static_cast<int>(kLogicalProcessorCount);
    const int kColumnCount = std::max(1, static_cast<int>(std::ceil(std::sqrt(static_cast<double>(kCoreCount)))));
    const int kRowCount = std::max(
        1,
        static_cast<int>(std::ceil(static_cast<double>(kCoreCount) / static_cast<double>(kColumnCount))));
    cpuCoreGridColumnCount_ = kColumnCount;
    cpuCoreGridRowCount_ = kRowCount;

    coreChartEntries_.clear();
    coreChartEntries_.reserve(kCoreCount);

    for (int coreIndex = 0; coreIndex < kCoreCount; ++coreIndex)
    {
        CoreChartEntry chartEntry;
        chartEntry.containerWidget = new QWidget(coreChartHostWidget_);
        appendTransparentBackgroundStyle(chartEntry.containerWidget);
        QVBoxLayout* containerLayout = new QVBoxLayout(chartEntry.containerWidget);
        containerLayout->setContentsMargins(4, 4, 4, 4);
        containerLayout->setSpacing(2);

        chartEntry.titleLabel = new QLabel(
            QStringLiteral("CPU %1").arg(coreIndex),
            chartEntry.containerWidget);
        chartEntry.titleLabel->setStyleSheet(QStringLiteral("color:#B9CDE1;font-weight:600;"));
        chartEntry.titleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        chartEntry.titleLabel->setMinimumWidth(128);
        containerLayout->addWidget(chartEntry.titleLabel, 0);

        auto* sparklineWidget = new CpuCoreSparklineWidget(chartEntry.containerWidget);
        chartEntry.chartWidget = sparklineWidget;
        containerLayout->addWidget(chartEntry.chartWidget, 1);

        const int kRowIndex = coreIndex / kColumnCount;
        const int kColumnIndex = coreIndex % kColumnCount;
        coreChartGridLayout_->addWidget(chartEntry.containerWidget, kRowIndex, kColumnIndex);
        coreChartEntries_.push_back(chartEntry);
    }

    adjustChartHeights();
}

void HudPerformancePanel::syncSidebarSelection(const int selectedRowIndex)
{
    if (detailStack_ == nullptr)
    {
        return;
    }

    const int kPageCount = detailStack_->count();
    if (kPageCount <= 0)
    {
        return;
    }

    const int kBoundedIndex = qBound(0, selectedRowIndex, kPageCount - 1);
    detailStack_->setCurrentIndex(kBoundedIndex);

    if (cpuNavCard_ != nullptr) cpuNavCard_->setSelectedState(kBoundedIndex == 0);
    if (memoryNavCard_ != nullptr) memoryNavCard_->setSelectedState(kBoundedIndex == 1);
    if (diskNavCard_ != nullptr) diskNavCard_->setSelectedState(kBoundedIndex == 2);
    if (networkNavCard_ != nullptr) networkNavCard_->setSelectedState(kBoundedIndex == 3);
    if (gpuNavCard_ != nullptr) gpuNavCard_->setSelectedState(kBoundedIndex == 4);

    adjustChartHeights();
    QTimer::singleShot(0, this, [this]() { adjustChartHeights(); });
    QTimer::singleShot(80, this, [this]() { adjustChartHeights(); });
}

void HudPerformancePanel::adjustChartHeights()
{
    if (cpuPage_ != nullptr
        && coreChartHostWidget_ != nullptr
        && coreChartGridLayout_ != nullptr
        && !coreChartEntries_.empty())
    {
        auto applyFixedHeightIfChanged =
            [](QWidget* widgetPointer, const int heightValue)
            {
                if (widgetPointer == nullptr || heightValue <= 0)
                {
                    return;
                }
                if (widgetPointer->minimumHeight() == heightValue
                    && widgetPointer->maximumHeight() == heightValue)
                {
                    return;
                }
                widgetPointer->setMinimumHeight(heightValue);
                widgetPointer->setMaximumHeight(heightValue);
            };

        int chartViewportHeight = 0;
        if (coreChartScrollArea_ != nullptr && coreChartScrollArea_->viewport() != nullptr)
        {
            chartViewportHeight = coreChartScrollArea_->viewport()->height();
        }
        if (chartViewportHeight <= 0 && coreChartScrollArea_ != nullptr)
        {
            chartViewportHeight = coreChartScrollArea_->height();
        }
        if (chartViewportHeight < 120)
        {
            int cpuReferenceHeight = 0;
            if (detailStack_ != nullptr)
            {
                cpuReferenceHeight = detailStack_->contentsRect().height();
            }
            if (cpuReferenceHeight <= 0)
            {
                cpuReferenceHeight = cpuPage_->contentsRect().height();
            }
            chartViewportHeight = std::max(120, cpuReferenceHeight / 2);
        }

        const int kAvailableChartAreaHeight = std::max(1, chartViewportHeight);
        const int kGridRows = std::max(1, cpuCoreGridRowCount_);
        const int kGridSpacing = std::max(0, coreChartGridLayout_->verticalSpacing());
        const int kCellHeight = std::max(
            18,
            (kAvailableChartAreaHeight - kGridSpacing * (kGridRows - 1)) / kGridRows);

        for (CoreChartEntry& chartEntry : coreChartEntries_)
        {
            if (chartEntry.containerWidget != nullptr)
            {
                applyFixedHeightIfChanged(chartEntry.containerWidget, kCellHeight);
            }
            if (chartEntry.chartWidget != nullptr)
            {
                applyFixedHeightIfChanged(chartEntry.chartWidget, std::max(10, kCellHeight - 12));
            }
        }

        const int kHostHeight = kGridRows * kCellHeight + kGridSpacing * (kGridRows - 1);
        applyFixedHeightIfChanged(coreChartHostWidget_, kHostHeight);
        if (coreChartScrollArea_ != nullptr)
        {
            coreChartScrollArea_->setMinimumHeight(0);
            coreChartScrollArea_->setMaximumHeight(QWIDGETSIZE_MAX);
        }
    }

    auto adjustMainChartHeight =
        [](
            QWidget* pageWidget,
            QChartView* chartView,
            const double ratioValue,
            const int minHeightValue,
            const int reserveHeightValue)
        {
            if (pageWidget == nullptr || chartView == nullptr)
            {
                return;
            }
            const int kPageHeight = pageWidget->contentsRect().height();
            const int kMaxAllowedHeight = std::max(minHeightValue, kPageHeight - reserveHeightValue);
            const int kExpectedHeight = static_cast<int>(std::round(static_cast<double>(kPageHeight) * ratioValue));
            const int kFinalHeight = qBound(minHeightValue, kExpectedHeight, kMaxAllowedHeight);
            chartView->setMinimumHeight(kFinalHeight);
            chartView->setMaximumHeight(kFinalHeight);
        };

    adjustMainChartHeight(memoryPage_, memoryChartView_, 0.36, 56, 116);
    adjustMainChartHeight(diskPage_, diskChartView_, 0.40, 58, 120);
    adjustMainChartHeight(networkPage_, networkChartView_, 0.40, 58, 120);

    if (gpuPage_ != nullptr)
    {
        auto applyMaxHeightIfChanged =
            [](QWidget* widgetPointer, const int maxHeightValue)
            {
                if (widgetPointer == nullptr || maxHeightValue <= 0)
                {
                    return;
                }
                if (widgetPointer->minimumHeight() == 0
                    && widgetPointer->maximumHeight() == maxHeightValue)
                {
                    return;
                }
                widgetPointer->setMinimumHeight(0);
                widgetPointer->setMaximumHeight(maxHeightValue);
            };

        int gpuReferenceHeight = 0;
        if (detailStack_ != nullptr)
        {
            gpuReferenceHeight = detailStack_->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = gpuPage_->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = 320;
        }

        const int kTitleHeight = std::max(
            gpuAdapterTitleLabel_ != nullptr ? gpuAdapterTitleLabel_->sizeHint().height() : 0,
            44);
        const int kSummaryHeight = gpuSummaryLabel_ != nullptr
            ? gpuSummaryLabel_->sizeHint().height()
            : 20;
        const int kDetailHeight = gpuDetailLabel_ != nullptr
            ? gpuDetailLabel_->sizeHint().height()
            : 22;
        const int kReservedHeight = kTitleHeight + kSummaryHeight + kDetailHeight + 38;
        const int kAvailableHeight = std::max(120, gpuReferenceHeight - kReservedHeight);
        const int kEngineAreaHeight = static_cast<int>(std::round(static_cast<double>(kAvailableHeight) * 0.52));
        const int kMemoryAreaEachHeight = std::max(34, (kAvailableHeight - kEngineAreaHeight - 8) / 2);

        if (gpuEngineHostWidget_ != nullptr && gpuEngineGridLayout_ != nullptr)
        {
            const int kRowSpacing = std::max(0, gpuEngineGridLayout_->verticalSpacing());
            const int kCellHeight = std::max(30, (kEngineAreaHeight - kRowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : gpuEngineCharts_)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(18, kCellHeight - 10));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(14);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(gpuEngineHostWidget_, kEngineAreaHeight);
        }

        if (gpuDedicatedMemoryChartView_ != nullptr)
        {
            applyMaxHeightIfChanged(gpuDedicatedMemoryChartView_, kMemoryAreaEachHeight);
        }
        if (gpuSharedMemoryChartView_ != nullptr)
        {
            applyMaxHeightIfChanged(gpuSharedMemoryChartView_, kMemoryAreaEachHeight);
        }
    }
}

void HudPerformancePanel::initializePerformanceCounters()
{
    if (cpuPerfQueryHandle_ != nullptr)
    {
        return;
    }

    PDH_HQUERY queryHandle = nullptr;
    const PDH_STATUS kQueryStatus = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
    if (kQueryStatus != ERROR_SUCCESS || queryHandle == nullptr)
    {
        return;
    }

    cpuPerfQueryHandle_ = queryHandle;
    coreCounterHandles_.clear();
    coreCounterHandles_.reserve(coreChartEntries_.size());

    for (int coreIndex = 0; coreIndex < static_cast<int>(coreChartEntries_.size()); ++coreIndex)
    {
        const QString kCounterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            reinterpret_cast<LPCWSTR>(kCounterPath.utf16()),
            0,
            &counterHandle);
        if (kAddStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            coreCounterHandles_.push_back(nullptr);
            continue;
        }
        coreCounterHandles_.push_back(counterHandle);
    }

    ::PdhCollectQueryData(queryHandle);
}

void HudPerformancePanel::refreshAllViews()
{
    requestLiveRefresh();
}

void HudPerformancePanel::requestLiveRefresh()
{
    if (liveSampleInProgress_ || liveSampleWatcher_ == nullptr)
    {
        return;
    }

    liveSampleInProgress_ = true;
    liveSampleWatcher_->setFuture(QtConcurrent::run([this]()
    {
        return collectLiveSampleResult();
    }));
}

HudPerformancePanel::LiveSampleResult HudPerformancePanel::collectLiveSampleResult()
{
    QMutexLocker locker(&liveSampleMutex_);

    LiveSampleResult result;
    result.perCoreOk = samplePerCoreUsage(&result.coreUsageList, &result.totalCpuUsage);
    if (!result.perCoreOk)
    {
        result.coreUsageList.assign(coreChartEntries_.size(), 0.0);
        result.totalCpuUsage = 0.0;
    }

    result.memoryOk = sampleMemoryUsage(&result.memoryUsagePercent);
    if (!result.memoryOk)
    {
        result.memoryUsagePercent = 0.0;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
    {
        result.totalPhysBytes = static_cast<std::uint64_t>(memoryStatus.ullTotalPhys);
        result.availPhysBytes = static_cast<std::uint64_t>(memoryStatus.ullAvailPhys);
    }

    result.diskOk = sampleDiskRate(&result.diskReadBytesPerSec, &result.diskWriteBytesPerSec);
    if (!result.diskOk)
    {
        result.diskReadBytesPerSec = 0.0;
        result.diskWriteBytesPerSec = 0.0;
    }

    result.networkOk = sampleNetworkRate(&result.networkRxBytesPerSec, &result.networkTxBytesPerSec);
    if (!result.networkOk)
    {
        result.networkRxBytesPerSec = 0.0;
        result.networkTxBytesPerSec = 0.0;
    }

    result.gpuOk = sampleGpuUsage(&result.gpuUsagePercent);
    if (!result.gpuOk)
    {
        result.gpuUsagePercent = 0.0;
    }

    result.powerInfoOk = sampleCpuPowerInfo(&result.powerInfoList);
    result.systemPerfOk = sampleSystemPerformanceSnapshot(&result.systemPerfSnapshot);

    result.primaryNetworkAdapterName = primaryNetworkAdapterName_;
    result.primaryNetworkLinkBitsPerSecond = primaryNetworkLinkBitsPerSecond_;
    result.gpuUsage3DPercent = gpuUsage3DPercent_;
    result.gpuUsageCopyPercent = gpuUsageCopyPercent_;
    result.gpuUsageVideoEncodePercent = gpuUsageVideoEncodePercent_;
    result.gpuUsageVideoDecodePercent = gpuUsageVideoDecodePercent_;
    result.gpuDedicatedUsedGiB = gpuDedicatedUsedGiB_;
    result.gpuDedicatedBudgetGiB = gpuDedicatedBudgetGiB_;
    result.gpuSharedUsedGiB = gpuSharedUsedGiB_;
    result.gpuSharedBudgetGiB = gpuSharedBudgetGiB_;
    result.systemVolumeText = systemVolumeText_;
    result.systemVolumeTotalBytes = systemVolumeTotalBytes_;
    result.systemVolumeFreeBytes = systemVolumeFreeBytes_;
    return result;
}

void HudPerformancePanel::applyLiveSampleResult(const LiveSampleResult& liveSampleResult)
{
    {
        QMutexLocker locker(&liveSampleMutex_);
        primaryNetworkAdapterName_ = liveSampleResult.primaryNetworkAdapterName;
        primaryNetworkLinkBitsPerSecond_ = liveSampleResult.primaryNetworkLinkBitsPerSecond;
        gpuUsage3DPercent_ = liveSampleResult.gpuUsage3DPercent;
        gpuUsageCopyPercent_ = liveSampleResult.gpuUsageCopyPercent;
        gpuUsageVideoEncodePercent_ = liveSampleResult.gpuUsageVideoEncodePercent;
        gpuUsageVideoDecodePercent_ = liveSampleResult.gpuUsageVideoDecodePercent;
        gpuDedicatedUsedGiB_ = liveSampleResult.gpuDedicatedUsedGiB;
        gpuDedicatedBudgetGiB_ = liveSampleResult.gpuDedicatedBudgetGiB;
        gpuSharedUsedGiB_ = liveSampleResult.gpuSharedUsedGiB;
        gpuSharedBudgetGiB_ = liveSampleResult.gpuSharedBudgetGiB;
        systemVolumeText_ = liveSampleResult.systemVolumeText;
        systemVolumeTotalBytes_ = liveSampleResult.systemVolumeTotalBytes;
        systemVolumeFreeBytes_ = liveSampleResult.systemVolumeFreeBytes;
        lastTotalPhysBytes_ = liveSampleResult.totalPhysBytes;
        lastAvailPhysBytes_ = liveSampleResult.availPhysBytes;
    }

    ++sampleCounter_;
    updateView(
        liveSampleResult.coreUsageList,
        liveSampleResult.memoryUsagePercent,
        liveSampleResult.diskReadBytesPerSec,
        liveSampleResult.diskWriteBytesPerSec,
        liveSampleResult.networkRxBytesPerSec,
        liveSampleResult.networkTxBytesPerSec,
        liveSampleResult.gpuUsagePercent);
    updateTaskManagerDetailLabels(
        liveSampleResult.coreUsageList,
        liveSampleResult.powerInfoList,
        liveSampleResult.memoryUsagePercent,
        liveSampleResult.diskReadBytesPerSec,
        liveSampleResult.diskWriteBytesPerSec,
        liveSampleResult.networkRxBytesPerSec,
        liveSampleResult.networkTxBytesPerSec,
        liveSampleResult.gpuUsagePercent,
        &liveSampleResult.systemPerfSnapshot,
        liveSampleResult.systemPerfOk);

    if ((sampleCounter_ % 5) == 1)
    {
        requestAsyncSensorRefresh();
    }
    if ((sampleCounter_ % 60) == 1)
    {
        requestAsyncStaticInfoRefresh();
    }
}

bool HudPerformancePanel::samplePerCoreUsage(
    std::vector<double>* coreUsageOut,
    double* totalUsageOut)
{
    if (coreUsageOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }
    if (cpuPerfQueryHandle_ == nullptr)
    {
        initializePerformanceCounters();
    }
    if (cpuPerfQueryHandle_ == nullptr)
    {
        return false;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_);
    if (::PdhCollectQueryData(kQueryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    coreUsageOut->clear();
    coreUsageOut->reserve(coreCounterHandles_.size());
    double usageSum = 0.0;
    int validCount = 0;

    for (void* counterHandleVoid : coreCounterHandles_)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE formattedValue{};
        const PDH_STATUS kReadStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &formattedValue);
        if (kReadStatus != ERROR_SUCCESS)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        const double kUsageValue = qBound(0.0, formattedValue.doubleValue, 100.0);
        coreUsageOut->push_back(kUsageValue);
        usageSum += kUsageValue;
        ++validCount;
    }

    *totalUsageOut = validCount > 0 ? (usageSum / static_cast<double>(validCount)) : 0.0;
    return true;
}

bool HudPerformancePanel::sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut)
{
    if (powerInfoOut == nullptr)
    {
        return false;
    }

    const ULONG kLogicalProcessorCount = std::max<ULONG>(
        1,
        static_cast<ULONG>(coreChartEntries_.size()));
    struct KsProcessorPowerInformation
    {
        ULONG number;
        ULONG maxMhz;
        ULONG currentMhz;
        ULONG mhzLimit;
        ULONG maxIdleState;
        ULONG currentIdleState;
    };
    std::vector<KsProcessorPowerInformation> nativeInfoList(kLogicalProcessorCount);

    const NTSTATUS kNtStatus = ::CallNtPowerInformation(
        ProcessorInformation,
        nullptr,
        0,
        nativeInfoList.data(),
        static_cast<ULONG>(nativeInfoList.size() * sizeof(KsProcessorPowerInformation)));
    if (kNtStatus != 0)
    {
        return false;
    }

    powerInfoOut->clear();
    powerInfoOut->reserve(nativeInfoList.size());
    for (const KsProcessorPowerInformation& nativeInfo : nativeInfoList)
    {
        CpuPowerSnapshot snapshot;
        snapshot.coreIndex = nativeInfo.number;
        snapshot.currentMhz = nativeInfo.currentMhz;
        snapshot.maxMhz = nativeInfo.maxMhz;
        snapshot.limitMhz = nativeInfo.mhzLimit;
        powerInfoOut->push_back(snapshot);
    }
    return true;
}

bool HudPerformancePanel::sampleMemoryUsage(double* memoryUsagePercentOut)
{
    if (memoryUsagePercentOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memoryUsagePercentOut = 0.0;
        return false;
    }

    *memoryUsagePercentOut = static_cast<double>(memoryStatus.dwMemoryLoad);
    return true;
}

bool HudPerformancePanel::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
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

        PDH_HCOUNTER readCounterHandle = nullptr;
        PDH_HCOUNTER writeCounterHandle = nullptr;
        const PDH_STATUS kAddReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
            0,
            &readCounterHandle);
        const PDH_STATUS kAddWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
            0,
            &writeCounterHandle);
        if (kAddReadStatus != ERROR_SUCCESS || kAddWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        diskPerfQueryHandle_ = queryHandle;
        diskReadCounterHandle_ = readCounterHandle;
        diskWriteCounterHandle_ = writeCounterHandle;
        ::PdhCollectQueryData(queryHandle);
        return false;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_);
    if (::PdhCollectQueryData(kQueryHandle) != ERROR_SUCCESS)
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

bool HudPerformancePanel::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    ULONG tableSize = 0;
    if (::GetIfTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER || tableSize == 0)
    {
        return false;
    }

    std::vector<unsigned char> tableBuffer(tableSize);
    auto* tablePointer = reinterpret_cast<MIB_IFTABLE*>(tableBuffer.data());
    if (::GetIfTable(tablePointer, &tableSize, FALSE) != NO_ERROR)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->dwNumEntries; ++rowIndex)
    {
        const MIB_IFROW& rowValue = tablePointer->table[rowIndex];
        if (rowValue.dwOperStatus != IF_OPER_STATUS_OPERATIONAL
            || rowValue.dwType == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        totalRxBytes += static_cast<std::uint64_t>(rowValue.dwInOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.dwOutOctets);

        const std::uint64_t kRowTrafficBytes =
            static_cast<std::uint64_t>(rowValue.dwInOctets)
            + static_cast<std::uint64_t>(rowValue.dwOutOctets);
        if (kRowTrafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = kRowTrafficBytes;
            primaryAdapterName = QString::fromLocal8Bit(
                reinterpret_cast<const char*>(rowValue.bDescr),
                static_cast<int>(rowValue.dwDescrLen)).trimmed();
            primaryLinkBitsPerSecond = static_cast<std::uint64_t>(rowValue.dwSpeed);
        }
    }

    primaryNetworkAdapterName_ = primaryAdapterName;
    primaryNetworkLinkBitsPerSecond_ = primaryLinkBitsPerSecond;

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

    const std::uint64_t kDeltaRx =
        totalRxBytes >= lastNetworkRxBytes_ ? (totalRxBytes - lastNetworkRxBytes_) : 0;
    const std::uint64_t kDeltaTx =
        totalTxBytes >= lastNetworkTxBytes_ ? (totalTxBytes - lastNetworkTxBytes_) : 0;

    lastNetworkSampleMs_ = kNowMs;
    lastNetworkRxBytes_ = totalRxBytes;
    lastNetworkTxBytes_ = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(kDeltaRx) * 1000.0 / static_cast<double>(kElapsedMs);
    *txBytesPerSecOut = static_cast<double>(kDeltaTx) * 1000.0 / static_cast<double>(kElapsedMs);
    return true;
}

bool HudPerformancePanel::sampleGpuUsage(double* gpuUsagePercentOut)
{
    if (gpuUsagePercentOut == nullptr)
    {
        return false;
    }

    if (gpuPerfQueryHandle_ == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            &counterHandle);
        if (kAddStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        gpuPerfQueryHandle_ = queryHandle;
        gpuCounterHandle_ = counterHandle;
        ::PdhCollectQueryData(queryHandle);
        *gpuUsagePercentOut = 0.0;
        return true;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(gpuPerfQueryHandle_);
    if (::PdhCollectQueryData(kQueryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(gpuCounterHandle_),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        nullptr);
    if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
    {
        gpuUsage3DPercent_ = 0.0;
        gpuUsageCopyPercent_ = 0.0;
        gpuUsageVideoEncodePercent_ = 0.0;
        gpuUsageVideoDecodePercent_ = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    std::vector<unsigned char> rawBuffer(bufferSize);
    auto* itemPtr = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
    queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(gpuCounterHandle_),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        itemPtr);
    if (queryStatus != ERROR_SUCCESS)
    {
        gpuUsage3DPercent_ = 0.0;
        gpuUsageCopyPercent_ = 0.0;
        gpuUsageVideoEncodePercent_ = 0.0;
        gpuUsageVideoDecodePercent_ = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    double usage3DPercent = 0.0;
    double usageCopyPercent = 0.0;
    double usageVideoEncodePercent = 0.0;
    double usageVideoDecodePercent = 0.0;
    double peakUsage = 0.0;
    for (DWORD indexValue = 0; indexValue < itemCount; ++indexValue)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPtr[indexValue];
        if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        const double kEngineUsagePercent = qBound(0.0, itemValue.FmtValue.doubleValue, 100.0);
        const QString kEngineNameText = QString::fromWCharArray(
            itemValue.szName != nullptr ? itemValue.szName : L"");
        const QString kEngineKeyText = resolveGpuEngineKeyFromCounter(kEngineNameText);
        if (kEngineKeyText == QStringLiteral("3d"))
        {
            usage3DPercent = std::max(usage3DPercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("copy"))
        {
            usageCopyPercent = std::max(usageCopyPercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("video_encode"))
        {
            usageVideoEncodePercent = std::max(usageVideoEncodePercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("video_decode"))
        {
            usageVideoDecodePercent = std::max(usageVideoDecodePercent, kEngineUsagePercent);
        }

        peakUsage = std::max(peakUsage, kEngineUsagePercent);
    }

    gpuUsage3DPercent_ = usage3DPercent;
    gpuUsageCopyPercent_ = usageCopyPercent;
    gpuUsageVideoEncodePercent_ = usageVideoEncodePercent;
    gpuUsageVideoDecodePercent_ = usageVideoDecodePercent;
    *gpuUsagePercentOut = qBound(0.0, peakUsage, 100.0);
    sampleGpuMemoryInfoByDxgi();
    return true;
}

bool HudPerformancePanel::sampleGpuMemoryInfoByDxgi()
{
    IDXGIFactory6* factoryPointer = nullptr;
    const HRESULT kCreateFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
    if (FAILED(kCreateFactoryStatus) || factoryPointer == nullptr)
    {
        return false;
    }

    bool querySuccess = false;
    for (UINT adapterIndex = 0;; ++adapterIndex)
    {
        IDXGIAdapter1* adapterPointer = nullptr;
        const HRESULT kEnumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
        if (kEnumStatus == DXGI_ERROR_NOT_FOUND)
        {
            break;
        }
        if (FAILED(kEnumStatus) || adapterPointer == nullptr)
        {
            continue;
        }

        DXGI_ADAPTER_DESC1 adapterDesc{};
        adapterPointer->GetDesc1(&adapterDesc);
        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
        {
            adapterPointer->Release();
            continue;
        }

        IDXGIAdapter3* adapter3Pointer = nullptr;
        const HRESULT kQueryInterfaceStatus = adapterPointer->QueryInterface(IID_PPV_ARGS(&adapter3Pointer));
        if (SUCCEEDED(kQueryInterfaceStatus) && adapter3Pointer != nullptr)
        {
            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
            const HRESULT kLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                &localMemoryInfo);
            const HRESULT kNonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                &nonLocalMemoryInfo);
            if (SUCCEEDED(kLocalStatus) && SUCCEEDED(kNonLocalStatus))
            {
                gpuDedicatedUsedGiB_ = static_cast<double>(localMemoryInfo.CurrentUsage) / kOneGiBInBytes;
                gpuDedicatedBudgetGiB_ = static_cast<double>(localMemoryInfo.Budget) / kOneGiBInBytes;
                gpuSharedUsedGiB_ = static_cast<double>(nonLocalMemoryInfo.CurrentUsage) / kOneGiBInBytes;
                gpuSharedBudgetGiB_ = static_cast<double>(nonLocalMemoryInfo.Budget) / kOneGiBInBytes;

                if (gpuSharedBudgetGiB_ <= 0.0)
                {
                    MEMORYSTATUSEX memoryStatus{};
                    memoryStatus.dwLength = sizeof(memoryStatus);
                    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                    {
                        const double kTotalMemoryGiB =
                            static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
                        gpuSharedBudgetGiB_ = std::max(0.5, kTotalMemoryGiB * 0.5);
                    }
                }

                const QString kAdapterNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                if (!kAdapterNameText.isEmpty())
                {
                    gpuAdapterNameText_ = kAdapterNameText;
                }
                querySuccess = true;
            }
            adapter3Pointer->Release();
        }

        adapterPointer->Release();
        if (querySuccess)
        {
            break;
        }
    }

    factoryPointer->Release();
    return querySuccess;
}

bool HudPerformancePanel::sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const
{
    if (snapshotOut == nullptr)
    {
        return false;
    }

    PERFORMANCE_INFORMATION perfInfo{};
    perfInfo.cb = sizeof(perfInfo);
    if (::GetPerformanceInfo(&perfInfo, sizeof(perfInfo)) == FALSE)
    {
        return false;
    }

    const std::uint64_t kPageSizeBytes = static_cast<std::uint64_t>(perfInfo.PageSize);
    snapshotOut->processCount = static_cast<std::uint32_t>(perfInfo.ProcessCount);
    snapshotOut->threadCount = static_cast<std::uint32_t>(perfInfo.ThreadCount);
    snapshotOut->handleCount = static_cast<std::uint32_t>(perfInfo.HandleCount);
    snapshotOut->commitTotalBytes = static_cast<std::uint64_t>(perfInfo.CommitTotal) * kPageSizeBytes;
    snapshotOut->commitLimitBytes = static_cast<std::uint64_t>(perfInfo.CommitLimit) * kPageSizeBytes;
    snapshotOut->cachedBytes = static_cast<std::uint64_t>(perfInfo.SystemCache) * kPageSizeBytes;
    snapshotOut->pagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelPaged) * kPageSizeBytes;
    snapshotOut->nonPagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelNonpaged) * kPageSizeBytes;
    return true;
}

void HudPerformancePanel::updateView(
    const std::vector<double>& coreUsageList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double kUsageValue : coreUsageList)
        {
            averageCpuUsage += kUsageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    if (cpuSummaryLabel_ != nullptr)
    {
        cpuSummaryLabel_->setText(
            QStringLiteral("CPU total: %1%    Memory: %2%    Logical processors: %3")
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(memoryUsagePercent, 0, 'f', 1)
            .arg(coreUsageList.size()));
    }
    if (cpuModelLabel_ != nullptr && !cpuModelText_.isEmpty())
    {
        cpuModelLabel_->setText(cpuModelText_);
    }

    const bool kCpuPageVisible =
        (detailStack_ != nullptr && detailStack_->currentWidget() == cpuPage_);
    if (kCpuPageVisible)
    {
        const int kChartCount = std::min(
            static_cast<int>(coreChartEntries_.size()),
            static_cast<int>(coreUsageList.size()));
        for (int indexValue = 0; indexValue < kChartCount; ++indexValue)
        {
            CoreChartEntry& chartEntry = coreChartEntries_[static_cast<std::size_t>(indexValue)];
            const double kUsageValue = coreUsageList[static_cast<std::size_t>(indexValue)];
            if (chartEntry.titleLabel != nullptr)
            {
                const QString kTitleText = QStringLiteral("CPU %1  %2%")
                    .arg(indexValue, 2, 10, QLatin1Char('0'))
                    .arg(kUsageValue, 5, 'f', 1, QLatin1Char(' '));
                if (chartEntry.titleLabel->text() != kTitleText)
                {
                    chartEntry.titleLabel->setText(kTitleText);
                }
            }
            appendCoreSeriesPoint(chartEntry, kUsageValue);
        }
    }

    if (memorySummaryLabel_ != nullptr)
    {
        memorySummaryLabel_->setText(
            QStringLiteral("Current memory load: %1%").arg(memoryUsagePercent, 0, 'f', 1));
    }
    appendGeneralSeriesPoint(
        memoryLineSeries_,
        memoryAxisX_,
        memoryAxisY_,
        memoryUsagePercent,
        0.0);

    if (diskSummaryLabel_ != nullptr)
    {
        diskSummaryLabel_->setText(
            QStringLiteral("Read: %1    Write: %2")
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
    }
    appendGeneralSeriesPoint(diskReadLineSeries_, diskAxisX_, diskAxisY_, diskReadBytesPerSec, 0.0);
    appendGeneralSeriesPoint(diskWriteLineSeries_, diskAxisX_, diskAxisY_, diskWriteBytesPerSec, 0.0);

    if (networkSummaryLabel_ != nullptr)
    {
        networkSummaryLabel_->setText(
            QStringLiteral("Receive: %1    Send: %2")
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec)));
    }
    appendGeneralSeriesPoint(networkRxLineSeries_, networkAxisX_, networkAxisY_, networkRxBytesPerSec, 0.0);
    appendGeneralSeriesPoint(networkTxLineSeries_, networkAxisX_, networkAxisY_, networkTxBytesPerSec, 0.0);

    if (gpuSummaryLabel_ != nullptr)
    {
        gpuSummaryLabel_->setText(
            QStringLiteral("GPU: %1%    3D: %2%    Copy: %3%")
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(gpuUsage3DPercent_, 0, 'f', 1)
            .arg(gpuUsageCopyPercent_, 0, 'f', 1));
    }

    for (GpuEngineChartEntry& chartEntry : gpuEngineCharts_)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = gpuUsage3DPercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = gpuUsageCopyPercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = gpuUsageVideoEncodePercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = gpuUsageVideoDecodePercent_;
        }

        appendGeneralSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendGeneralSeriesPoint(
        gpuDedicatedMemoryLineSeries_,
        gpuDedicatedMemoryAxisX_,
        gpuDedicatedMemoryAxisY_,
        gpuDedicatedUsedGiB_,
        0.0);
    appendGeneralSeriesPoint(
        gpuSharedMemoryLineSeries_,
        gpuSharedMemoryAxisX_,
        gpuSharedMemoryAxisY_,
        gpuSharedUsedGiB_,
        0.0);
    if (gpuDedicatedMemoryAxisY_ != nullptr)
    {
        const double kDedicatedUpperGiB = std::max(
            0.5,
            (gpuDedicatedBudgetGiB_ > 0.0 ? gpuDedicatedBudgetGiB_ : gpuDedicatedMemoryGiB_));
        gpuDedicatedMemoryAxisY_->setRange(0.0, kDedicatedUpperGiB);
    }
    if (gpuSharedMemoryAxisY_ != nullptr)
    {
        const double kSharedUpperGiB = std::max(0.5, gpuSharedBudgetGiB_);
        gpuSharedMemoryAxisY_->setRange(0.0, kSharedUpperGiB);
    }

    updateSidebarCards(
        averageCpuUsage,
        memoryUsagePercent,
        lastTotalPhysBytes_,
        lastAvailPhysBytes_,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
}

void HudPerformancePanel::updateSidebarCards(
    const double cpuUsagePercent,
    const double memoryUsagePercent,
    const std::uint64_t totalPhysBytes,
    const std::uint64_t availPhysBytes,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (cpuNavCard_ != nullptr)
    {
        cpuNavCard_->setSubtitleText(
            QStringLiteral("%1%  %2 GHz")
            .arg(cpuUsagePercent, 0, 'f', 0)
            .arg(lastCpuSpeedGhz_, 0, 'f', 2));
        cpuNavCard_->appendSample(cpuUsagePercent);
    }

    if (memoryNavCard_ != nullptr && totalPhysBytes > 0)
    {
        const double kTotalGiB = static_cast<double>(totalPhysBytes) / kOneGiBInBytes;
        const double kUsedGiB =
            static_cast<double>(totalPhysBytes - availPhysBytes) / kOneGiBInBytes;
        memoryNavCard_->setSubtitleText(
            QStringLiteral("%1/%2 GB (%3%)")
            .arg(kUsedGiB, 0, 'f', 1)
            .arg(kTotalGiB, 0, 'f', 1)
            .arg(memoryUsagePercent, 0, 'f', 0));
        memoryNavCard_->appendSample(memoryUsagePercent);
    }

    if (diskNavCard_ != nullptr)
    {
        const double kTotalDiskBytesPerSec = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        diskNavAutoScaleBytesPerSec_ = std::max(
            kTotalDiskBytesPerSec + 1.0,
            diskNavAutoScaleBytesPerSec_ * 0.96);
        const double kDiskUsagePercent = qBound(
            0.0,
            kTotalDiskBytesPerSec / std::max(1.0, diskNavAutoScaleBytesPerSec_) * 100.0,
            100.0);
        diskNavCard_->setSubtitleText(
            QStringLiteral("R %1 / W %2")
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
        diskNavCard_->appendSample(kDiskUsagePercent);
    }

    if (networkNavCard_ != nullptr)
    {
        const double kTotalNetworkBytesPerSec = std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec);
        networkNavAutoScaleBytesPerSec_ = std::max(
            kTotalNetworkBytesPerSec + 1.0,
            networkNavAutoScaleBytesPerSec_ * 0.96);
        const double kNetworkUsagePercent = qBound(
            0.0,
            kTotalNetworkBytesPerSec / std::max(1.0, networkNavAutoScaleBytesPerSec_) * 100.0,
            100.0);
        networkNavCard_->setSubtitleText(
            QStringLiteral("S %1 / R %2")
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec)));
        networkNavCard_->appendSample(kNetworkUsagePercent);
    }

    if (gpuNavCard_ != nullptr)
    {
        gpuNavCard_->setSubtitleText(
            QStringLiteral("%1%  %2/%3 GB")
            .arg(gpuUsagePercent, 0, 'f', 0)
            .arg(gpuDedicatedUsedGiB_, 0, 'f', 1)
            .arg((gpuDedicatedBudgetGiB_ > 0.0 ? gpuDedicatedBudgetGiB_ : gpuDedicatedMemoryGiB_), 0, 'f', 1));
        gpuNavCard_->appendSample(gpuUsagePercent);
    }
}

void HudPerformancePanel::updateTaskManagerDetailLabels(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent,
    const SystemPerformanceSnapshot* const systemPerfSnapshotPointer,
    const bool systemPerfOk)
{
    Q_UNUSED(memoryUsagePercent);

    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double kUsageValue : coreUsageList)
        {
            averageCpuUsage += kUsageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    double currentMhzSum = 0.0;
    double maxMhzSum = 0.0;
    int cpuPowerCount = 0;
    for (const CpuPowerSnapshot& snapshot : powerInfoList)
    {
        if (snapshot.currentMhz > 0)
        {
            currentMhzSum += static_cast<double>(snapshot.currentMhz);
        }
        if (snapshot.maxMhz > 0)
        {
            maxMhzSum += static_cast<double>(snapshot.maxMhz);
        }
        ++cpuPowerCount;
    }
    const double kCurrentCpuGhz = cpuPowerCount > 0
        ? (currentMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    const double kBaseCpuGhz = cpuPowerCount > 0
        ? (maxMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    lastCpuSpeedGhz_ = kCurrentCpuGhz;

    const std::uint64_t kUptimeSeconds = static_cast<std::uint64_t>(::GetTickCount64() / 1000ULL);

    if (cpuPrimaryDetailLabel_ != nullptr)
    {
        cpuPrimaryDetailLabel_->setText(
            QStringLiteral(
                "Utilization: %1%\n"
                "Speed: %2 GHz\n"
                "Processes: %3\n"
                "Threads: %4\n"
                "Handles: %5\n"
                "Up time: %6")
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(kCurrentCpuGhz, 0, 'f', 2)
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->processCount) : QStringLiteral("N/A"))
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->threadCount) : QStringLiteral("N/A"))
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->handleCount) : QStringLiteral("N/A"))
            .arg(formatDurationText(kUptimeSeconds)));
    }

    if (cpuSecondaryDetailLabel_ != nullptr)
    {
        cpuSecondaryDetailLabel_->setText(
            QStringLiteral(
                "Base speed: %1 GHz\n"
                "Sockets: %2\n"
                "Cores: %3\n"
                "Logical processors: %4\n"
                "L1 cache: %5\n"
                "L2 cache: %6\n"
                "L3 cache: %7")
            .arg(kBaseCpuGhz, 0, 'f', 2)
            .arg(cpuPackageCount_ > 0 ? QString::number(cpuPackageCount_) : QStringLiteral("N/A"))
            .arg(cpuPhysicalCoreCount_ > 0 ? QString::number(cpuPhysicalCoreCount_) : QStringLiteral("N/A"))
            .arg(cpuLogicalCoreCount_ > 0 ? QString::number(cpuLogicalCoreCount_) : QStringLiteral("N/A"))
            .arg(cpuL1CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL1CacheBytes_)) : QStringLiteral("N/A"))
            .arg(cpuL2CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL2CacheBytes_)) : QStringLiteral("N/A"))
            .arg(cpuL3CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL3CacheBytes_)) : QStringLiteral("N/A")));
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool kMemoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
    if (kMemoryStatusOk)
    {
        const double kTotalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
        const double kAvailableGiB = static_cast<double>(memoryStatus.ullAvailPhys) / kOneGiBInBytes;
        const double kUsedGiB = kTotalGiB - kAvailableGiB;
        if (memoryCapacityLabel_ != nullptr)
        {
            memoryCapacityLabel_->setText(QStringLiteral("%1 GB").arg(kTotalGiB, 0, 'f', 1));
        }
        if (memoryPrimaryDetailLabel_ != nullptr)
        {
            memoryPrimaryDetailLabel_->setText(
                QStringLiteral(
                    "In use: %1 GB\n"
                    "Available: %2 GB\n"
                    "Committed: %3 / %4\n"
                    "Cached: %5\n"
                    "Paged pool: %6\n"
                    "Non-paged pool: %7")
                .arg(kUsedGiB, 0, 'f', 1)
                .arg(kAvailableGiB, 0, 'f', 1)
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->commitTotalBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->commitLimitBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->cachedBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->pagedPoolBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->nonPagedPoolBytes)) : QStringLiteral("N/A")));
        }
    }

    if (memorySecondaryDetailLabel_ != nullptr)
    {
        ULONGLONG installedMemoryKb = 0;
        ::GetPhysicallyInstalledSystemMemory(&installedMemoryKb);
        const double kInstalledBytes = static_cast<double>(installedMemoryKb) * 1024.0;
        const double kReservedBytes = kMemoryStatusOk
            ? std::max(0.0, kInstalledBytes - static_cast<double>(memoryStatus.ullTotalPhys))
            : 0.0;
        memorySecondaryDetailLabel_->setText(
            QStringLiteral(
                "Speed: %1 MHz\n"
                "Slots used: %2/%3\n"
                "Form factor: %4\n"
                "Hardware reserved: %5")
            .arg(memorySpeedMhz_ > 0 ? QString::number(memorySpeedMhz_) : QStringLiteral("N/A"))
            .arg(memorySlotUsed_ > 0 ? QString::number(memorySlotUsed_) : QStringLiteral("N/A"))
            .arg(memorySlotTotal_ > 0 ? QString::number(memorySlotTotal_) : QStringLiteral("N/A"))
            .arg(memoryFormFactorText_.isEmpty() ? QStringLiteral("N/A") : memoryFormFactorText_)
            .arg(bytesToReadableText(kReservedBytes)));
    }

    if (diskDetailLabel_ != nullptr)
    {
        const double kDiskTotalRate = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        const double kDiskApproxPercent = qBound(
            0.0,
            kDiskTotalRate / std::max(1.0, diskNavAutoScaleBytesPerSec_) * 100.0,
            100.0);
        diskDetailLabel_->setText(
            QStringLiteral(
                "Active time (approx): %1%\n"
                "Read speed: %2\n"
                "Write speed: %3\n"
                "System volume: %4\n"
                "Total: %5\n"
                "Free: %6")
            .arg(kDiskApproxPercent, 0, 'f', 1)
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec))
            .arg(systemVolumeText_.isEmpty() ? QStringLiteral("N/A") : systemVolumeText_)
            .arg(systemVolumeTotalBytes_ > 0
                ? bytesToReadableText(static_cast<double>(systemVolumeTotalBytes_))
                : QStringLiteral("N/A"))
            .arg(systemVolumeFreeBytes_ > 0
                ? bytesToReadableText(static_cast<double>(systemVolumeFreeBytes_))
                : QStringLiteral("N/A")));
    }

    if (networkDetailLabel_ != nullptr)
    {
        const QString kAdapterText = primaryNetworkAdapterName_.isEmpty()
            ? QStringLiteral("N/A")
            : primaryNetworkAdapterName_;
        const double kLinkMbps = static_cast<double>(primaryNetworkLinkBitsPerSecond_) / (1000.0 * 1000.0);
        networkDetailLabel_->setText(
            QStringLiteral(
                "Adapter: %1\n"
                "Send: %2\n"
                "Receive: %3\n"
                "Link speed: %4 Mbps")
            .arg(kAdapterText)
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(kLinkMbps > 0.0 ? QString::number(kLinkMbps, 'f', 1) : QStringLiteral("N/A")));
    }

    if (gpuAdapterTitleLabel_ != nullptr)
    {
        gpuAdapterTitleLabel_->setText(
            gpuAdapterNameText_.isEmpty() ? QStringLiteral("N/A") : gpuAdapterNameText_);
    }
    if (gpuDedicatedMemoryChartView_ != nullptr && gpuDedicatedMemoryChartView_->chart() != nullptr)
    {
        gpuDedicatedMemoryChartView_->chart()->setTitle(
            QStringLiteral("Dedicated GPU memory  %1 / %2 GiB")
            .arg(gpuDedicatedUsedGiB_, 0, 'f', 2)
            .arg(gpuDedicatedBudgetGiB_ > 0.0 ? gpuDedicatedBudgetGiB_ : gpuDedicatedMemoryGiB_, 0, 'f', 2));
    }
    if (gpuSharedMemoryChartView_ != nullptr && gpuSharedMemoryChartView_->chart() != nullptr)
    {
        gpuSharedMemoryChartView_->chart()->setTitle(
            QStringLiteral("Shared GPU memory  %1 / %2 GiB")
            .arg(gpuSharedUsedGiB_, 0, 'f', 2)
            .arg(gpuSharedBudgetGiB_, 0, 'f', 2));
    }

    if (gpuDetailLabel_ != nullptr)
    {
        gpuDetailLabel_->setText(
            QStringLiteral(
                "Utilization: %1%\n"
                "3D: %2%   Copy: %3%   Video Encode: %4%   Video Decode: %5%\n"
                "Dedicated memory: %6 / %7 GiB\n"
                "Shared memory: %8 / %9 GiB\n"
                "Driver version: %10\n"
                "Driver date: %11\n"
                "PNP: %12")
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(gpuUsage3DPercent_, 0, 'f', 1)
            .arg(gpuUsageCopyPercent_, 0, 'f', 1)
            .arg(gpuUsageVideoEncodePercent_, 0, 'f', 1)
            .arg(gpuUsageVideoDecodePercent_, 0, 'f', 1)
            .arg(gpuDedicatedUsedGiB_, 0, 'f', 2)
            .arg((gpuDedicatedBudgetGiB_ > 0.0 ? gpuDedicatedBudgetGiB_ : gpuDedicatedMemoryGiB_), 0, 'f', 2)
            .arg(gpuSharedUsedGiB_, 0, 'f', 2)
            .arg(gpuSharedBudgetGiB_, 0, 'f', 2)
            .arg(gpuDriverVersionText_.isEmpty() ? QStringLiteral("N/A") : gpuDriverVersionText_)
            .arg(gpuDriverDateText_.isEmpty() ? QStringLiteral("N/A") : gpuDriverDateText_)
            .arg(gpuPnpDeviceIdText_.isEmpty() ? QStringLiteral("N/A") : gpuPnpDeviceIdText_));
    }
}

void HudPerformancePanel::appendCoreSeriesPoint(CoreChartEntry& chartEntry, const double usagePercent)
{
    auto* sparklineWidget = static_cast<CpuCoreSparklineWidget*>(chartEntry.chartWidget);
    if (sparklineWidget == nullptr)
    {
        return;
    }
    sparklineWidget->appendSample(usagePercent, historyLength_);
}

void HudPerformancePanel::appendGeneralSeriesPoint(
    QLineSeries* lineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double sampleValue,
    const double minAxisYValue)
{
    if (lineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    lineSeries->append(sampleCounter_, sampleValue);
    while (lineSeries->count() > historyLength_)
    {
        lineSeries->remove(0);
    }

    const QList<QPointF> kPointList = lineSeries->points();
    if (kPointList.isEmpty())
    {
        return;
    }

    const double kFirstX = kPointList.first().x();
    const double kLastX = kPointList.last().x();
    if (qFuzzyCompare(kFirstX, kLastX))
    {
        axisX->setRange(kFirstX - 1.0, kLastX + 1.0);
    }
    else
    {
        axisX->setRange(kFirstX, kLastX);
    }

    double maxYValue = minAxisYValue + 1.0;
    for (const QPointF& pointValue : kPointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

QString HudPerformancePanel::formatRateText(const double bytesPerSecondValue) const
{
    return bytesPerSecondToText(bytesPerSecondValue);
}

void HudPerformancePanel::requestAsyncStaticInfoRefresh()
{
    bool expectedFlag = false;
    if (!staticInfoRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QPointer<HudPerformancePanel> safeThis(this);
    std::thread([safeThis]()
    {
        const MemoryHardwareSummarySnapshot kMemorySummary = queryMemoryHardwareSummarySnapshot();
        const GpuHardwareSummarySnapshot kGpuSummary = queryGpuHardwareSummarySnapshot();

        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kMemorySummary, kGpuSummary]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->memorySpeedMhz_ = kMemorySummary.speedMhz;
                safeThis->memorySlotUsed_ = kMemorySummary.usedSlots;
                safeThis->memorySlotTotal_ = kMemorySummary.totalSlots;
                safeThis->memoryFormFactorText_ = kMemorySummary.formFactorText;
                safeThis->gpuAdapterNameText_ = kGpuSummary.adapterNameText;
                safeThis->gpuDriverVersionText_ = kGpuSummary.driverVersionText;
                safeThis->gpuDriverDateText_ = kGpuSummary.driverDateText;
                safeThis->gpuPnpDeviceIdText_ = kGpuSummary.pnpDeviceIdText;
                safeThis->gpuDedicatedMemoryGiB_ = kGpuSummary.dedicatedMemoryGiB;
                safeThis->staticInfoRefreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->staticInfoRefreshing_.store(false);
        }
    }).detach();
}

void HudPerformancePanel::requestAsyncSensorRefresh()
{
    bool expectedFlag = false;
    if (!sensorRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QPointer<HudPerformancePanel> safeThis(this);
    std::thread([safeThis]()
    {
        const QString kSensorText = QStringLiteral("%1|%2")
            .arg(queryCpuTemperatureText())
            .arg(queryCpuVoltageText());

        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kSensorText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->cachedSensorText_ = kSensorText;
                safeThis->sensorRefreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->sensorRefreshing_.store(false);
        }
    }).detach();
}

void HudPerformancePanel::refreshCpuTopologyStaticInfo()
{
    cpuModelText_ = queryCpuBrandTextByCpuid();

    DWORD requiredBytes = 0;
    ::GetLogicalProcessorInformationEx(RelationAll, nullptr, &requiredBytes);
    if (requiredBytes == 0)
    {
        cpuLogicalCoreCount_ = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    std::vector<unsigned char> buffer(requiredBytes);
    auto* infoPointer =
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationAll, infoPointer, &requiredBytes) == FALSE)
    {
        cpuLogicalCoreCount_ = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    int packageCount = 0;
    int physicalCoreCount = 0;
    int logicalCoreCount = 0;
    std::uint64_t l1Bytes = 0;
    std::uint64_t l2Bytes = 0;
    std::uint64_t l3Bytes = 0;

    DWORD offsetBytes = 0;
    while (offsetBytes < requiredBytes)
    {
        auto* entryPointer = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() + offsetBytes);
        if (entryPointer->Relationship == RelationProcessorPackage)
        {
            ++packageCount;
        }
        else if (entryPointer->Relationship == RelationProcessorCore)
        {
            ++physicalCoreCount;
            for (WORD groupIndex = 0; groupIndex < entryPointer->Processor.GroupCount; ++groupIndex)
            {
                logicalCoreCount += countBits(entryPointer->Processor.GroupMask[groupIndex].Mask);
            }
        }
        else if (entryPointer->Relationship == RelationCache)
        {
            if (entryPointer->Cache.Level == 1)
            {
                l1Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 2)
            {
                l2Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 3)
            {
                l3Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
        }

        if (entryPointer->Size == 0)
        {
            break;
        }
        offsetBytes += entryPointer->Size;
    }

    cpuPackageCount_ = std::max(1, packageCount);
    cpuPhysicalCoreCount_ = std::max(1, physicalCoreCount);
    cpuLogicalCoreCount_ = logicalCoreCount > 0
        ? logicalCoreCount
        : static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    cpuL1CacheBytes_ = l1Bytes;
    cpuL2CacheBytes_ = l2Bytes;
    cpuL3CacheBytes_ = l3Bytes;
}

void HudPerformancePanel::refreshSystemVolumeInfo()
{
    QString systemDrive = qEnvironmentVariable("SystemDrive");
    if (systemDrive.isEmpty())
    {
        systemDrive = QStringLiteral("C:");
    }

    QString rootPath = systemDrive;
    if (!rootPath.endsWith('\\'))
    {
        rootPath += QLatin1Char('\\');
    }

    ULARGE_INTEGER freeAvailableBytes{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (::GetDiskFreeSpaceExW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        &freeAvailableBytes,
        &totalBytes,
        &totalFreeBytes) == TRUE)
    {
        systemVolumeTotalBytes_ = static_cast<std::uint64_t>(totalBytes.QuadPart);
        systemVolumeFreeBytes_ = static_cast<std::uint64_t>(totalFreeBytes.QuadPart);
    }

    wchar_t volumeNameBuffer[MAX_PATH] = {};
    if (::GetVolumeInformationW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        volumeNameBuffer,
        MAX_PATH,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0) == TRUE)
    {
        const QString kVolumeNameText = QString::fromWCharArray(volumeNameBuffer).trimmed();
        if (!kVolumeNameText.isEmpty())
        {
            systemVolumeText_ = QStringLiteral("%1 (%2)").arg(kVolumeNameText, systemDrive);
            return;
        }
    }

    systemVolumeText_ = rootPath;
}

QString HudPerformancePanel::buildCpuSensorText(const bool forceRefresh)
{
    if (forceRefresh)
    {
        requestAsyncSensorRefresh();
    }

    if (!cachedSensorText_.isEmpty())
    {
        return cachedSensorText_;
    }
    return QStringLiteral("N/A|N/A");
}
