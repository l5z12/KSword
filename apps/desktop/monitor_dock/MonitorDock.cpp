#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

MonitorDock::MonitorDock(QWidget* parent)
    : QWidget(parent)
{
    KLogEvent event;
    info << event << "[MonitorDock] 构造开始。" << eol;

    initializeUi();
    initializeConnections();

    // The top four-panel performance graphs have been migrated to the "Monitor Panel" Dock
    // (MonitorPanelWidget); MonitorDock now only handles WMI/ETW real-time monitoring logic.

    // WMI event table refresh throttling: background threads queue events first, and the main thread batches them into the UI every 100ms to prevent event storms from freezing the UI.
    wmiUiUpdateTimer_ = new QTimer(this);
    wmiUiUpdateTimer_->setInterval(100);
    connect(wmiUiUpdateTimer_, &QTimer::timeout, this, [this]() {
        flushWmiPendingRows();
    });

    KLogEvent finishEvent;
    info << finishEvent << "[MonitorDock] 构造完成。" << eol;
}

void MonitorDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    // On first display, trigger discovery tasks only for the current sub-page:
    // - When defaulting to 'Process-Oriented', do not trigger WMI/ETW enumeration;
    // - Refresh in the background only when the user switches to the WMI/ETW page to avoid concurrent startup of four discovery paths after the first click on MonitorDock.
    QTimer::singleShot(80, this, [this]()
    {
        triggerDeferredDiscoveryForCurrentTab();
    });
}

bool MonitorDock::event(QEvent* eventPointer)
{
    // Theme switching updates the global palette; since the collapsible panel uses dynamic stylesheets, re-assembly is required when the event arrives.
    const bool kHandled = QWidget::event(eventPointer);
    if (eventPointer != nullptr
        && (eventPointer->type() == QEvent::PaletteChange
            || eventPointer->type() == QEvent::ApplicationPaletteChange
            || eventPointer->type() == QEvent::StyleChange))
    {
        refreshIndependentCollapseTheme(wmiPage_);
        refreshIndependentCollapseTheme(etwPage_);
        updateEtwCollapseHeight();
    }
    return kHandled;
}

void MonitorDock::ensureDirectKernelCallTabInitialized()
{
    if (directKernelCallWidget_ != nullptr || directKernelCallHostPage_ == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(directKernelCallHostPage_->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(directKernelCallHostPage_);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // Clean up placeholder controls: Direct kernel call pages resolve syscall mappings at construction time; creating them on demand avoids the need for MonitorDock's first click.
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    directKernelCallWidget_ = new DirectKernelCallMonitorWidget(directKernelCallHostPage_);
    hostLayout->addWidget(directKernelCallWidget_, 1);
}

void MonitorDock::ensureKernelCallbackTabInitialized()
{
    if (kernelCallbackWidget_ != nullptr || kernelCallbackHostPage_ == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(kernelCallbackHostPage_->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(kernelCallbackHostPage_);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        if (QWidget* itemWidget = itemPointer->widget(); itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    kernelCallbackWidget_ = new KernelCallbackMonitorWidget(kernelCallbackHostPage_);
    hostLayout->addWidget(kernelCallbackWidget_, 1);
}

void MonitorDock::ensureWinApiTabInitialized()
{
    if (winApiPage_ == nullptr)
    {
        return;
    }

    if (winApiWidget_ == nullptr)
    {
        QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(winApiPage_->layout());
        if (hostLayout == nullptr)
        {
            hostLayout = new QVBoxLayout(winApiPage_);
            hostLayout->setContentsMargins(0, 0, 0, 0);
            hostLayout->setSpacing(0);
        }

        winApiWidget_ = new WinAPIDock(winApiPage_);
        hostLayout->addWidget(winApiWidget_, 1);
    }

    winApiWidget_->notifyPageActivated();
}

void MonitorDock::triggerDeferredDiscoveryForCurrentTab()
{
    if (sideTabWidget_ == nullptr)
    {
        return;
    }

    QWidget* currentPage = sideTabWidget_->currentWidget();
    if (currentPage == wmiPage_ && !wmiInitialDiscoveryDone_)
    {
        wmiInitialDiscoveryDone_ = true;
        refreshWmiProvidersAsync();
        refreshWmiEventClassesAsync();
        return;
    }

    if (currentPage == etwPage_ && !etwInitialDiscoveryDone_)
    {
        etwInitialDiscoveryDone_ = true;
        refreshEtwProvidersAsync();
        refreshEtwSessionsAsync();
        return;
    }

    if (currentPage == arkRiskCenterPage_ && !arkRiskCenterInitialDiscoveryDone_)
    {
        arkRiskCenterInitialDiscoveryDone_ = true;
        refreshArkRiskCenterAsync();
    }
}

void MonitorDock::activateMonitorTab(const QString& tabKey)
{
    if (sideTabWidget_ == nullptr)
    {
        return;
    }

    const QString kNormalizedKey = tabKey.trimmed().toLower();
    if (kNormalizedKey == QStringLiteral("kernel-callback")
        || kNormalizedKey == QStringLiteral("kernelcallback")
        || kNormalizedKey == QStringLiteral("callback"))
    {
        if (kernelCallbackHostPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(kernelCallbackHostPage_);
            QTimer::singleShot(0, this, [this]()
            {
                ensureKernelCallbackTabInitialized();
            });
        }
        return;
    }
    if (kNormalizedKey == QStringLiteral("direct-kernel-call")
        || kNormalizedKey == QStringLiteral("directkernelcall")
        || kNormalizedKey == QStringLiteral("syscall"))
    {
        if (directKernelCallHostPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(directKernelCallHostPage_);
            // Programmatic jumps also maintain 'switch page first, then load' to avoid blocking the main window when the default page is configured as a syscall.
            QTimer::singleShot(0, this, [this]()
            {
                ensureDirectKernelCallTabInitialized();
            });
        }
        return;
    }
    if (kNormalizedKey == QStringLiteral("winapi"))
    {
        ensureWinApiTabInitialized();
        if (winApiPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(winApiPage_);
        }
        return;
    }
    if (kNormalizedKey == QStringLiteral("wmi"))
    {
        if (wmiPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(wmiPage_);
        }
        return;
    }
    if (kNormalizedKey == QStringLiteral("etw"))
    {
        if (etwPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(etwPage_);
        }
        return;
    }
    if (kNormalizedKey == QStringLiteral("ark-risk") ||
        kNormalizedKey == QStringLiteral("risk") ||
        kNormalizedKey == QStringLiteral("ark-risk-center"))
    {
        if (arkRiskCenterPage_ != nullptr)
        {
            sideTabWidget_->setCurrentWidget(arkRiskCenterPage_);
        }
        return;
    }

    if (processTraceWidget_ != nullptr)
    {
        sideTabWidget_->setCurrentWidget(processTraceWidget_);
    }
}

MonitorDock::~MonitorDock()
{
    // During destruction, must synchronously wait for threads to exit to prevent background threads from accessing members after the object is released.
    stopWmiSubscriptionInternal(true);
    stopEtwCaptureInternal(true);
    cancelAndWaitEtwArchiveBackgroundTasks();

    if (wmiUiUpdateTimer_ != nullptr)
    {
        wmiUiUpdateTimer_->stop();
    }

    if (etwUiUpdateTimer_ != nullptr)
    {
        etwUiUpdateTimer_->stop();
    }

    if (perfUpdateTimer_ != nullptr)
    {
        perfUpdateTimer_->stop();
    }

    // Release the PDH query handle during destruction to prevent system counter handle leaks.
    if (diskPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_));
        diskPerfQueryHandle_ = nullptr;
        diskReadCounterHandle_ = nullptr;
        diskWriteCounterHandle_ = nullptr;
    }
}
