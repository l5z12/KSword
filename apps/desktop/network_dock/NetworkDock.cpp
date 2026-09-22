#include "NetworkDock.InternalCommon.h"
#include "HttpsProxyService.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QMessageBox>

// ============================================================
// NetworkDock.cpp
// Purpose:
// 1) Retains NetworkDock construction/destruction and background callback wiring;
// 2) Separate specific UI and business logic functions into independent .cpp files;
// 3) Replace the old .inc aggregate structure without changing functionality.
// ============================================================

NetworkDock::NetworkDock(QWidget* parent)
    : QWidget(parent)
{
    // Before any network page initialization and new proxy application, restore the proxy transaction left over from the previous crash or forced kill.
    bool recoveredPreviousProxy = false;
    QString recoveryErrorText;
    const bool kRecoveryOk = recoverPendingHttpsSystemProxyTransaction(
        &recoveredPreviousProxy,
        &recoveryErrorText);

    // Create the background service object: responsible for packet capture, PID mapping, and rate limiting logic.
    trafficService_ = std::make_unique<ks::network::TrafficMonitorService>();

    // initialize the UI and connection logic.
    initializeUi();
    initializeConnections();
    loadMonitorFilterConfigFromDefaultPath();

    if (recoveredPreviousProxy)
    {
        appendHttpsProxyLogLine(QStringLiteral(
            "检测到上次异常退出遗留的 HTTPS 系统代理，已自动恢复原配置。"));
        KLogEvent recoveryEvent;
        info << recoveryEvent
            << "[NetworkDock] 已从持久化事务恢复上次 HTTPS 系统代理配置。"
            << eol;
    }
    else if (!kRecoveryOk)
    {
        appendHttpsProxyLogLine(
            QStringLiteral("自动恢复上次 HTTPS 系统代理失败：%1")
                .arg(recoveryErrorText));
        KLogEvent recoveryEvent;
        warn << recoveryEvent
            << "[NetworkDock] 启动时恢复 HTTPS 系统代理失败："
            << recoveryErrorText
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS 系统代理恢复失败"),
            QStringLiteral(
                "检测到未完成的 HTTPS 代理恢复事务，但自动恢复失败：\n%1\n\n"
                "在恢复成功前将禁止再次应用 HTTPS 系统代理，以免覆盖原始配置。")
                .arg(recoveryErrorText));
    }

    // The 'Process Throttling' page is currently not exposed to users, so the dedicated polling refresh timer for this page is not created.
    // Handling logic:
    // - Input is empty: No user-visible rate-limiting page; no need to periodically fetch rule snapshots.
    // - Handling: Keep m_rateLimitRefreshTimer as nullptr.
    // - Return: Constructor continues initializing other network feature pages.

    // Packet batch flush timer:
    // - Periodically batch-consume the background queue from the UI thread.
    // - Avoid flooding the event loop with 'one invokeMethod per packet'.
    packetFlushTimer_ = new QTimer(this);
    packetFlushTimer_->setInterval(50);
    connect(packetFlushTimer_, &QTimer::timeout, this, [this]()
        {
            flushPendingPacketsToUi();
        });
    packetFlushTimer_->start();

    // R0 traffic mode polling:
    // - Only queries new WFP IPv4/IPv6 per-packet records by sequence cursor when running in R0 mode.
    // - Query failures seamlessly fall back to R3 within refreshR0TrafficSnapshotAsync;
    // - The standalone 'Connection Management' page has been removed; its old poller is no longer created.
    r0TrafficRefreshTimer_ = new QTimer(this);
    r0TrafficRefreshTimer_->setInterval(250);
    connect(r0TrafficRefreshTimer_, &QTimer::timeout, this, [this]()
        {
            if (!monitorRunning_ || monitorSource_ != TrafficMonitorSource::kR0)
            {
                return;
            }
            refreshR0TrafficSnapshotAsync(monitorGeneration_.load(), false);
        });

    // Multi-threaded download refresh timer:
    // - Periodically refreshes the task table, segmented table, and total progress bar.
    // - Even if not currently on the download page, maintain refresh as long as running tasks exist.
    multiDownloadRefreshTimer_ = new QTimer(this);
    multiDownloadRefreshTimer_->setInterval(180);
    connect(multiDownloadRefreshTimer_, &QTimer::timeout, this, [this]()
        {
            if (sideTabWidget_ == nullptr || sideTabWidget_->currentWidget() != multiThreadDownloadPage_)
            {
                return;
            }
            refreshMultiThreadDownloadUi();
        });
    multiDownloadRefreshTimer_->start();

    // Forward background thread callbacks to the UI thread to ensure thread-safe table operations.
    trafficService_->setPacketCallback([this](const ks::network::PacketRecord& packetRecord)
        {
            // The packet capture thread performs only lightweight 'enqueue' actions and does not directly touch UI controls.
            std::lock_guard<std::mutex> guard(pendingPacketMutex_);
            if (pendingPacketQueue_.size() >= kMaxPendingPacketQueueCount)
            {
                // When the queue is full, discard the oldest packet to maintain system availability.
                pendingPacketQueue_.pop_front();
                ++droppedPacketCount_;
            }
            pendingPacketQueue_.push_back(packetRecord);
        });

    trafficService_->setStatusCallback([this](const std::string& statusText)
        {
            QMetaObject::invokeMethod(this, [this, statusText]()
                {
                    onStatusMessageArrived(statusText);
                }, Qt::QueuedConnection);
        });

    trafficService_->setRateLimitActionCallback([this](const ks::network::RateLimitActionEvent& actionEvent)
        {
            QMetaObject::invokeMethod(this, [this, actionEvent]()
                {
                    onRateLimitActionArrived(actionEvent);
                }, Qt::QueuedConnection);
        });

    // Initialization log.
    KLogEvent initializeEvent;
    info << initializeEvent << "[NetworkDock] 网络面板初始化完成。" << eol;

}

NetworkDock::~NetworkDock()
{
    monitorGeneration_.fetch_add(1);
    monitorSource_ = TrafficMonitorSource::kStopped;
    // Destruction must first disable the R0 packet-level data plane; stopping polling alone leaves the kernel copying all traffic.
    {
        const ksword::ark::DriverClient kDriverClient;
        (void)kDriverClient.controlNetworkTrafficCapture(false);
    }
    if (r0TrafficRefreshTimer_ != nullptr)
    {
        r0TrafficRefreshTimer_->stop();
    }

    // First terminate the ICMP scan to prevent background workers from accessing NetworkDock members after destruction.
    cancelAndWaitForAliveHostScan();

    // Requests cancellation of all download tasks before destruction to prevent long-running downloads after the window is released.
    {
        std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
        for (const std::shared_ptr<MultiThreadDownloadTaskState>& taskState : multiDownloadTaskList_)
        {
            if (taskState != nullptr)
            {
                taskState->canceled.store(true);
                taskState->cancelRequested.store(true);
                taskState->pauseRequested.store(false);
            }
        }
    }

    // If an async stop thread is running, wait synchronously during destruction to ensure the service object remains valid.
    if (monitorStopThread_ != nullptr && monitorStopThread_->joinable())
    {
        monitorStopThread_->join();
    }
    monitorStopThread_.reset();

    // Proactively stop background threads before window destruction to prevent dangling callbacks after destruction.
    if (trafficService_ != nullptr)
    {
        trafficService_->stopCapture();
    }
    if (httpsProxyService_ != nullptr)
    {
        httpsProxyService_->stop();
    }
    if (httpsSystemProxySnapshotCaptured_)
    {
        QString restoreErrorText;
        if (!restoreHttpsSystemProxySnapshot(&restoreErrorText))
        {
            KLogEvent restoreEvent;
            warn << restoreEvent << "[NetworkDock] HTTPS 系统代理恢复失败：" << restoreErrorText << eol;
        }
    }

    KLogEvent destroyEvent;
    info << destroyEvent << "[NetworkDock] 网络面板已析构，抓包线程已停止。" << eol;
}

void NetworkDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (httpsProxyServiceInitialized_)
    {
        return;
    }

    httpsProxyServiceInitialized_ = true;
    httpsProxyService_ = std::make_unique<ks::network::HttpsMitmProxyService>();
    if (httpsProxyService_ != nullptr)
    {
        httpsProxyService_->setParsedCallback([this](const ks::network::HttpsProxyParsedEntry& parsedEntry)
            {
                QMetaObject::invokeMethod(this, [this, parsedEntry]()
                    {
                        onHttpsProxyParsedEntryArrived(parsedEntry);
                    }, Qt::QueuedConnection);
            });
        httpsProxyService_->setStatusCallback([this](const QString& statusText)
            {
                QMetaObject::invokeMethod(this, [this, statusText]()
                    {
                        appendHttpsProxyLogLine(statusText);
                        if (!statusText.isEmpty())
                        {
                            updateHttpsProxyStatusLabel(statusText);
                        }
                    }, Qt::QueuedConnection);
            });
    }
}
