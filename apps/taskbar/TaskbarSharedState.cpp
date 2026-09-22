#include "TaskbarSharedState.h"

#include <QDebug>
#include <QMetaType>
#include <algorithm>
#include <chrono>

TaskbarSharedState::TaskbarSharedState(QObject* parent)
    : QObject(parent),
      analyzer_(std::make_unique<AudioSpectrumAnalyzer>()),
      started_(false),
      audioCaptureStarted_(false),
      cpuWorkerRunning_(false),
      networkWorkerRunning_(false),
      uploadBytesPerSecond_(0),
      downloadBytesPerSecond_(0)
{
    // When spectrum data is queued for cross-thread delivery, the meta type must be registered to prevent the audio sampling thread from directly connecting to the UI.
    qRegisterMetaType<QVector<float>>("QVector<float>");

    // The audio analyzer is created only once; multiple Taskbar windows share the same spectrum data broadcast.
    connect(
        analyzer_.get(),
        &AudioSpectrumAnalyzer::spectrumDataReady,
        this,
        &TaskbarSharedState::spectrumDataReady,
        Qt::QueuedConnection
    );
}

TaskbarSharedState::~TaskbarSharedState()
{
    // Stop sampling uniformly during destruction to ensure no background threads are left behind when multiple windows close or auto-restart.
    stop();
}

void TaskbarSharedState::start()
{
    // start can be called repeatedly by main or subsequent recovery logic, but actual sampling occurs only once.
    if (started_) {
        return;
    }
    started_ = true;

    // Audio failure does not prevent the CPU, network, and multi-monitor toolbar windows from continuing to work.
    if (analyzer_ && analyzer_->initialize()) {
        analyzer_->startCapture();
        audioCaptureStarted_ = true;
    }
    else {
        qWarning() << "Taskbar shared audio analyzer failed to initialize.";
    }

    startCpuWorker();
    startNetworkWorker();
}

void TaskbarSharedState::stop()
{
    // stop must be idempotent, as window closure, process restart, and destruction can all trigger it.
    if (!started_) {
        return;
    }
    started_ = false;

    stopCpuWorker();
    stopNetworkWorker();

    if (audioCaptureStarted_ && analyzer_) {
        analyzer_->stopCapture();
        audioCaptureStarted_ = false;
    }
}

QVector<int> TaskbarSharedState::cpuUsageSnapshot() const
{
    // Returns a copy, allowing the caller to safely read and render it on the UI thread.
    std::lock_guard<std::mutex> lock(cpuUsageMutex_);
    return cpuUsage_;
}

std::uint64_t TaskbarSharedState::uploadSpeedBytesPerSecond() const
{
    // Atomic read ensures no data race between the network sampling thread and multiple UI windows.
    return uploadBytesPerSecond_.load(std::memory_order_acquire);
}

std::uint64_t TaskbarSharedState::downloadSpeedBytesPerSecond() const
{
    // Atomic read ensures no data race between the network sampling thread and multiple UI windows.
    return downloadBytesPerSecond_.load(std::memory_order_acquire);
}

void TaskbarSharedState::startCpuWorker()
{
    // Prevents duplicate startup of the CPU sampling thread.
    if (cpuWorkerRunning_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    cpuWorkerThread_ = std::thread([this]() {
        while (cpuWorkerRunning_.load(std::memory_order_acquire)) {
            const std::vector<int> kSampledUsage = getCPUCoreUsage();
            QVector<int> nextUsage;
            nextUsage.reserve(static_cast<int>(kSampledUsage.size()));
            for (int usage : kSampledUsage) {
                nextUsage.append(std::clamp(usage, 0, 100));
            }

            {
                std::lock_guard<std::mutex> lock(cpuUsageMutex_);
                cpuUsage_ = nextUsage;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });
}

void TaskbarSharedState::stopCpuWorker()
{
    // Notify the thread to exit first, then join, to prevent threads from accessing freed objects during process restart.
    cpuWorkerRunning_.store(false, std::memory_order_release);
    if (cpuWorkerThread_.joinable()) {
        cpuWorkerThread_.join();
    }
}

void TaskbarSharedState::startNetworkWorker()
{
    // Prevent duplicate startup of the network sampling thread.
    if (networkWorkerRunning_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    networkWorkerThread_ = std::thread([this]() {
        while (networkWorkerRunning_.load(std::memory_order_acquire)) {
            const NetworkSpeedRate kRate = getNetworkSpeedRate();

            uploadBytesPerSecond_.store(
                kRate.uploadBytesPerSecond,
                std::memory_order_release
            );
            downloadBytesPerSecond_.store(
                kRate.downloadBytesPerSecond,
                std::memory_order_release
            );

            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    });
}

void TaskbarSharedState::stopNetworkWorker()
{
    // Notify the thread to exit first, then join, to prevent background threads from running after UI closure.
    networkWorkerRunning_.store(false, std::memory_order_release);
    if (networkWorkerThread_.joinable()) {
        networkWorkerThread_.join();
    }
}
