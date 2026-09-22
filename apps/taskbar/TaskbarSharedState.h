#ifndef TASKBARSHAREDSTATE_H
#define TASKBARSHAREDSTATE_H

#include "AudioAnalyze.h"
#include "Function.h"

#include <QObject>
#include <QVector>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

class TaskbarSharedState : public QObject
{
    Q_OBJECT

public:
    // Constructor: accepts a parent QObject; initializes the shared sampler and cache; returns no business value.
    explicit TaskbarSharedState(QObject* parent = nullptr);

    // Destructor: no input; handle stopping audio, CPU, and network sampling threads; no return value.
    ~TaskbarSharedState() override;

    // Start shared sampling: no input; performs one-time audio capture, CPU sampling, and network sampling; no return value.
    void start();

    // Stop shared sampling: no input; safely terminates all background sampling threads; no return value.
    void stop();

    // Get CPU snapshot: no input; handle mutex-protected read; return utilization per logical core (0-100).
    QVector<int> cpuUsageSnapshot() const;

    // Get upload rate: no input; performs atomic read; returns bytes per second for upload.
    std::uint64_t uploadSpeedBytesPerSecond() const;

    // Get download rate: no input; performs atomic read; returns bytes per second for download.
    std::uint64_t downloadSpeedBytesPerSecond() const;

signals:
    // Spectrum data broadcast: accepts 16-segment spectrum data; processing is handled by the receive window; the signal itself has no return value.
    void spectrumDataReady(const QVector<float>& spectrumData);

private:
    // Start CPU thread: no input; handles re-entrancy and thread creation; no return value.
    void startCpuWorker();

    // Stop CPU thread: No input; handles stop flag and join; no return value.
    void stopCpuWorker();

    // Start network thread: no input; handles re-entrancy and thread creation; no return value.
    void startNetworkWorker();

    // Stop network thread: no input; process stop flag and join; no return value.
    void stopNetworkWorker();

    std::unique_ptr<AudioSpectrumAnalyzer> analyzer_;// Process-wide unique audio spectrum sampler.
    bool started_;                                   // Idempotency protection flag for start/stop.
    bool audioCaptureStarted_;                       // Whether audio capture has started successfully.

    mutable std::mutex cpuUsageMutex_;               // Mutex for CPU utilization cache.
    QVector<int> cpuUsage_;                          // Per-core CPU utilization shared snapshot.
    std::atomic<bool> cpuWorkerRunning_;             // Flag indicating whether the CPU background thread is running.
    std::thread cpuWorkerThread_;                    // CPU background sampling thread object.

    std::atomic<bool> networkWorkerRunning_;         // Network background thread running flag.
    std::thread networkWorkerThread_;                // Network background sampling thread object.
    std::atomic<std::uint64_t> uploadBytesPerSecond_;// Uplink speed cache, unit B/s.
    std::atomic<std::uint64_t> downloadBytesPerSecond_;// Downlink speed cache, unit B/s.
};

#endif
