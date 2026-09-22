#ifndef AUDIOSPECTRUMANALYZER_H
#define AUDIOSPECTRUMANALYZER_H

#include <QObject>
#include <QVector>
#include <atomic>
#include <memory>
#include <mutex>
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

class AudioSpectrumAnalyzer : public QObject
{
    Q_OBJECT

public:
    // Constructs the spectrum analyzer and initializes FFT data that does not depend on the device.
    explicit AudioSpectrumAnalyzer(QObject* parent = nullptr);
    // Destroy the analyzer; waits for the capture thread to exit before releasing COM interfaces.
    ~AudioSpectrumAnalyzer();

    // Stop the capture thread and clean up non-COM spectrum buffers.
    void releaseResources();
    // Reset local cache for the next capture; Core Audio session is created only within the capture thread.
    bool initialize();
    // Start single background capture thread.
    void startCapture();
    // Request the background capture thread to exit and wait for it to release the audio interface.
    void stopCapture();
    // Returns the most recently calculated spectrum snapshot.
    QVector<float> getSpectrumData() const;

signals:
    void spectrumDataReady(const QVector<float>& spectrumData);

private:
    static constexpr int kFftSize = 1024;
    static constexpr int kNumBands = 16;

    // Note: The following session functions are called only from the thread executing captureAudioData to avoid passing interfaces across COM apartments.
    bool initializeAudioSessionOnWorker();
    void releaseAudioSessionOnWorker();
    bool enumerateAudioDevices();

    // sample_rate: Read and written only by the capture thread, used for frequency band conversion.
    int sampleRate_ = 48000;
    // defaultAudioDeviceChangedOnWorker: Compares the current session with the system default output device and returns whether the session needs to be rebuilt.
    bool defaultAudioDeviceChangedOnWorker() const;
    bool initializeAudioDevice();
    bool setupAudioClient();
    void captureAudioData();
    void processAudioData(const BYTE* data, UINT32 framesAvailable);
    void applyFFT(const float* audioData, int size);
    void calculateFrequencyBands();
    void applySmoothing();

    // Windows Core Audio members are exclusively owned, used, and released by the collection thread (MTA).
    IMMDeviceEnumerator* deviceEnumerator_ = nullptr;
    IMMDevice* audioDevice_ = nullptr;
    IAudioClient* audioClient_ = nullptr;
    IAudioCaptureClient* captureClient_ = nullptr;
    WAVEFORMATEX* waveFormat_ = nullptr;
    // This flag is accessed only by the capture thread to balance its own CoInitializeEx calls.
    bool workerComInitialized_ = false;

    // Audio processing members. Spectrum snapshots can be read by the UI thread, so they are protected by a separate mutex.
    QVector<float> audioBuffer_;
    QVector<float> spectrumData_;
    QVector<float> previousSpectrum_;
    QVector<float> magnitudes_;
    mutable std::mutex spectrumMutex_;

    // The UI thread requests exit only via this atomic flag; the capture thread polls and terminates the Core Audio session independently.
    std::atomic<bool> isCapturing_{ false };
    // The thread handle is reclaimed only by the start/stop side and is retained until the capture thread actually exits.
    HANDLE captureThread_ = nullptr;

    // FFT window function
    QVector<float> hanningWindow_;
    void createWindowFunction();
};

#endif // AUDIOSPECTRUMANALYZER_H
