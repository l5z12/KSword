#include "AudioAnalyze.h"
#include <algorithm>
#include <cmath>
#include <complex>
#include <cwchar>
#include <thread>
#include <vector>
#include <QDebug>

// Simple complex type definition
typedef std::complex<double> Complex;

AudioSpectrumAnalyzer::AudioSpectrumAnalyzer(QObject* parent)
    : QObject(parent)
    , spectrumData_(kNumBands, 0.0f)
    , previousSpectrum_(kNumBands, 0.0f)
    , magnitudes_(kFftSize / 2, 0.0f)  // Add missing definition.
{
    audioBuffer_.reserve(kFftSize * 2);
    createWindowFunction();
}

AudioSpectrumAnalyzer::~AudioSpectrumAnalyzer()
{
    // Ensure a unified release path during destruction to prevent threads from still using released COM interfaces.
    releaseResources();
}

bool AudioSpectrumAnalyzer::initialize() {
    // The UI side only resets the cache. COM initialization and session creation for Core Audio are performed
    // by the capture thread, ensuring interfaces created in the STA are not passed naked to background threads.
    releaseResources();
    audioBuffer_.clear();
    {
        std::lock_guard<std::mutex> lock(spectrumMutex_);
        spectrumData_.fill(0.0f, kNumBands);
        previousSpectrum_.fill(0.0f, kNumBands);
    }
    magnitudes_.fill(0.0f, kFftSize / 2);
    sampleRate_ = 48000;
    return true;
}

void AudioSpectrumAnalyzer::releaseResources() {
    // The capture thread must exit first; COM interface Stop/Release/CoUninitialize operations are all performed on that thread.
    stopCapture();
}

bool AudioSpectrumAnalyzer::initializeAudioSessionOnWorker()
{
    // The capture thread is the sole Core Audio apartment; all interfaces are created and used within this MTA.
    const HRESULT kComResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(kComResult)) {
        qWarning() << "采集线程 COM 初始化失败，错误码:" << kComResult;
        return false;
    }
    workerComInitialized_ = true;

    const HRESULT kEnumeratorResult = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void**>(&deviceEnumerator_));
    if (FAILED(kEnumeratorResult)) {
        qWarning() << "创建音频设备枚举器失败，错误码:" << kEnumeratorResult;
        return false;
    }

    if (!initializeAudioDevice()) {
        qWarning() << "未能初始化可用的环回音频设备。";
        return false;
    }

    return true;
}

void AudioSpectrumAnalyzer::releaseAudioSessionOnWorker()
{
    // This function executes only in the captureAudioData collection thread to avoid cross-apartment Release.
    if (audioClient_) {
        audioClient_->Stop();
    }
    if (captureClient_) {
        captureClient_->Release();
        captureClient_ = nullptr;
    }
    if (audioClient_) {
        audioClient_->Release();
        audioClient_ = nullptr;
    }
    if (audioDevice_) {
        audioDevice_->Release();
        audioDevice_ = nullptr;
    }
    if (deviceEnumerator_) {
        deviceEnumerator_->Release();
        deviceEnumerator_ = nullptr;
    }
    if (waveFormat_) {
        CoTaskMemFree(waveFormat_);
        waveFormat_ = nullptr;
    }
    if (workerComInitialized_) {
        CoUninitialize();
        workerComInitialized_ = false;
    }
}

bool AudioSpectrumAnalyzer::enumerateAudioDevices()
{
    if (!deviceEnumerator_) {
        return false;
    }

    IMMDeviceCollection* deviceCollection = nullptr;
    HRESULT hr = deviceEnumerator_->EnumAudioEndpoints(
        eRender, DEVICE_STATE_ACTIVE, &deviceCollection);

    if (SUCCEEDED(hr) && deviceCollection) {
        UINT count = 0;
        deviceCollection->GetCount(&count);

        for (UINT i = 0; i < count; i++) {
            IMMDevice* device = nullptr;
            hr = deviceCollection->Item(i, &device);
            if (SUCCEEDED(hr)) {
                audioDevice_ = device;
                if (setupAudioClient()) {
                    deviceCollection->Release();
                    return true;
                }
                device->Release();
                // Clear the member immediately upon failure to avoid dangling pointers to released devices.
                audioDevice_ = nullptr;
            }
        }
        deviceCollection->Release();
    }
    return false;
}
bool AudioSpectrumAnalyzer::initializeAudioDevice()
{
    if (!deviceEnumerator_) {
        return false;
    }

    HRESULT hr = deviceEnumerator_->GetDefaultAudioEndpoint(
        eRender, eConsole, &audioDevice_);

    if (FAILED(hr)) {
        qWarning() << "Failed to get default audio endpoint, trying loopback...";
        // Attempt to enumerate devices to find a suitable loopback device.
        return enumerateAudioDevices();
    }

    return setupAudioClient();
}

bool AudioSpectrumAnalyzer::defaultAudioDeviceChangedOnWorker() const
{
    // Both the device enumerator and the current device are owned by the capture thread; missing either indicates the current session needs re-establishment.
    if (!deviceEnumerator_ || !audioDevice_)
    {
        return true;
    }

    // Read the stable endpoint IDs of the currently bound device and the system default render device to determine if the user has switched the output device.
    LPWSTR currentDeviceId = nullptr;
    LPWSTR defaultDeviceId = nullptr;
    IMMDevice* defaultDevice = nullptr;
    const HRESULT kCurrentIdResult = audioDevice_->GetId(&currentDeviceId);
    const HRESULT kDefaultDeviceResult = deviceEnumerator_->GetDefaultAudioEndpoint(
        eRender,
        eConsole,
        &defaultDevice);

    HRESULT defaultIdResult = E_FAIL;
    if (SUCCEEDED(kDefaultDeviceResult) && defaultDevice)
    {
        defaultIdResult = defaultDevice->GetId(&defaultDeviceId);
    }

    // Session is invalid when the current device ID is unreadable; if the default endpoint is temporarily unavailable, retain the current session and retry later.
    const bool kCurrentDeviceInvalid = FAILED(kCurrentIdResult) || currentDeviceId == nullptr;
    const bool kDefaultDeviceAvailable = SUCCEEDED(defaultIdResult) && defaultDeviceId != nullptr;
    const bool kDefaultDeviceChanged = kDefaultDeviceAvailable
        && !kCurrentDeviceInvalid
        && std::wcscmp(currentDeviceId, defaultDeviceId) != 0;

    // The device ID is allocated by COM; after comparison, all temporary objects created by it are released in pairs within the collection thread that created them.
    if (defaultDeviceId)
    {
        CoTaskMemFree(defaultDeviceId);
    }
    if (defaultDevice)
    {
        defaultDevice->Release();
    }
    if (currentDeviceId)
    {
        CoTaskMemFree(currentDeviceId);
    }

    return kCurrentDeviceInvalid || kDefaultDeviceChanged;
}

bool AudioSpectrumAnalyzer::setupAudioClient()
{
    // Establish a complete session in a local variable first; if it fails, no partially initialized interface is left for the next device.
    if (!audioDevice_) {
        return false;
    }

    IAudioClient* audioClient = nullptr;
    IAudioCaptureClient* captureClient = nullptr;
    WAVEFORMATEX* defaultFormat = nullptr;

    HRESULT hr = audioDevice_->Activate(__uuidof(IAudioClient), CLSCTX_ALL,
        nullptr, reinterpret_cast<void**>(&audioClient));
    if (FAILED(hr)) {
        qWarning() << "Failed to activate audio device";
        return false;
    }

    // pDefaultFormat is the sole format copy passed to IAudioClient; subsequent parsing must also use this same format.
    hr = audioClient->GetMixFormat(&defaultFormat);
    if (FAILED(hr)) {
        qWarning() << "获取设备默认格式失败. 错误码:" << hr;
        audioClient->Release();
        return false;
    }

    // Print default format (for debugging).
    qDebug() << "设备默认格式: " << defaultFormat->nSamplesPerSec << "Hz, "
        << defaultFormat->nChannels << "声道, "
        << defaultFormat->wBitsPerSample << "位";

    // initialize the audio client: use default format + shared mode.
    hr = audioClient->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_LOOPBACK,  // Capture speaker output (remove if capturing microphone).
        50000000,  // Buffer duration adjusted to 50ms (increasing the buffer improves compatibility).
        0,
        defaultFormat,
        nullptr
    );

    if (FAILED(hr)) {
        QString errorMsg;
        if (hr == AUDCLNT_E_DEVICE_IN_USE) {
            errorMsg = "设备被其他程序独占占用（请关闭占用程序）";
        }
        else if (hr == AUDCLNT_E_UNSUPPORTED_FORMAT) {
            errorMsg = "设备不支持默认格式（罕见）";
        }
        else {
            errorMsg = "初始化失败，错误码: " + QString::number(hr, 16);
        }
        qWarning() << "设备初始化失败:" << errorMsg;
        CoTaskMemFree(defaultFormat);
        audioClient->Release();
        return false;
    }

    hr = audioClient->GetService(__uuidof(IAudioCaptureClient),
        reinterpret_cast<void**>(&captureClient));
    if (FAILED(hr)) {
        qWarning() << "Failed to get audio capture client";
        CoTaskMemFree(defaultFormat);
        audioClient->Release();
        return false;
    }

    // Publish interfaces only after all steps succeed to avoid failed retries overwriting member pointers that still need release.
    audioClient_ = audioClient;
    captureClient_ = captureClient;
    waveFormat_ = defaultFormat;
    // Save the sample rate of the actually applied format; the format memory will be released before the capture thread exits.
    sampleRate_ = defaultFormat->nSamplesPerSec;
    return true;
}

void AudioSpectrumAnalyzer::startCapture()
{
    if (isCapturing_.load(std::memory_order_acquire)) {
        return;
    }

    // Old thread handles that have ended but not yet closed must be reclaimed first to avoid overwriting ownership of waitable threads.
    if (captureThread_) {
        if (WaitForSingleObject(captureThread_, 0) != WAIT_OBJECT_0) {
            return;
        }
        CloseHandle(captureThread_);
        captureThread_ = nullptr;
    }

    // UI does not touch IAudioClient; the worker thread creates, starts, and stops the session in its own MTA.
    isCapturing_.store(true, std::memory_order_release);

    // Create capture thread
    captureThread_ = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto analyzer = static_cast<AudioSpectrumAnalyzer*>(param);
        analyzer->captureAudioData();
        return 0;
        }, this, 0, nullptr);

    // If creation fails, no thread exists to clean up the state; it must be restored immediately to ensure the next restart succeeds.
    if (!captureThread_) {
        qWarning() << "创建音频捕获线程失败，错误码:" << GetLastError();
        isCapturing_.store(false, std::memory_order_release);
    }
}

void AudioSpectrumAnalyzer::stopCapture()
{
    // Note: Only send a stop request. Do not call IAudioClient::Stop from the UI thread within the worker thread's MTA.
    isCapturing_.store(false, std::memory_order_release);

    if (captureThread_) {
        // Wait for the capture thread to complete its Stop/Release/CoUninitialize sequence before destroying the object to avoid a dangling this pointer.
        WaitForSingleObject(captureThread_, INFINITE);
        CloseHandle(captureThread_);
        captureThread_ = nullptr;
    }
}

void AudioSpectrumAnalyzer::captureAudioData()
{
    // The capture thread holds all Core Audio interfaces; session reconstruction always completes in this thread to avoid cross-COM apartment calls.
    constexpr ULONGLONG kDefaultDeviceCheckIntervalMs = 500;
    ULONGLONG nextDefaultDeviceCheckAt = 0;

    while (isCapturing_.load(std::memory_order_acquire))
    {
        // On first launch or after a device switch, rebind the current default output device and enable its loopback capture.
        if (!audioClient_ || !captureClient_)
        {
            if (!initializeAudioSessionOnWorker())
            {
                qWarning() << "音频采集会话初始化失败，稍后重试。";
                releaseAudioSessionOnWorker();
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            // A stop request may occur during initialization; in this case, release only the session just created by this thread and do not start capturing.
            if (!isCapturing_.load(std::memory_order_acquire))
            {
                break;
            }

            const HRESULT kStartResult = audioClient_->Start();
            if (FAILED(kStartResult))
            {
                qWarning() << "启动音频采集失败，错误码:" << kStartResult << "，稍后重试。";
                releaseAudioSessionOnWorker();
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            // Immediately start a new default endpoint check cycle upon establishing a new session to avoid redundant queries in the same round.
            nextDefaultDeviceCheckAt = GetTickCount64() + kDefaultDeviceCheckIntervalMs;
        }

        // Periodically compare endpoint IDs to switch the spectrum audio source after Windows changes the default output device, without restarting the Taskbar.
        const ULONGLONG kCurrentTick = GetTickCount64();
        if (kCurrentTick >= nextDefaultDeviceCheckAt)
        {
            nextDefaultDeviceCheckAt = kCurrentTick + kDefaultDeviceCheckIntervalMs;
            if (defaultAudioDeviceChangedOnWorker())
            {
                qInfo() << "检测到默认音频输出设备改变，正在重建频谱采集会话。";
                releaseAudioSessionOnWorker();
                continue;
            }
        }

        UINT32 packetSize = 0;
        HRESULT hr = captureClient_->GetNextPacketSize(&packetSize);

        if (FAILED(hr))
        {
            // Rebuild immediately if the device is removed or invalidated by the system; for other transient errors, retain the original session and back off briefly.
            qWarning() << "GetNextPacketSize失败，错误码:" << hr;
            if (hr == AUDCLNT_E_DEVICE_INVALIDATED)
            {
                releaseAudioSessionOnWorker();
                continue;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (packetSize > 0)
        {
            BYTE* data = nullptr;
            UINT32 framesAvailable = 0;
            DWORD flags = 0;

            hr = captureClient_->GetBuffer(&data, &framesAvailable, &flags, nullptr, nullptr);
            if (SUCCEEDED(hr))
            {
                // The data field in silent packets may be nullptr; explicitly zeroing it preserves the timeline without dereferencing a null pointer.
                if (framesAvailable > 0)
                {
                    const BYTE* sampleData = (flags & AUDCLNT_BUFFERFLAGS_SILENT) ? nullptr : data;
                    if (isCapturing_.load(std::memory_order_acquire))
                    {
                        processAudioData(sampleData, framesAvailable);
                    }
                }

                // ReleaseBuffer must always be paired with a successful GetBuffer, including zero-frame packets.
                captureClient_->ReleaseBuffer(framesAvailable);
            }
            else
            {
                // Same as GetNextPacketSize: release the old interface when the device is invalidated, and the worker thread will rebind the default endpoint in the next iteration.
                qWarning() << "GetBuffer失败，错误码:" << hr;
                if (hr == AUDCLNT_E_DEVICE_INVALIDATED)
                {
                    releaseAudioSessionOnWorker();
                }
            }
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // All Stop and Release operations remain in the same MTA where the interface was created; the UI side only waits for the thread to terminate.
    releaseAudioSessionOnWorker();
    isCapturing_.store(false, std::memory_order_release);
    qDebug() << "捕获线程退出";
}

void AudioSpectrumAnalyzer::processAudioData(const BYTE* data, UINT32 framesAvailable) {
    // Each call appends only the mono samples actually generated by this packet and uses this precise range for diagnostics.
    if (!waveFormat_ || framesAvailable == 0 || waveFormat_->nChannels == 0) {
        qDebug() << "m_waveFormat is null!";
        return;
    }

    qDebug() << "Processing audio data - Frames:" << framesAvailable
        << "Format:" << waveFormat_->wFormatTag
        << "Channels:" << waveFormat_->nChannels
        << "Bits:" << waveFormat_->wBitsPerSample;

    const UINT16 kChannelCount = waveFormat_->nChannels;
    const int kBufferStart = audioBuffer_.size();

    // Average interleaved frames from any number of channels into a single mono sample to prevent out-of-bounds access for dual-channel-specific indices.
    const auto kAppendFloatFrames = [this, framesAvailable, kChannelCount](const float* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < kChannelCount; ++channel) {
                mixedSample += samples[static_cast<size_t>(frame) * kChannelCount + channel];
            }
            audioBuffer_.append(mixedSample / static_cast<float>(kChannelCount));
        }
    };

    // normalize signed PCM frames by the specified ratio before mixing; the caller guarantees sample bit-width matches.
    const auto kAppendPcm32Frames = [this, framesAvailable, kChannelCount](const int32_t* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < kChannelCount; ++channel) {
                mixedSample += static_cast<float>(samples[static_cast<size_t>(frame) * kChannelCount + channel]) / 2147483648.0f;
            }
            audioBuffer_.append(mixedSample / static_cast<float>(kChannelCount));
        }
    };

    // 16-bit PCM uses independent conversion to avoid misinterpreting the 16-bit buffer as a 32-bit array.
    const auto kAppendPcm16Frames = [this, framesAvailable, kChannelCount](const int16_t* samples) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            float mixedSample = 0.0f;
            for (UINT16 channel = 0; channel < kChannelCount; ++channel) {
                mixedSample += static_cast<float>(samples[static_cast<size_t>(frame) * kChannelCount + channel]) / 32768.0f;
            }
            audioBuffer_.append(mixedSample / static_cast<float>(kChannelCount));
        }
    };

    // WASAPI mute packets have no valid data pointer; padding with zeros per frame allows FFT to decay smoothly.
    if (!data) {
        for (UINT32 frame = 0; frame < framesAvailable; ++frame) {
            audioBuffer_.append(0.0f);
        }
    }
    else {
    // Parse samples based on the actual format.
    qDebug() << "Audio format - Tag:" << waveFormat_->wFormatTag
        << "Bits:" << waveFormat_->wBitsPerSample;

    // Parse samples based on the actual format.
    if (waveFormat_->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
        // Cast to extended format structure
        WAVEFORMATEXTENSIBLE* waveFormatExt = (WAVEFORMATEXTENSIBLE*)waveFormat_;
        GUID subFormat = waveFormatExt->SubFormat;

        qDebug() << "Extended format - SubFormat:" << subFormat.Data1;

        // Check if the format is IEEE floating-point.
        if (subFormat.Data1 == WAVE_FORMAT_IEEE_FLOAT) {
            qDebug() << "Detected IEEE FLOAT format";
            kAppendFloatFrames(reinterpret_cast<const float*>(data));
        }
        // Check if the format is PCM.
        else if (subFormat.Data1 == WAVE_FORMAT_PCM) {
            qDebug() << "Detected PCM format in extensible wrapper";
            if (waveFormat_->wBitsPerSample == 32) {
                kAppendPcm32Frames(reinterpret_cast<const int32_t*>(data));
            }
            else if (waveFormat_->wBitsPerSample == 16) {
                kAppendPcm16Frames(reinterpret_cast<const int16_t*>(data));
            }
        }
        else {
            qDebug() << "Unsupported subformat:" << subFormat.Data1;
            return;
        }
    }
    else
        if (waveFormat_->wFormatTag == WAVE_FORMAT_IEEE_FLOAT && waveFormat_->wBitsPerSample == 32) {
        // 32-bit floating-point format (format returned by the device)
        kAppendFloatFrames(reinterpret_cast<const float*>(data));
    }
    else if (waveFormat_->wFormatTag == WAVE_FORMAT_PCM) {
        // PCM format handling
        if (waveFormat_->wBitsPerSample == 32) {
            kAppendPcm32Frames(reinterpret_cast<const int32_t*>(data));
        }
        else if (waveFormat_->wBitsPerSample == 16) {
            kAppendPcm16Frames(reinterpret_cast<const int16_t*>(data));
        }
    }
    else {
        qDebug() << "Unsupported format tag:" << waveFormat_->wFormatTag;
        return;
    }
    }

    const int kAppendedSampleCount = audioBuffer_.size() - kBufferStart;
    if (kAppendedSampleCount > 0) {
        // Since only one mono sample is appended per frame, the range start must use appendedSampleCount rather than the channel count.
        const auto kFirstNewSample = audioBuffer_.cbegin() + kBufferStart;
        const float kMinSample = *std::min_element(kFirstNewSample, audioBuffer_.cend());
        const float kMaxSample = *std::max_element(kFirstNewSample, audioBuffer_.cend());
        qDebug() << "Collected" << framesAvailable << "frames, buffer size:" << audioBuffer_.size();
        qDebug() << "Sample range: min=" << kMinSample << "max=" << kMaxSample;
    }
    else {
        qDebug() << "No data collected! Buffer remains empty.";
    }


    // Consume all complete windows one by one; a single large packet no longer causes unbounded growth of the pending buffer.
    while (audioBuffer_.size() >= kFftSize) {
        qDebug() << "Performing FFT...";
        applyFFT(audioBuffer_.constData(), kFftSize);
        audioBuffer_.remove(0, kFftSize / 2);
        qDebug() << "Buffer after FFT:" << audioBuffer_.size();
    }
    qDebug() << "Audio buffer size:" << audioBuffer_.size();
}
void AudioSpectrumAnalyzer::applyFFT(const float* audioData, int size)
{
    std::vector<Complex> complexData(size);

    // Apply Hanning window and convert to complex.
    for (int i = 0; i < size; ++i) {
        float windowedSample = audioData[i] * hanningWindow_[i];
        complexData[i] = Complex(windowedSample, 0.0);
    }

    // Execute FFT
    for (int i = 1, j = 0; i < size; ++i) {
        int bit = size >> 1;
        for (; j >= bit; bit >>= 1) {
            j -= bit;
        }
        j += bit;
        if (i < j) {
            std::swap(complexData[i], complexData[j]);
        }
    }

    for (int length = 2; length <= size; length <<= 1) {
        double angle = -2.0 * M_PI / length;
        Complex wlen(std::cos(angle), std::sin(angle));

        for (int i = 0; i < size; i += length) {
            Complex w(1.0, 0.0);
            for (int j = 0; j < length / 2; ++j) {
                Complex u = complexData[i + j];
                Complex v = complexData[i + j + length / 2] * w;
                complexData[i + j] = u + v;
                complexData[i + j + length / 2] = u - v;
                w *= wlen;
            }
        }
    }

    // Calculate magnitude and store in m_magnitudes
    for (int i = 0; i < size / 2; ++i) {
        magnitudes_[i] = static_cast<float>(std::abs(complexData[i]));
    }

    calculateFrequencyBands();
}

void AudioSpectrumAnalyzer::calculateFrequencyBands() {
    qDebug() << "Calculating frequency bands...";

    if (magnitudes_.isEmpty()) {
        qDebug() << "ERROR: Magnitudes array is empty!";
        return;
    }

    // Calculate the average magnitude for each frequency band. The band index
    // must use the current device format; do not assume all devices are 48 kHz.
    const int kFftSize = magnitudes_.size();
    const float kSampleRate = static_cast<float>(sampleRate_);
    if (kSampleRate <= 0.0f) {
        return;
    }

    // Compute first in the local copy within the acquisition thread, then publish to the UI thread all at once.
    QVector<float> nextSpectrum(kNumBands, 0.0f);
    for (int band = 0; band < kNumBands; ++band) {
        // Calculate the frequency range (logarithmic scale) corresponding to the band.
        float lowFreq = band == 0 ? 20.0f : (kSampleRate / 2) * pow(2.0f, (band - 1) / (kNumBands - 1.0f));
        float highFreq = (kSampleRate / 2) * pow(2.0f, band / (kNumBands - 1.0f));

        int lowBin = qMax(0, static_cast<int>(lowFreq * kFftSize / kSampleRate));
        int highBin = qMin(kFftSize - 1, static_cast<int>(highFreq * kFftSize / kSampleRate));

        if (lowBin >= highBin) {
            lowBin = highBin - 1;
            if (lowBin < 0) lowBin = 0;
        }

        // Calculate the average value for this frequency band.
        float sum = 0.0f;
        int count = 0;
        for (int bin = lowBin; bin <= highBin; ++bin) {
            sum += magnitudes_[bin];
            count++;
        }
        //Custom spectrum scaling coefficient.
        if(band < 4){
            sum *= 0.8f; // Low-frequency amplification
        } else if(band < 8){
            sum *= 1.5f; // Slightly amplify mid-low frequencies
        } else if(band < 12){
            sum *= 1.5f; // Slightly reduce mid-high frequencies
        } else {
            sum *= 5.0f; // High frequencies soar.
		}
        nextSpectrum[band] = count > 0 ? sum / count : 0.0f;
    }

    // Debug output for frequency band data
    const float kMaxBand = *std::max_element(nextSpectrum.cbegin(), nextSpectrum.cend());
    qDebug() << "Frequency bands calculated - max band:" << kMaxBand;

    if (kMaxBand > 0) {
        qDebug() << "First 5 bands:";
        for (int i = 0; i < 5 && i < kNumBands; ++i) {
            qDebug() << "  Band" << i << ":" << nextSpectrum[i];
        }
    }

    {
        std::lock_guard<std::mutex> lock(spectrumMutex_);
        spectrumData_ = nextSpectrum;
    }
    emit spectrumDataReady(nextSpectrum);
    qDebug() << "Spectrum data signal emitted";
}
void AudioSpectrumAnalyzer::createWindowFunction()
{
    hanningWindow_.resize(kFftSize);
    for (int i = 0; i < kFftSize; ++i) {
        hanningWindow_[i] = 0.5f * (1.0f - std::cos(2.0f * M_PI * i / (kFftSize - 1)));
    }
}

QVector<float> AudioSpectrumAnalyzer::getSpectrumData() const
{
    std::lock_guard<std::mutex> lock(spectrumMutex_);
    return spectrumData_;
}
