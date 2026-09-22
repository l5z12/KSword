#include "SoundSourceDetector.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <Audioclient.h>
#include <Audiopolicy.h>
#include <Endpointvolume.h>
#include <propkeydef.h>
#include <Functiondiscoverykeys_devpkey.h>
#include <Mmdeviceapi.h>
#include <Propvarutil.h>
#include <QFileInfo>
#include <QHash>
#include <QStringList>
#include <QThread>
#include <wrl/client.h>

#include <algorithm>
#include <map>
#include <set>

// ============================================================
// SoundSourceDetector.cpp
// Purpose:
// - Confirms the output sound source via Core Audio session-level peak detection.
// - Prevent PID reuse false positives using R3 process creation time.
// - Independently verify candidate PIDs via R0 Cross-View and Runtime Detail.
// ============================================================

namespace
{
    using Microsoft::WRL::ComPtr;

    constexpr float kAudiblePeakThreshold = 0.0005F;
    constexpr float kAudibleVolumeThreshold = 0.0001F;
    constexpr unsigned long kKernelCrossViewNodeBudget = 4096UL;

    // ScopedComInitialization: Manages COM initialization balance for the detection worker thread.
    class ScopedComInitialization final
    {
    public:
        ScopedComInitialization()
            : result_(::CoInitializeEx(nullptr, COINIT_MULTITHREADED))
            , shouldUninitialize_(SUCCEEDED(result_))
        {
        }

        ~ScopedComInitialization()
        {
            if (shouldUninitialize_)
            {
                ::CoUninitialize();
            }
        }

        // usable: RPC_E_CHANGED_MODE indicates the thread has switched to another apartment; COM can still invoke.
        bool usable() const
        {
            return SUCCEEDED(result_) || result_ == RPC_E_CHANGED_MODE;
        }

        HRESULT result() const
        {
            return result_;
        }

    private:
        HRESULT result_ = E_FAIL;       // Return value of CoInitializeEx.
        bool shouldUninitialize_ = false; // Whether CoUninitialize must be executed by the destructor.
    };

    // SessionProbe: saves the session meters that still need to be called within a single sampling window.
    struct SessionProbe
    {
        std::size_t recordIndex = 0;                // Corresponding result record index.
        ComPtr<IAudioMeterInformation> meter;       // Session-level peak interface.
        float peakSum = 0.0F;                       // Sum of all successfully sampled peak values.
        int successfulSamples = 0;                  // Number of successful peak reads.
    };

    // EndpointProbe: stores the output endpoint meter and the session indices belonging to that endpoint.
    struct EndpointProbe
    {
        ComPtr<IAudioMeterInformation> meter;       // Output device peak interface.
        std::vector<std::size_t> recordIndices;     // The result record indices contained in this endpoint.
        float peakMaximum = 0.0F;                   // Device maximum peak within the sampling window.
    };

    // coTaskMemString: Copies a COM-allocated wide string and immediately frees the original memory.
    QString coTaskMemString(LPWSTR rawText)
    {
        if (rawText == nullptr)
        {
            return QString();
        }

        const QString kCopiedText = QString::fromWCharArray(rawText);
        ::CoTaskMemFree(rawText);
        return kCopiedText;
    }

    // queryDeviceFriendlyName: Reads the endpoint name visible to the user from the MMDevice property store.
    QString queryDeviceFriendlyName(IMMDevice* const device)
    {
        if (device == nullptr)
        {
            return QString();
        }

        ComPtr<IPropertyStore> propertyStore;
        const HRESULT kStoreResult = device->OpenPropertyStore(
            STGM_READ,
            propertyStore.GetAddressOf());
        if (FAILED(kStoreResult))
        {
            return QString();
        }

        PROPVARIANT friendlyNameValue;
        ::PropVariantInit(&friendlyNameValue);
        const HRESULT kPropertyResult = propertyStore->GetValue(
            PKEY_Device_FriendlyName,
            &friendlyNameValue);
        QString friendlyName;
        if (SUCCEEDED(kPropertyResult) &&
            friendlyNameValue.vt == VT_LPWSTR &&
            friendlyNameValue.pwszVal != nullptr)
        {
            friendlyName = QString::fromWCharArray(friendlyNameValue.pwszVal);
        }
        ::PropVariantClear(&friendlyNameValue);
        return friendlyName;
    }

    // queryProcessIdentity: Reads the path and creation time using R3 public APIs without requesting write permissions.
    void queryProcessIdentity(ks::misc::SoundSourceRecord& record)
    {
        if (record.processId == 0U)
        {
            record.processName = QStringLiteral("系统声音");
            return;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            record.processId);
        if (processHandle == nullptr)
        {
            record.processName = QStringLiteral("PID %1").arg(record.processId);
            return;
        }

        std::wstring imagePathBuffer(32768U, L'\0');
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        if (::QueryFullProcessImageNameW(
                processHandle,
                0,
                imagePathBuffer.data(),
                &imagePathLength) != FALSE)
        {
            imagePathBuffer.resize(imagePathLength);
            record.imagePath = QString::fromStdWString(imagePathBuffer);
            record.processName = QFileInfo(record.imagePath).fileName();
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE)
        {
            record.creationTime100ns =
                (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        }
        ::CloseHandle(processHandle);

        if (record.processName.trimmed().isEmpty())
        {
            record.processName = QStringLiteral("PID %1").arg(record.processId);
        }
    }

    // sessionStateText: Converts Core Audio state to stable, visible text.
    QString sessionStateText(const AudioSessionState state)
    {
        switch (state)
        {
        case AudioSessionStateActive:
            return QStringLiteral("活动");
        case AudioSessionStateInactive:
            return QStringLiteral("静默");
        case AudioSessionStateExpired:
            return QStringLiteral("已过期");
        default:
            return QStringLiteral("未知");
        }
    }

    // defaultEndpointIds: Reads the endpoint IDs for the three default output roles.
    QHash<int, QString> defaultEndpointIds(IMMDeviceEnumerator* const enumerator)
    {
        QHash<int, QString> roleIds;
        if (enumerator == nullptr)
        {
            return roleIds;
        }

        const ERole kRoles[] = { eConsole, eMultimedia, eCommunications };
        for (const ERole kRole : kRoles)
        {
            ComPtr<IMMDevice> defaultDevice;
            if (FAILED(enumerator->GetDefaultAudioEndpoint(
                    eRender,
                    kRole,
                    defaultDevice.GetAddressOf())))
            {
                continue;
            }

            LPWSTR rawEndpointId = nullptr;
            if (SUCCEEDED(defaultDevice->GetId(&rawEndpointId)))
            {
                roleIds.insert(static_cast<int>(kRole), coTaskMemString(rawEndpointId));
            }
        }
        return roleIds;
    }

    // endpointRoleText: Indicates whether the endpoint assumes the default console, multimedia, or communication role.
    QString endpointRoleText(
        const QString& endpointId,
        const QHash<int, QString>& roleIds)
    {
        QStringList roles;
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eConsole)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认控制台"));
        }
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eMultimedia)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认多媒体"));
        }
        if (endpointId.compare(
                roleIds.value(static_cast<int>(eCommunications)),
                Qt::CaseInsensitive) == 0)
        {
            roles.push_back(QStringLiteral("默认通信"));
        }
        return roles.isEmpty() ? QStringLiteral("非默认端点") : roles.join(QStringLiteral(" / "));
    }

    // shortAnsiImageName: safely copies the fixed 16-byte EPROCESS ImageFileName from R0.
    QString shortAnsiImageName(const char* const sourceText, const std::size_t capacity)
    {
        if (sourceText == nullptr || capacity == 0U)
        {
            return QString();
        }

        std::size_t textLength = 0U;
        while (textLength < capacity && sourceText[textLength] != '\0')
        {
            ++textLength;
        }
        return QString::fromLatin1(sourceText, static_cast<qsizetype>(textLength));
    }

    // crossViewSourceText: Expands the R0 three-source bits to avoid displaying hard-to-interpret hexadecimal values.
    QString crossViewSourceText(const std::uint32_t sourceMask)
    {
        QStringList sources;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            sources.push_back(QStringLiteral("Public API"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            sources.push_back(QStringLiteral("ActiveProcessLinks"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            sources.push_back(QStringLiteral("PspCidTable"));
        }
        return sources.isEmpty() ? QStringLiteral("无") : sources.join(QStringLiteral(" + "));
    }

    // sourceBitCount: Counts the number of R0 process sources relevant to this feature.
    int sourceBitCount(const std::uint32_t sourceMask)
    {
        int sourceCount = 0;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            ++sourceCount;
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            ++sourceCount;
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            ++sourceCount;
        }
        return sourceCount;
    }

    // kernelEvidenceForProcess: Synthesizes Cross-View and Runtime Detail into a single PID verification conclusion.
    ks::misc::SoundSourceKernelEvidence kernelEvidenceForProcess(
        const ks::misc::SoundSourceRecord& record,
        const ksword::ark::ProcessCrossViewEntry* const crossViewEntry,
        const ksword::ark::ProcessRuntimeDetailResult& runtimeDetail)
    {
        ks::misc::SoundSourceKernelEvidence evidence;
        evidence.attempted = true;
        evidence.driverAvailable = true;
        if (crossViewEntry == nullptr && !runtimeDetail.io.ok)
        {
            evidence.statusText = QStringLiteral("R0 查询失败");
            evidence.detailText = QString::fromStdString(runtimeDetail.io.message);
            return evidence;
        }

        if (crossViewEntry != nullptr)
        {
            evidence.processFound = true;
            evidence.sourceMask = crossViewEntry->sourceMask;
            evidence.anomalyFlags = crossViewEntry->anomalyFlags;
            evidence.confidence = crossViewEntry->confidence;
            evidence.processObjectAddress = crossViewEntry->objectAddress;
            evidence.imageName = QString::fromStdString(crossViewEntry->imageName);
        }

        if (runtimeDetail.io.ok)
        {
            const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response = runtimeDetail.response;
            evidence.runtimeFieldFlags = response.fieldFlags;
            evidence.processObjectAddress = response.processObjectAddress != 0U
                ? response.processObjectAddress
                : evidence.processObjectAddress;
            evidence.objectTableAddress = response.objectTableAddress;

            const bool kPublicIdentityPresent =
                (response.fieldFlags & KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY) != 0U;
            const bool kUniquePidPresent =
                (response.fieldFlags & KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID) != 0U;
            const bool kPublicPidMatches =
                response.processId == record.processId;
            const bool kUniquePidMatches =
                !kUniquePidPresent ||
                response.uniqueProcessIdValue == static_cast<std::uint64_t>(record.processId);
            evidence.processFound =
                evidence.processFound ||
                (kPublicIdentityPresent && kPublicPidMatches);
            evidence.identityMatched =
                kPublicIdentityPresent &&
                kPublicPidMatches &&
                kUniquePidMatches;

            const QString kRuntimeImageName = shortAnsiImageName(
                response.imageName,
                KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS);
            if (!kRuntimeImageName.isEmpty())
            {
                evidence.imageName = kRuntimeImageName;
            }
        }
        else if (crossViewEntry != nullptr)
        {
            // When Runtime Detail is missing, all observed source PIDs must match the target PID.
            const bool kPublicPidMatches =
                crossViewEntry->publicProcessId == 0U ||
                crossViewEntry->publicProcessId == record.processId;
            const bool kActivePidMatches =
                crossViewEntry->activeListProcessId == 0U ||
                crossViewEntry->activeListProcessId == record.processId;
            const bool kCidPidMatches =
                crossViewEntry->cidTableProcessId == 0U ||
                crossViewEntry->cidTableProcessId == record.processId;
            evidence.identityMatched =
                kPublicPidMatches &&
                kActivePidMatches &&
                kCidPidMatches;
        }

        const int kSourceCount = sourceBitCount(evidence.sourceMask);
        evidence.corroborated =
            evidence.processFound &&
            evidence.identityMatched &&
            kSourceCount >= 2 &&
            evidence.anomalyFlags == 0U;

        if (evidence.corroborated)
        {
            evidence.statusText = QStringLiteral("R0 多源一致");
        }
        else if (evidence.anomalyFlags != 0U)
        {
            evidence.statusText = QStringLiteral("R0 发现异常");
        }
        else if (evidence.processFound)
        {
            evidence.statusText = QStringLiteral("R0 部分佐证");
        }
        else
        {
            evidence.statusText = QStringLiteral("R0 未定位进程");
        }

        evidence.detailText = QStringLiteral(
            "来源=%1；Cross-View异常=0x%2；Runtime字段=0x%3；R0映像=%4")
            .arg(crossViewSourceText(evidence.sourceMask))
            .arg(evidence.anomalyFlags, 0, 16)
            .arg(evidence.runtimeFieldFlags, 0, 16)
            .arg(evidence.imageName.isEmpty() ? QStringLiteral("不可用") : evidence.imageName);
        return evidence;
    }

    // applyKernelEvidence: Performs a single R0 verification of shared handles only for active/sound-emitting candidate PIDs.
    void applyKernelEvidence(
        const ks::misc::SoundSourceScanOptions& options,
        ks::misc::SoundSourceScanResult& scanResult)
    {
        std::set<std::uint32_t> candidateProcessIds;
        for (const ks::misc::SoundSourceRecord& record : scanResult.records)
        {
            const bool kProcessDetailScope = options.processIdFilter != 0U;
            if (record.processId != 0U &&
                (record.currentlyAudible || record.sessionActive || kProcessDetailScope))
            {
                candidateProcessIds.insert(record.processId);
            }
        }
        if (!options.includeKernelEvidence || candidateProcessIds.empty())
        {
            return;
        }

        scanResult.kernelAttempted = true;
        const ksword::ark::DriverClient kDriverClient;
        ksword::ark::DriverHandle driverHandle = kDriverClient.open();
        const unsigned long kOpenError = driverHandle.isValid()
            ? ERROR_SUCCESS
            : ::GetLastError();
        if (!driverHandle.isValid())
        {
            scanResult.kernelDiagnosticText =
                QStringLiteral("KswordARK 不可用，Win32=%1").arg(kOpenError);
            for (ks::misc::SoundSourceRecord& record : scanResult.records)
            {
                if (candidateProcessIds.contains(record.processId))
                {
                    record.kernel.attempted = true;
                    record.kernel.statusText = QStringLiteral("R0 不可用");
                    record.kernel.detailText = scanResult.kernelDiagnosticText;
                }
            }
            return;
        }
        scanResult.kernelAvailable = true;

        const std::uint32_t kMinimumPid = *candidateProcessIds.begin();
        const std::uint32_t kMaximumPid = *candidateProcessIds.rbegin();
        const ksword::ark::ProcessCrossViewResult kCrossViewResult =
            kDriverClient.queryProcessCrossView(
                KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
                kMinimumPid,
                kMaximumPid,
                kKernelCrossViewNodeBudget,
                &driverHandle);
        std::map<std::uint32_t, const ksword::ark::ProcessCrossViewEntry*> crossViewByPid;
        if (kCrossViewResult.io.ok)
        {
            for (const ksword::ark::ProcessCrossViewEntry& entry : kCrossViewResult.entries)
            {
                if (candidateProcessIds.contains(entry.processId))
                {
                    crossViewByPid[entry.processId] = &entry;
                }
            }
        }
        else
        {
            scanResult.kernelDiagnosticText =
                QString::fromStdString(kCrossViewResult.io.message);
        }

        for (const std::uint32_t kProcessId : candidateProcessIds)
        {
            const ksword::ark::ProcessRuntimeDetailResult kRuntimeDetail =
                kDriverClient.queryProcessRuntimeDetail(
                    kProcessId,
                    KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL,
                    &driverHandle);
            const auto kCrossViewIterator = crossViewByPid.find(kProcessId);
            const ksword::ark::ProcessCrossViewEntry* const kCrossViewEntry =
                kCrossViewIterator == crossViewByPid.end()
                ? nullptr
                : kCrossViewIterator->second;

            for (ks::misc::SoundSourceRecord& record : scanResult.records)
            {
                if (record.processId == kProcessId)
                {
                    record.kernel = kernelEvidenceForProcess(
                        record,
                        kCrossViewEntry,
                        kRuntimeDetail);
                }
            }
        }
    }
}

namespace ks::misc
{
    SoundSourceScanResult detectSoundSources(const SoundSourceScanOptions& options)
    {
        SoundSourceScanResult scanResult;
        const int kSampleCount = std::clamp(options.sampleCount, 1, 20);
        const int kSampleIntervalMs = std::clamp(options.sampleIntervalMs, 10, 250);
        scanResult.sampleWindowMs = (kSampleCount - 1) * kSampleIntervalMs;

        ScopedComInitialization comInitialization;
        if (!comInitialization.usable())
        {
            scanResult.diagnosticText =
                QStringLiteral("Core Audio COM 初始化失败，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(comInitialization.result()), 0, 16);
            return scanResult;
        }

        ComPtr<IMMDeviceEnumerator> deviceEnumerator;
        const HRESULT kEnumeratorResult = ::CoCreateInstance(
            __uuidof(MMDeviceEnumerator),
            nullptr,
            CLSCTX_ALL,
            IID_PPV_ARGS(deviceEnumerator.GetAddressOf()));
        if (FAILED(kEnumeratorResult))
        {
            scanResult.diagnosticText =
                QStringLiteral("无法创建 MMDeviceEnumerator，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(kEnumeratorResult), 0, 16);
            return scanResult;
        }

        const QHash<int, QString> kRoleIds = defaultEndpointIds(deviceEnumerator.Get());
        ComPtr<IMMDeviceCollection> endpointCollection;
        const HRESULT kEndpointEnumResult = deviceEnumerator->EnumAudioEndpoints(
            eRender,
            DEVICE_STATE_ACTIVE,
            endpointCollection.GetAddressOf());
        if (FAILED(kEndpointEnumResult))
        {
            scanResult.diagnosticText =
                QStringLiteral("无法枚举活动输出端点，HRESULT=0x%1")
                .arg(static_cast<unsigned long>(kEndpointEnumResult), 0, 16);
            return scanResult;
        }

        UINT endpointCount = 0U;
        endpointCollection->GetCount(&endpointCount);
        std::vector<SessionProbe> sessionProbes;
        std::vector<EndpointProbe> endpointProbes;

        for (UINT endpointIndex = 0U; endpointIndex < endpointCount; ++endpointIndex)
        {
            ComPtr<IMMDevice> endpointDevice;
            if (FAILED(endpointCollection->Item(
                    endpointIndex,
                    endpointDevice.GetAddressOf())))
            {
                continue;
            }

            LPWSTR rawEndpointId = nullptr;
            const QString kEndpointId = SUCCEEDED(endpointDevice->GetId(&rawEndpointId))
                ? coTaskMemString(rawEndpointId)
                : QString();
            const QString kEndpointName = queryDeviceFriendlyName(endpointDevice.Get());
            const QString kEndpointRoles = endpointRoleText(kEndpointId, kRoleIds);

            ComPtr<IAudioSessionManager2> sessionManager;
            if (FAILED(endpointDevice->Activate(
                    __uuidof(IAudioSessionManager2),
                    CLSCTX_ALL,
                    nullptr,
                    reinterpret_cast<void**>(sessionManager.GetAddressOf()))))
            {
                continue;
            }

            ComPtr<IAudioSessionEnumerator> sessionEnumerator;
            if (FAILED(sessionManager->GetSessionEnumerator(
                    sessionEnumerator.GetAddressOf())))
            {
                continue;
            }

            EndpointProbe endpointProbe;
            endpointDevice->Activate(
                __uuidof(IAudioMeterInformation),
                CLSCTX_ALL,
                nullptr,
                reinterpret_cast<void**>(endpointProbe.meter.GetAddressOf()));

            int sessionCount = 0;
            sessionEnumerator->GetCount(&sessionCount);
            for (int sessionIndex = 0; sessionIndex < sessionCount; ++sessionIndex)
            {
                ComPtr<IAudioSessionControl> baseSessionControl;
                if (FAILED(sessionEnumerator->GetSession(
                        sessionIndex,
                        baseSessionControl.GetAddressOf())))
                {
                    continue;
                }

                ComPtr<IAudioSessionControl2> sessionControl;
                if (FAILED(baseSessionControl.As(&sessionControl)))
                {
                    continue;
                }

                DWORD processId = 0U;
                sessionControl->GetProcessId(&processId);
                if (options.processIdFilter != 0U &&
                    processId != options.processIdFilter)
                {
                    continue;
                }

                SoundSourceRecord record;
                record.processId = static_cast<std::uint32_t>(processId);
                record.endpointId = kEndpointId;
                record.endpointName = kEndpointName.isEmpty()
                    ? QStringLiteral("未命名输出端点")
                    : kEndpointName;
                record.endpointRoleText = kEndpointRoles;
                record.systemSounds =
                    sessionControl->IsSystemSoundsSession() == S_OK;

                AudioSessionState sessionState = AudioSessionStateInactive;
                if (SUCCEEDED(sessionControl->GetState(&sessionState)))
                {
                    record.sessionActive = sessionState == AudioSessionStateActive;
                    record.stateText = sessionStateText(sessionState);
                }
                else
                {
                    record.stateText = QStringLiteral("状态不可用");
                }

                LPWSTR rawDisplayName = nullptr;
                if (SUCCEEDED(sessionControl->GetDisplayName(&rawDisplayName)))
                {
                    record.sessionName = coTaskMemString(rawDisplayName);
                }
                LPWSTR rawSessionId = nullptr;
                if (SUCCEEDED(sessionControl->GetSessionIdentifier(&rawSessionId)))
                {
                    record.sessionIdentifier = coTaskMemString(rawSessionId);
                }
                LPWSTR rawSessionInstanceId = nullptr;
                if (SUCCEEDED(sessionControl->GetSessionInstanceIdentifier(
                        &rawSessionInstanceId)))
                {
                    record.sessionInstanceId = coTaskMemString(rawSessionInstanceId);
                }

                queryProcessIdentity(record);
                if (options.expectedCreationTime100ns != 0U &&
                    record.creationTime100ns != options.expectedCreationTime100ns)
                {
                    // Process details are bound to PID + creation time; ownership is rejected if creation time cannot be read or the PID is reused.
                    continue;
                }
                if (record.systemSounds)
                {
                    record.processName = QStringLiteral("系统声音");
                }
                if (record.sessionName.trimmed().isEmpty())
                {
                    record.sessionName = record.processName;
                }

                ComPtr<ISimpleAudioVolume> simpleVolume;
                if (SUCCEEDED(baseSessionControl.As(&simpleVolume)))
                {
                    simpleVolume->GetMasterVolume(&record.sessionVolume);
                    BOOL muted = FALSE;
                    simpleVolume->GetMute(&muted);
                    record.muted = muted != FALSE;
                    record.volumeAvailable = true;
                }

                SessionProbe sessionProbe;
                sessionProbe.recordIndex = scanResult.records.size();
                if (SUCCEEDED(baseSessionControl.As(&sessionProbe.meter)))
                {
                    record.meterAvailable = true;
                }

                scanResult.records.push_back(std::move(record));
                endpointProbe.recordIndices.push_back(sessionProbe.recordIndex);
                sessionProbes.push_back(std::move(sessionProbe));
            }
            endpointProbes.push_back(std::move(endpointProbe));
        }

        // Note: Peak sampling is performed per 'all sessions round' to ensure different processes use the same time window.
        for (int sampleIndex = 0; sampleIndex < kSampleCount; ++sampleIndex)
        {
            for (SessionProbe& sessionProbe : sessionProbes)
            {
                if (sessionProbe.meter == nullptr)
                {
                    continue;
                }
                float peakValue = 0.0F;
                if (SUCCEEDED(sessionProbe.meter->GetPeakValue(&peakValue)))
                {
                    SoundSourceRecord& record =
                        scanResult.records[sessionProbe.recordIndex];
                    record.peakMaximum = std::max(record.peakMaximum, peakValue);
                    sessionProbe.peakSum += peakValue;
                    ++sessionProbe.successfulSamples;
                }
            }

            for (EndpointProbe& endpointProbe : endpointProbes)
            {
                if (endpointProbe.meter == nullptr)
                {
                    continue;
                }
                float endpointPeakValue = 0.0F;
                if (SUCCEEDED(endpointProbe.meter->GetPeakValue(
                        &endpointPeakValue)))
                {
                    endpointProbe.peakMaximum = std::max(
                        endpointProbe.peakMaximum,
                        endpointPeakValue);
                }
            }

            if (sampleIndex + 1 < kSampleCount)
            {
                QThread::msleep(static_cast<unsigned long>(kSampleIntervalMs));
            }
        }

        for (const SessionProbe& sessionProbe : sessionProbes)
        {
            SoundSourceRecord& record = scanResult.records[sessionProbe.recordIndex];
            if (sessionProbe.successfulSamples > 0)
            {
                record.peakAverage =
                    sessionProbe.peakSum /
                    static_cast<float>(sessionProbe.successfulSamples);
            }
            record.currentlyAudible =
                record.meterAvailable &&
                record.sessionActive &&
                !record.muted &&
                (!record.volumeAvailable ||
                 record.sessionVolume > kAudibleVolumeThreshold) &&
                record.peakMaximum >= kAudiblePeakThreshold;

            if (record.currentlyAudible)
            {
                record.verdictText = QStringLiteral("正在发声");
            }
            else if (record.sessionActive && record.muted)
            {
                record.verdictText = QStringLiteral("活动但已静音");
            }
            else if (record.sessionActive)
            {
                record.verdictText = record.meterAvailable
                    ? QStringLiteral("活动，本次未检测到波形")
                    : QStringLiteral("活动，会话峰值不可用");
            }
            else
            {
                record.verdictText = QStringLiteral("静默会话");
            }
        }

        for (const EndpointProbe& endpointProbe : endpointProbes)
        {
            for (const std::size_t kRecordIndex : endpointProbe.recordIndices)
            {
                if (kRecordIndex < scanResult.records.size())
                {
                    scanResult.records[kRecordIndex].endpointPeakMaximum =
                        endpointProbe.peakMaximum;
                }
            }
        }

        std::stable_sort(
            scanResult.records.begin(),
            scanResult.records.end(),
            [](const SoundSourceRecord& left, const SoundSourceRecord& right)
            {
                if (left.currentlyAudible != right.currentlyAudible)
                {
                    return left.currentlyAudible;
                }
                if (left.sessionActive != right.sessionActive)
                {
                    return left.sessionActive;
                }
                return left.peakMaximum > right.peakMaximum;
            });

        scanResult.audioQueryOk = true;
        applyKernelEvidence(options, scanResult);
        return scanResult;
    }
}
