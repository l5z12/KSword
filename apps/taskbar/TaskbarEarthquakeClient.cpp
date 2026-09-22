#include "TaskbarEarthquakeClient.h"
#include "TaskbarEarthquakeAudioPlayer.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <mutex>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace
{
    // Earthquake source definitions follow the multi-source configuration validated by WindowsMarker, connecting to three real-time Chinese sources by default.
    enum class WarningProvider
    {
        kFanStudio, // FanStudio aggregation source update message.
        kWolfx      // Standard EEW messages for each Wolfx region source.
    };

    struct SourceConfig
    {
        const char* id;             // Stable source identifier.
        const char* name;           // Source name for the settings window.
        const wchar_t* host;        // WebSocket host name.
        const wchar_t* path;        // WebSocket HTTPS path.
        WarningProvider provider;   // JSON parser type for the current source.
        bool enabledByDefault;      // Whether to establish a connection by default.
    };

    constexpr SourceConfig kSources[] = {
        { "fanstudio-cea", "FanStudio CEA", L"ws.fanstudio.tech", L"/all", WarningProvider::kFanStudio, true },
        { "wolfx-cenc", "Wolfx CENC", L"ws-api.wolfx.jp", L"/cenc_eew", WarningProvider::kWolfx, true },
        { "wolfx-sc", "Wolfx Sichuan", L"ws-api.wolfx.jp", L"/sc_eew", WarningProvider::kWolfx, true },
        { "wolfx-fj", "Wolfx Fujian", L"ws-api.wolfx.jp", L"/fj_eew", WarningProvider::kWolfx, false },
        { "wolfx-cq", "Wolfx Chongqing", L"ws-api.wolfx.jp", L"/cq_eew", WarningProvider::kWolfx, false },
        { "wolfx-jma", "Wolfx JMA", L"ws-api.wolfx.jp", L"/jma_eew", WarningProvider::kWolfx, false }
    };
    constexpr int kSourceCount = static_cast<int>(std::size(kSources));
    constexpr ULONGLONG kActiveNoUpdateTimeoutMs = 90ull * 1000ull;
    constexpr DWORD kReconnectBaseMs = 2000;
    constexpr DWORD kReconnectMaxMs = 30000;
    constexpr DWORD kServerBusyReconnectMs = 60000;
    constexpr DWORD kKeepalivePingIntervalMs = 30000;

    // ParsedWarningMessage: Internal message representation unified from different JSON sources.
    struct ParsedWarningMessage
    {
        bool hasEvent = false;      // Whether it contains a valid earthquake event field.
        bool heartbeat = false;     // Whether this is solely for heartbeat/ping/pong.
        bool finalReport = false;   // Whether the current source has published the final report.
        bool canceled = false;      // Whether the current source has canceled the warning.
        QString eventId;            // Original event ID, currently retained for diagnostics only.
        QString source;             // Source text provided by the server.
        QString originTime;         // Earthquake occurrence time.
        QString hypoCenter;         // Epicenter location text.
        double magnitude = 0.0;     // Message magnitude.
        double depth = 0.0;         // Packet depth, in kilometers.
        double latitude = 0.0;      // Epicenter latitude.
        double longitude = 0.0;     // Epicenter longitude.
        int reportNum = 0;          // Current report count.
    };

    // Read JSON strings by multiple candidate field names to support WindowsMarker-compatible server variants.
    QString firstStringValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue kValue = object.value(QLatin1String(key));
            if (kValue.isString())
            {
                const QString kText = kValue.toString().trimmed();
                if (!kText.isEmpty())
                {
                    return kText;
                }
            }
            if (kValue.isDouble())
            {
                return QString::number(kValue.toDouble(), 'f', 0);
            }
        }
        return QString();
    }

    // When reading JSON values, preserve 0 as an indicator for missing or invalid fields to avoid triggering high-level audio with unreliable data.
    double firstDoubleValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue kValue = object.value(QLatin1String(key));
            if (kValue.isDouble())
            {
                return kValue.toDouble();
            }
            if (kValue.isString())
            {
                bool converted = false;
                const double kNumber = kValue.toString().toDouble(&converted);
                if (converted)
                {
                    return kNumber;
                }
            }
        }
        return 0.0;
    }

    // Tolerates the server encoding the report count as a string when reading JSON integers.
    int firstIntValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue kValue = object.value(QLatin1String(key));
            if (kValue.isDouble())
            {
                return kValue.toInt();
            }
            if (kValue.isString())
            {
                bool converted = false;
                const int kNumber = kValue.toString().toInt(&converted);
                if (converted)
                {
                    return kNumber;
                }
            }
        }
        return 0;
    }

    // When reading JSON boolean values, recognize both boolean types and common text states.
    bool firstBoolValue(const QJsonObject& object, std::initializer_list<const char*> keys)
    {
        for (const char* key : keys)
        {
            const QJsonValue kValue = object.value(QLatin1String(key));
            if (kValue.isBool())
            {
                return kValue.toBool();
            }
            if (kValue.isString())
            {
                const QString kText = kValue.toString().trimmed().toLower();
                if (kText == QStringLiteral("true") || kText == QStringLiteral("yes") ||
                    kText == QStringLiteral("final") || kText == QStringLiteral("cancel") ||
                    kText == QStringLiteral("cancelled"))
                {
                    return true;
                }
            }
        }
        return false;
    }

    // containsInsensitive is used to identify custom status/type fields from various sources without relying on case sensitivity.
    bool containsInsensitive(const QString& text, const QString& needle)
    {
        return text.contains(needle, Qt::CaseInsensitive);
    }

    // parseWolfxMessage parses the unified EEW messages from Wolfx CENC, Sichuan, Fujian, Chongqing, and JMA.
    ParsedWarningMessage parseWolfxMessage(const QByteArray& payload)
    {
        ParsedWarningMessage parsed;
        const QJsonDocument kDocument = QJsonDocument::fromJson(payload);
        if (!kDocument.isObject())
        {
            return parsed;
        }

        const QJsonObject kObject = kDocument.object();
        const QString kType = firstStringValue(kObject, { "type", "Type" });
        parsed.heartbeat = containsInsensitive(kType, QStringLiteral("heart")) ||
            containsInsensitive(kType, QStringLiteral("ping")) ||
            containsInsensitive(kType, QStringLiteral("pong")) ||
            kObject.contains(QStringLiteral("heartbeat"));
        parsed.eventId = firstStringValue(kObject, { "EventID", "EventId", "event_id", "ID", "id" });
        parsed.source = firstStringValue(kObject, { "Source", "source" });
        parsed.originTime = firstStringValue(kObject, { "OriginTime", "originTime", "origin_time" });
        parsed.hypoCenter = firstStringValue(kObject, { "HypoCenter", "Hypocenter", "hypocenter", "placeName" });
        parsed.magnitude = firstDoubleValue(kObject, { "Magnitude", "Magunitude", "magnitude" });
        parsed.depth = firstDoubleValue(kObject, { "Depth", "depth" });
        parsed.latitude = firstDoubleValue(kObject, { "Latitude", "latitude" });
        parsed.longitude = firstDoubleValue(kObject, { "Longitude", "longitude" });
        parsed.reportNum = firstIntValue(kObject, { "ReportNum", "Serial", "reportNum", "updates" });
        const QString kStatus = firstStringValue(kObject, { "ReportStatus", "Status", "status" });
        parsed.finalReport = firstBoolValue(kObject, { "Final", "isFinal", "is_final" }) ||
            containsInsensitive(kStatus, QStringLiteral("final"));
        parsed.canceled = firstBoolValue(kObject, { "Cancel", "Canceled", "Cancelled", "isCancel", "is_cancel" }) ||
            containsInsensitive(kStatus, QStringLiteral("cancel"));
        parsed.hasEvent = !parsed.eventId.isEmpty() || !parsed.hypoCenter.isEmpty() || parsed.magnitude > 0.0;
        return parsed;
    }

    // parseFanStudioMessage accepts only real-time update data from CEA/CEA-PR, filtering out other aggregated channel events.
    ParsedWarningMessage parseFanStudioMessage(const QByteArray& payload)
    {
        ParsedWarningMessage parsed;
        const QJsonDocument kDocument = QJsonDocument::fromJson(payload);
        if (!kDocument.isObject())
        {
            return parsed;
        }

        const QJsonObject kObject = kDocument.object();
        const QString kType = firstStringValue(kObject, { "type", "Type" });
        parsed.heartbeat = containsInsensitive(kType, QStringLiteral("heart")) ||
            containsInsensitive(kType, QStringLiteral("ping")) ||
            containsInsensitive(kType, QStringLiteral("pong"));
        if (parsed.heartbeat || !containsInsensitive(kType, QStringLiteral("update")))
        {
            return parsed;
        }

        parsed.source = firstStringValue(kObject, { "source", "Source" }).toLower();
        if (parsed.source != QStringLiteral("cea") && parsed.source != QStringLiteral("cea-pr"))
        {
            return parsed;
        }

        parsed.eventId = firstStringValue(kObject, { "eventId", "id", "EventID" });
        parsed.originTime = firstStringValue(kObject, { "shockTime", "originTime", "OriginTime" });
        parsed.hypoCenter = firstStringValue(kObject, { "placeName", "HypoCenter" });
        parsed.magnitude = firstDoubleValue(kObject, { "magnitude", "Magnitude" });
        parsed.depth = firstDoubleValue(kObject, { "depth", "Depth" });
        parsed.latitude = firstDoubleValue(kObject, { "latitude", "Latitude" });
        parsed.longitude = firstDoubleValue(kObject, { "longitude", "Longitude" });
        parsed.reportNum = firstIntValue(kObject, { "updates", "ReportNum" });
        const QString kStatus = firstStringValue(kObject, { "status", "Status" });
        parsed.finalReport = firstBoolValue(kObject, { "Final", "isFinal", "final" }) ||
            containsInsensitive(kStatus, QStringLiteral("final"));
        parsed.canceled = firstBoolValue(kObject, { "Cancel", "isCancel", "cancel" }) ||
            containsInsensitive(kStatus, QStringLiteral("cancel"));
        parsed.hasEvent = !parsed.eventId.isEmpty() || !parsed.hypoCenter.isEmpty();
        return parsed;
    }

    // parseMessageForProvider dispatches JSON adapters for each source, outputting unified warning fields.
    ParsedWarningMessage parseMessageForProvider(WarningProvider provider, const QByteArray& payload)
    {
        return provider == WarningProvider::kFanStudio ? parseFanStudioMessage(payload) : parseWolfxMessage(payload);
    }

    // makeLocationKey merges multi-source epicenters with the same location using 0.01-degree precision for latitude and longitude; falls back to location text if coordinates are missing.
    QString makeLocationKey(const ParsedWarningMessage& parsed)
    {
        if (!qFuzzyIsNull(parsed.latitude) || !qFuzzyIsNull(parsed.longitude))
        {
            return QStringLiteral("%1,%2")
                .arg(parsed.latitude, 0, 'f', 2)
                .arg(parsed.longitude, 0, 'f', 2);
        }
        return parsed.hypoCenter.trimmed();
    }

    // sleepUntilStop segments long reconnection waits to allow stop() to respond within the 100ms range.
    bool sleepUntilStop(const std::atomic_bool& stopRequested, DWORD milliseconds)
    {
        DWORD elapsed = 0;
        while (elapsed < milliseconds && !stopRequested.load())
        {
            const DWORD kStep = std::min<DWORD>(100, milliseconds - elapsed);
            ::Sleep(kStep);
            elapsed += kStep;
        }
        return stopRequested.load();
    }
}

// Private consolidates WinHTTP threads, event aggregation, and optional audio queues into the implementation file to keep the Taskbar public header stable.
class TaskbarEarthquakeClient::Private
{
public:
    struct SourceReading
    {
        bool present = false;      // Whether this source has ever reported the event.
        bool ended = false;        // Whether this source publishes a final report or a cancellation.
        bool canceled = false;     // Whether this source is explicitly canceled.
        double magnitude = 0.0;    // The most recent magnitude from this source.
        double depth = 0.0;        // The most recent depth from this source.
        int reportNum = 0;         // The most recent report count from this source.
    };

    struct AggregatedEvent
    {
        QString locationKey;                       // Key for aggregation by epicenter location.
        QString hypoCenter;                        // First valid location text.
        QString originTime;                        // First valid occurrence time.
        double latitude = 0.0;                      // Aggregated latitude.
        double longitude = 0.0;                     // Aggregated longitude.
        ULONGLONG lastUpdateTick = 0;               // Last valid message timestamp.
        bool testEvent = false;                     // true indicates testing the warning in the local settings page.
        ULONGLONG testExpirationTick = 0;           // Test warning auto-expiration time.
        std::array<SourceReading, kSourceCount> readings; // Current readings per source.
    };

    struct SourceRuntime
    {
        std::thread thread;                  // The sole receiving thread for this source.
        std::mutex socketMutex;              // Coordinate socket closure between stop and the blocking receive.
        HINTERNET socket = nullptr;          // Currently upgraded WebSocket handle.
        std::atomic_bool connected{ false }; // Current connection status.
        std::atomic_bool everConnected{ false }; // At least one successful connection in this process.
        std::atomic_bool preferDirect{ false }; // Prefer to skip system proxy after a successful direct connection.
        std::atomic<ULONGLONG> lastMessageTick{ 0 }; // Time of the last data/heartbeat arrival.
        std::atomic<ULONGLONG> lastPingTick{ 0 }; // Monotonic clock of the most recent ping sent.
        std::atomic<ULONGLONG> latencyMs{ 0 }; // Round-trip latency for ping/pong.
    };

    // Constructor: Save external QObject, create runtime directory audio player without loading any embedded audio resources.
    explicit Private(TaskbarEarthquakeClient* owner)
        : owner(owner)
        , audioPlayer(new TaskbarEarthquakeAudioPlayer(owner))
    {
    }

    // Destructor: Releases members after calling stop(); all thread objects have been joined, so no dangling WinHTTP handles exist.
    ~Private()
    {
        stop();
    }

    // start: Starts the worker thread with the default source; repeated calls do not create a second set of connections.
    void start()
    {
        if (started.exchange(true))
        {
            return;
        }

        stopRequested.store(false);
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            if (!kSources[sourceIndex].enabledByDefault)
            {
                continue;
            }
            runtimes[sourceIndex].thread = std::thread(&Private::sourceThreadMain, this, sourceIndex);
        }
        keepaliveThread = std::thread(&Private::keepaliveThreadMain, this);
    }

    // stop: Close all WebSocket connections to interrupt receive, then wait for each source thread to exit cleanly.
    void stop()
    {
        if (!started.exchange(false))
        {
            return;
        }

        stopRequested.store(true);
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            closeSourceSocket(sourceIndex);
        }
        if (keepaliveThread.joinable())
        {
            keepaliveThread.join();
        }
        for (SourceRuntime& runtime : runtimes)
        {
            if (runtime.thread.joinable())
            {
                runtime.thread.join();
            }
        }
    }

    // warningsSnapshot: constructs an immutable UI snapshot after cleaning up expired events; the caller does not hold the lock.
    QList<TaskbarEarthquakeEvent> warningsSnapshot()
    {
        std::lock_guard<std::mutex> lock(eventsMutex);
        const ULONGLONG kNow = ::GetTickCount64();
        pruneExpiredEventsLocked(kNow);
        QList<TaskbarEarthquakeEvent> warnings;
        for (const AggregatedEvent& event : events)
        {
            if (!isEventActiveLocked(event, kNow))
            {
                continue;
            }
            TaskbarEarthquakeEvent view;
            view.locationKey = event.locationKey;
            view.hypoCenter = event.hypoCenter;
            view.originTime = event.originTime;
            view.magnitudeText = combinedReadingText(event, true);
            view.depthText = combinedReadingText(event, false);
            view.sourcesText = activeSourcesText(event);
            view.reportNum = maxActiveReportNumber(event);
            view.sourceCount = activeSourceCount(event);
            warnings.push_back(view);
        }
        return warnings;
    }

    // statusesSnapshot: Reads diagnostic information from atomic connection states without needing to hold the network thread's socketMutex for a long duration.
    QList<TaskbarEarthquakeSourceStatus> statusesSnapshot() const
    {
        const ULONGLONG kNow = ::GetTickCount64();
        QList<TaskbarEarthquakeSourceStatus> statuses;
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            const SourceRuntime& runtime = runtimes[sourceIndex];
            TaskbarEarthquakeSourceStatus status;
            status.id = QLatin1String(kSources[sourceIndex].id);
            status.name = QLatin1String(kSources[sourceIndex].name);
            status.enabled = kSources[sourceIndex].enabledByDefault;
            status.connected = runtime.connected.load();
            status.everConnected = runtime.everConnected.load();
            const ULONGLONG kLastMessage = runtime.lastMessageTick.load();
            status.lastMessageAgeMs = kLastMessage != 0 && kNow >= kLastMessage ? kNow - kLastMessage : 0;
            status.latencyMs = runtime.latencyMs.load();
            statuses.push_back(status);
        }
        return statuses;
    }

    // injectTestWarning: Creates a 10-second test warning, deliberately bypassing the network to reuse the actual active state and red theme path.
    void injectTestWarning()
    {
        const ULONGLONG kNow = ::GetTickCount64();
        {
            std::lock_guard<std::mutex> lock(eventsMutex);
            events.erase(std::remove_if(events.begin(), events.end(), [](const AggregatedEvent& event) {
                return event.testEvent;
            }), events.end());

            AggregatedEvent testEvent;
            testEvent.locationKey = QStringLiteral("__taskbar_test_earthquake__");
            testEvent.hypoCenter = QStringLiteral("四川省阿坝州汶川县");
            testEvent.originTime = QStringLiteral("测试预警");
            testEvent.latitude = 31.0;
            testEvent.longitude = 103.4;
            testEvent.lastUpdateTick = kNow;
            testEvent.testEvent = true;
            testEvent.testExpirationTick = kNow + 10ull * 1000ull;
            SourceReading& reading = testEvent.readings[0];
            reading.present = true;
            reading.magnitude = 6.0;
            reading.depth = 10.0;
            reading.reportNum = 1;
            events.push_back(std::move(testEvent));
        }
        postWarningChange();
        queueAudioForReport(6.0, false);
    }

    // setAlertAudioEnabled: Controls only optional sounds and the playback queue; when disabled, clears unplayed content and mutes immediately.
    void setAlertAudioEnabled(bool enabled)
    {
        alertAudioEnabled = enabled;
        if (audioPlayer != nullptr)
        {
            audioPlayer->setEnabled(alertAudioEnabled);
        }
    }

    // sourceThreadMain: maintains a WinHTTP WebSocket for a single source, with exponential backoff reconnection on failure.
    void sourceThreadMain(int sourceIndex)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        const SourceConfig& config = kSources[sourceIndex];
        HINTERNET session = ::WinHttpOpen(L"KSword Taskbar/1.0 EEW", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session == nullptr)
        {
            return;
        }

        ::WinHttpSetTimeouts(session, 5000, 5000, 5000, 90000);
        DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
        secureProtocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
        ::WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols));

        DWORD reconnectDelayMs = kReconnectBaseMs;
        while (!stopRequested.load())
        {
            DWORD httpStatus = 0;
            DWORD lastError = ERROR_SUCCESS;
            bool usedDirect = runtime.preferDirect.load();
            HINTERNET socket = connectSourceWebSocket(session, config, usedDirect, &httpStatus, &lastError);
            if (socket == nullptr && httpStatus == 0 && lastError != ERROR_WINHTTP_TIMEOUT && !stopRequested.load())
            {
                usedDirect = !usedDirect;
                socket = connectSourceWebSocket(session, config, usedDirect, &httpStatus, &lastError);
            }

            if (socket == nullptr)
            {
                runtime.connected.store(false);
                postSourceStatusChange();
                const bool kServerBusy = httpStatus == 429 || httpStatus == 503 || lastError == ERROR_WINHTTP_TIMEOUT;
                const DWORD kDelay = kServerBusy ? kServerBusyReconnectMs : reconnectDelayMs;
                sleepUntilStop(stopRequested, kDelay);
                reconnectDelayMs = std::min<DWORD>(kReconnectMaxMs, reconnectDelayMs + kReconnectBaseMs);
                continue;
            }

            reconnectDelayMs = kReconnectBaseMs;
            runtime.preferDirect.store(usedDirect);
            {
                std::lock_guard<std::mutex> lock(runtime.socketMutex);
                runtime.socket = socket;
            }
            runtime.connected.store(true);
            runtime.everConnected.store(true);
            postSourceStatusChange();
            receiveSourceMessages(sourceIndex, socket);
            closeSourceSocketIfCurrent(sourceIndex, socket);
            runtime.connected.store(false);
            postSourceStatusChange();
            if (!stopRequested.load())
            {
                sleepUntilStop(stopRequested, reconnectDelayMs);
            }
        }

        ::WinHttpCloseHandle(session);
    }

    // connectSourceWebSocket: Completes the HTTPS upgrade, returns the successful WebSocket or nullptr, and returns the failure type.
    HINTERNET connectSourceWebSocket(HINTERNET session, const SourceConfig& config, bool bypassProxy,
        DWORD* httpStatus, DWORD* lastError)
    {
        if (httpStatus != nullptr)
        {
            *httpStatus = 0;
        }
        if (lastError != nullptr)
        {
            *lastError = ERROR_SUCCESS;
        }

        HINTERNET connection = ::WinHttpConnect(session, config.host, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (connection == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            return nullptr;
        }

        HINTERNET request = ::WinHttpOpenRequest(connection, L"GET", config.path, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        if (bypassProxy)
        {
            WINHTTP_PROXY_INFO proxyInfo = {};
            proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
            proxyInfo.lpszProxy = WINHTTP_NO_PROXY_NAME;
            proxyInfo.lpszProxyBypass = WINHTTP_NO_PROXY_BYPASS;
            ::WinHttpSetOption(request, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
        }

        ::WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0);
        const BOOL kSent = ::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        const BOOL kReceived = kSent != FALSE && ::WinHttpReceiveResponse(request, nullptr) != FALSE;
        if (kReceived == FALSE)
        {
            if (lastError != nullptr)
            {
                *lastError = ::GetLastError();
            }
            ::WinHttpCloseHandle(request);
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        ::WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        if (httpStatus != nullptr)
        {
            *httpStatus = status;
        }
        if (status != 101)
        {
            ::WinHttpCloseHandle(request);
            ::WinHttpCloseHandle(connection);
            return nullptr;
        }

        HINTERNET socket = ::WinHttpWebSocketCompleteUpgrade(request, 0);
        if (socket == nullptr && lastError != nullptr)
        {
            *lastError = ::GetLastError();
        }
        ::WinHttpCloseHandle(request);
        ::WinHttpCloseHandle(connection);
        return socket;
    }

    // receiveSourceMessages: Receive fragmented text frames; only pass complete messages to JSON parsing and event aggregation.
    void receiveSourceMessages(int sourceIndex, HINTERNET socket)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        QByteArray message;
        std::array<unsigned char, 8192> buffer = {};
        while (!stopRequested.load())
        {
            DWORD bytesRead = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType = WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
            const DWORD kResult = ::WinHttpWebSocketReceive(socket, buffer.data(),
                static_cast<DWORD>(buffer.size()), &bytesRead, &bufferType);
            if (kResult != ERROR_SUCCESS || bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
            {
                break;
            }

            const ULONGLONG kNow = ::GetTickCount64();
            runtime.lastMessageTick.store(kNow);
            if (runtime.lastPingTick.load() != 0)
            {
                const ULONGLONG kLastPing = runtime.lastPingTick.exchange(0);
                if (kNow >= kLastPing)
                {
                    runtime.latencyMs.store(kNow - kLastPing);
                }
            }
            postSourceStatusChange();

            if (bufferType != WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE &&
                bufferType != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
            {
                continue;
            }

            message.append(reinterpret_cast<const char*>(buffer.data()), static_cast<qsizetype>(bytesRead));
            if (bufferType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE)
            {
                continue;
            }

            const ParsedWarningMessage kParsed = parseMessageForProvider(kSources[sourceIndex].provider, message);
            message.clear();
            applySourceEvent(sourceIndex, kParsed);
        }
    }

    // applySourceEvent: Merges the source message into the event table deduplicated by coordinates and asynchronously notifies the GUI thread of changes.
    void applySourceEvent(int sourceIndex, const ParsedWarningMessage& parsed)
    {
        if (!parsed.hasEvent || parsed.heartbeat)
        {
            return;
        }

        const QString kLocationKey = makeLocationKey(parsed);
        if (kLocationKey.isEmpty())
        {
            return;
        }

        const ULONGLONG kNow = ::GetTickCount64();
        bool stateChanged = false;
        {
            std::lock_guard<std::mutex> lock(eventsMutex);
            auto iterator = std::find_if(events.begin(), events.end(), [&kLocationKey](const AggregatedEvent& event) {
                return event.locationKey == kLocationKey;
            });
            if (iterator == events.end())
            {
                if (parsed.canceled)
                {
                    return;
                }
                AggregatedEvent event;
                event.locationKey = kLocationKey;
                event.hypoCenter = parsed.hypoCenter;
                event.originTime = parsed.originTime;
                event.latitude = parsed.latitude;
                event.longitude = parsed.longitude;
                event.lastUpdateTick = kNow;
                events.push_back(std::move(event));
                iterator = std::prev(events.end());
            }

            AggregatedEvent& event = *iterator;
            if (event.hypoCenter.isEmpty())
            {
                event.hypoCenter = parsed.hypoCenter;
            }
            if (event.originTime.isEmpty())
            {
                event.originTime = parsed.originTime;
            }
            if (qFuzzyIsNull(event.latitude) && qFuzzyIsNull(event.longitude))
            {
                event.latitude = parsed.latitude;
                event.longitude = parsed.longitude;
            }
            event.lastUpdateTick = kNow;
            SourceReading& reading = event.readings[sourceIndex];
            reading.present = true;
            reading.ended = parsed.finalReport || parsed.canceled;
            reading.canceled = parsed.canceled;
            reading.magnitude = parsed.magnitude;
            reading.depth = parsed.depth;
            reading.reportNum = parsed.reportNum;
            stateChanged = true;
        }

        if (stateChanged)
        {
            postWarningChange();
            TaskbarEarthquakeClient* target = owner;
            QMetaObject::invokeMethod(target, [target, magnitude = parsed.magnitude, canceled = parsed.canceled]() {
                emit target->reportReceived(magnitude, canceled);
            }, Qt::QueuedConnection);
        }
    }

    // closeSourceSocket: Close a current socket; WinHTTP receive will return, allowing the corresponding thread to exit or reconnect.
    void closeSourceSocket(int sourceIndex)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        HINTERNET socket = nullptr;
        {
            std::lock_guard<std::mutex> lock(runtime.socketMutex);
            socket = runtime.socket;
            runtime.socket = nullptr;
        }
        if (socket != nullptr)
        {
            ::WinHttpCloseHandle(socket);
        }
    }

    // closeSourceSocketIfCurrent: Close only if the receiving thread still owns the handle to avoid double-close between stop() and the receiving thread.
    void closeSourceSocketIfCurrent(int sourceIndex, HINTERNET socket)
    {
        SourceRuntime& runtime = runtimes[sourceIndex];
        bool ownsSocket = false;
        {
            std::lock_guard<std::mutex> lock(runtime.socketMutex);
            if (runtime.socket == socket)
            {
                runtime.socket = nullptr;
                ownsSocket = true;
            }
        }
        if (ownsSocket)
        {
            ::WinHttpCloseHandle(socket);
        }
    }

    // sendSourcePing: The keep-alive thread is the sole sender; socketMutex serializes send operations with the close operation in stop().
    void sendSourcePing(int sourceIndex)
    {
        // The keep-alive thread is the sole sender; socketMutex serializes send operations with stop() closure.
        SourceRuntime& runtime = runtimes[sourceIndex];
        std::lock_guard<std::mutex> lock(runtime.socketMutex);
        if (runtime.socket == nullptr || !runtime.connected.load())
        {
            return;
        }

        const char kPing[] = "ping";
        const ULONGLONG kNow = ::GetTickCount64();
        const DWORD kResult = ::WinHttpWebSocketSend(runtime.socket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
            const_cast<char*>(kPing), static_cast<DWORD>(sizeof(kPing) - 1));
        if (kResult == ERROR_SUCCESS)
        {
            runtime.lastPingTick.store(kNow);
        }
    }

    // keepaliveThreadMain: Sends a lightweight ping every 30 seconds; the receive thread exclusively holds the WebSocket receive call.
    void keepaliveThreadMain()
    {
        while (!stopRequested.load())
        {
            for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
            {
                if (stopRequested.load())
                {
                    break;
                }
                if (kSources[sourceIndex].enabledByDefault)
                {
                    sendSourcePing(sourceIndex);
                }
            }
            sleepUntilStop(stopRequested, kKeepalivePingIntervalMs);
        }
    }

    // isEventActiveLocked: explicitly ends upon cancellation; the final report is retained until source cancellation or 90 seconds of no updates, maintaining WindowsMarker semantics.
    bool isEventActiveLocked(const AggregatedEvent& event, ULONGLONG now) const
    {
        if (event.testEvent)
        {
            return now < event.testExpirationTick;
        }
        if (now >= event.lastUpdateTick && now - event.lastUpdateTick > kActiveNoUpdateTimeoutMs)
        {
            return false;
        }
        return activeSourceCount(event) > 0;
    }

    // pruneExpiredEventsLocked: Removes expired, test-expired, and all-source-terminated events to control memory usage and false alarms.
    void pruneExpiredEventsLocked(ULONGLONG now)
    {
        events.erase(std::remove_if(events.begin(), events.end(), [this, now](const AggregatedEvent& event) {
            return !isEventActiveLocked(event, now);
        }), events.end());
    }

    // activeSourceCount: calculates the number of non-cancelled sources; the final report only marks source status and will not terminate the alert early.
    int activeSourceCount(const AggregatedEvent& event) const
    {
        int count = 0;
        for (const SourceReading& reading : event.readings)
        {
            if (reading.present && !reading.canceled)
            {
                ++count;
            }
        }
        return count;
    }

    // maxActiveReportNumber: Returns the maximum report count from active sources to help users determine if a warning has been updated.
    int maxActiveReportNumber(const AggregatedEvent& event) const
    {
        int maximum = 0;
        for (const SourceReading& reading : event.readings)
        {
            if (reading.present && !reading.canceled)
            {
                maximum = std::max(maximum, reading.reportNum);
            }
        }
        return maximum;
    }

    // combinedReadingText: Merges the magnitude or depth of the current active source, deduplicates, and separates with slashes.
    QString combinedReadingText(const AggregatedEvent& event, bool magnitude) const
    {
        QStringList values;
        for (const SourceReading& reading : event.readings)
        {
            if (!reading.present || reading.canceled)
            {
                continue;
            }
            const double kValue = magnitude ? reading.magnitude : reading.depth;
            if (kValue <= 0.0)
            {
                continue;
            }
            const QString kText = QString::number(kValue, 'f', magnitude ? 1 : 0);
            if (!values.contains(kText))
            {
                values.push_back(kText);
            }
        }
        return values.join(QLatin1Char('/'));
    }

    // activeSourcesText: Concatenate all currently confirmed source names into a compact diagnostic text.
    QString activeSourcesText(const AggregatedEvent& event) const
    {
        QStringList names;
        for (int sourceIndex = 0; sourceIndex < kSourceCount; ++sourceIndex)
        {
            const SourceReading& reading = event.readings[sourceIndex];
            if (reading.present && !reading.canceled)
            {
                names.push_back(QLatin1String(kSources[sourceIndex].name));
            }
        }
        return names.join(QStringLiteral(" / "));
    }

    // postWarningChange: Queues state changes from the network thread to the owner's thread to avoid cross-thread Qt UI access.
    void postWarningChange()
    {
        TaskbarEarthquakeClient* target = owner;
        QMetaObject::invokeMethod(target, [target]() {
            emit target->activeWarningsChanged();
        }, Qt::QueuedConnection);
    }

    // postSourceStatusChange: Queues the connection status refresh to the GUI thread, ensuring the window can safely read the snapshot.
    void postSourceStatusChange()
    {
        TaskbarEarthquakeClient* target = owner;
        QMetaObject::invokeMethod(target, [target]() {
            emit target->sourceStatusesChanged();
        }, Qt::QueuedConnection);
    }

    // queueAudioForReport: Forward the report to the player in the sounds/ directory; do not copy or embed WindowsMarker audio resources.
    void queueAudioForReport(double magnitude, bool canceled)
    {
        if (!alertAudioEnabled || audioPlayer == nullptr)
        {
            return;
        }
        audioPlayer->enqueueReport(magnitude, canceled);
    }

    TaskbarEarthquakeClient* owner;          // External QObject for safe signal emission.
    std::atomic_bool started{ false };       // Idempotent protection for start/stop.
    std::atomic_bool stopRequested{ false }; // Background thread exit flag.
    std::array<SourceRuntime, kSourceCount> runtimes; // Thread and connection state per alert source.
    std::thread keepaliveThread;             // Unique keepalive sender thread; no race with receiver thread on send calls.
    mutable std::mutex eventsMutex;          // Protect merge and cleanup operations on events.
    QList<AggregatedEvent> events;           // Current and pending aggregated earthquake events.
    TaskbarEarthquakeAudioPlayer* audioPlayer; // Note: Play files sequentially from the 'sounds/' directory in the same folder as the exe.
    bool alertAudioEnabled = true;            // Disable audio queue playback after the earthquake switch is turned off.
};

TaskbarEarthquakeClient::TaskbarEarthquakeClient(QObject* parent)
    : QObject(parent)
    , private_(new Private(this))
{
    // reportReceived triggers optional audio queuing in the GUI thread; the network thread never touches Qt Multimedia objects.
    connect(this, &TaskbarEarthquakeClient::reportReceived, this,
        [this](double magnitude, bool canceled) {
            private_->queueAudioForReport(magnitude, canceled);
        });
}

TaskbarEarthquakeClient::~TaskbarEarthquakeClient()
{
    // Destruction order: stop all network threads first, then release private state and Qt Multimedia sub-objects.
    private_->stop();
    delete private_;
    private_ = nullptr;
}

void TaskbarEarthquakeClient::start()
{
    // Called once when the Taskbar starts; the client internally filters sources that are not enabled by default.
    private_->start();
}

void TaskbarEarthquakeClient::stop()
{
    // Called when the Taskbar process exits; this method can be explicitly invoked before destruction or handled by the destructor as a fallback.
    private_->stop();
}

QList<TaskbarEarthquakeEvent> TaskbarEarthquakeClient::activeWarnings() const
{
    // The list read by the UI is a deep-copy snapshot, so no dependency on the network thread or mutex is required after returning.
    return private_->warningsSnapshot();
}

QList<TaskbarEarthquakeSourceStatus> TaskbarEarthquakeClient::sourceStatuses() const
{
    // Connection diagnostics are also returned as a snapshot; the settings window does not hold long-term references to network thread states.
    return private_->statusesSnapshot();
}

void TaskbarEarthquakeClient::injectTestWarning()
{
    // The settings page button calls this path, using real event aggregation and alert theme logic without relying on external networks.
    private_->injectTestWarning();
}

void TaskbarEarthquakeClient::setAlertAudioEnabled(bool enabled)
{
    // Configure the window to reuse the earthquake notification switch for optional audio; remain silent if sounds/ does not exist.
    private_->setAlertAudioEnabled(enabled);
}
