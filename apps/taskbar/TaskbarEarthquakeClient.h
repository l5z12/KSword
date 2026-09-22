#pragma once

#include <QList>
#include <QObject>
#include <QString>

// TaskbarEarthquakeEvent represents an active earthquake warning merged by epicenter location.
// It only stores fields required for Taskbar display and notification scheduling, without carrying WindowsMarker rendering or audio resources.
struct TaskbarEarthquakeEvent
{
    QString locationKey;          // A stable key for merging the same epicenter across multiple warning sources.
    QString hypoCenter;           // Epicenter location text.
    QString originTime;           // Origin time.
    QString magnitudeText;        // Merged text for magnitudes from various sources.
    QString depthText;            // Merged text for depths from various sources.
    QString sourcesText;          // Confirm the source name of this warning.
    int reportNum = 0;            // Current maximum report count.
    int sourceCount = 0;          // Current number of sources not cancelled.
};

// TaskbarEarthquakeSourceStatus represents the real-time connection state of a WebSocket alert source.
struct TaskbarEarthquakeSourceStatus
{
    QString id;                   // Stable source identifier.
    QString name;                 // Set the window display name.
    bool enabled = false;         // Whether to start based on current configuration.
    bool connected = false;       // Whether the current WebSocket is connected.
    bool everConnected = false;   // Whether this process has successfully connected at least once.
    quint64 lastMessageAgeMs = 0; // Time since the most recent packet; 0 indicates no data received yet.
    quint64 latencyMs = 0;        // ping/pong round-trip latency; 0 indicates not yet measured.
};

// TaskbarEarthquakeClient maintains multiple earthquake-alert WebSocket connections in one process, using the same sources as WindowsMarker.
// Worker thread handles only network and state merging; all Qt signals are posted via the GUI thread.
class TaskbarEarthquakeClient : public QObject
{
    Q_OBJECT

public:
    // Constructor: accepts a QObject parent; initializes connection state without immediate network access.
    explicit TaskbarEarthquakeClient(QObject* parent = nullptr);

    // Destructor: stop the receiving thread and close the WebSocket to ensure no background threads access the freed object.
    ~TaskbarEarthquakeClient() override;

    // start: No input; starts the receive thread with the default source; repeated calls remain idempotent.
    void start();

    // stop: No input; closes the socket and waits for the receive thread to exit; safe to call repeatedly.
    void stop();

    // activeWarnings: No input; returns a GUI thread-safe snapshot of current active warnings.
    QList<TaskbarEarthquakeEvent> activeWarnings() const;

    // sourceStatuses: no input; returns connection diagnostic snapshots for each alert source.
    QList<TaskbarEarthquakeSourceStatus> sourceStatuses() const;

    // injectTestWarning: No input; broadcasts a 10-second local test alert without accessing the network.
    void injectTestWarning();

    // setAlertAudioEnabled: Enable or disable playback of audio files in the sounds/ directory; does not affect network reception or warning display.
    void setAlertAudioEnabled(bool enabled);

signals:
    // activeWarningsChanged: Emitted after the active warning set changes; the receiver re-reads activeWarnings().
    void activeWarningsChanged();

    // sourceStatusesChanged: emitted after a diagnostic refresh; the receiver re-reads sourceStatuses().
    void sourceStatusesChanged();

    // reportReceived: Emitted after receiving a valid earthquake report, used to select a prompt sound from the optional sounds/ audio queue.
    void reportReceived(double magnitude, bool canceled);

private:
    // Implementation details reside in the cpp file: network thread, message parsing, event aggregation, and state refresh timers are not exposed to the UI layer.
    class Private;
    Private* private_;           // Earthquake client private state owner.
};
