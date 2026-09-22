#pragma once

#include <QObject>
#include <QStringList>

#include <memory>

class QAudioOutput;
class QMediaPlayer;

// TaskbarEarthquakeAudioPlayer is responsible only for sequentially playing existing earthquake alert sounds in the sounds/ directory alongside Taskbar.exe.
// It does not embed or copy WindowsMarker audio resources; it remains silent automatically if the directory is missing or the file is incomplete.
class TaskbarEarthquakeAudioPlayer : public QObject
{
public:
    // Constructor: accepts a QObject parent; creates Qt Multimedia output without loading any sound files.
    explicit TaskbarEarthquakeAudioPlayer(QObject* parent = nullptr);

    // Destructor: Destroys the player before the audio output to ensure Qt Multimedia resources are released in dependency order.
    ~TaskbarEarthquakeAudioPlayer() override;

    // setEnabled: Toggles the alert sound; when disabled, it immediately stops the current sound and discards the waiting queue.
    void setEnabled(bool enabled);

    // enqueueReport: Selects a WindowsMarker WAV file with the same name based on magnitude; only includes files actually present in the sounds/ queue.
    void enqueueReport(double magnitude, bool canceled);

private:
    // startNext: Plays the file at the head of the queue; performs no operation if no files are available. The caller does not need to pre-check the sounds/ directory.
    void startNext();

    std::unique_ptr<QAudioOutput> audioOutput_; // Current audio output device.
    std::unique_ptr<QMediaPlayer> mediaPlayer_; // Qt Multimedia player for sequential WAV playback.
    QStringList pendingPaths_;                  // Absolute local WAV paths waiting to be played.
    bool enabled_ = true;                       // State switch to disable playback when earthquake notifications are off.
};
