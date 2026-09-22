#include "TaskbarEarthquakeAudioPlayer.h"

#include <QAudioOutput>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMediaPlayer>
#include <QUrl>

namespace
{
    // runtimeSoundsDirectory: No input; concatenates sounds directory alongside Taskbar.exe; returns the unique runtime audio directory allowed for reading.
    QString runtimeSoundsDirectory()
    {
        const QDir kApplicationDirectory(QCoreApplication::applicationDirPath());
        return kApplicationDirectory.filePath(QStringLiteral("sounds"));
    }

    // filesForMagnitude: input is magnitude; selects WAV filenames following the WindowsMarker naming rule for sequential playback; returns candidate list.
    QStringList filesForMagnitude(double magnitude)
    {
        QStringList candidates;
        if (magnitude > 0.0)
        {
            if (magnitude < 3.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_3_0.wav"));
            }
            else if (magnitude < 4.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_3_5.wav"));
            }
            else if (magnitude < 4.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_4_0.wav"));
            }
            else if (magnitude < 5.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_4_5.wav"));
            }
            else if (magnitude < 5.5)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_5_0.wav"));
            }
            else if (magnitude < 6.0)
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_5_5.wav"));
            }
            else
            {
                candidates.push_back(QStringLiteral("earthquake_magnitude_6_0_plus.wav"));
            }
        }

        const QString kReceivedFile = magnitude >= 6.0
            ? QStringLiteral("earthquake_message_received_magnitude_6_0_plus.wav")
            : QStringLiteral("earthquake_message_received.wav");
        candidates.push_back(kReceivedFile);
        return candidates;
    }
}

TaskbarEarthquakeAudioPlayer::TaskbarEarthquakeAudioPlayer(QObject* parent)
    : QObject(parent)
    , audioOutput_(std::make_unique<QAudioOutput>())
    , mediaPlayer_(std::make_unique<QMediaPlayer>())
{
    // The audio output and player belong exclusively to this object; they are explicitly released in dependency order (player then output) during destruction.
    audioOutput_->setVolume(0.85f);
    mediaPlayer_->setAudioOutput(audioOutput_.get());
    connect(mediaPlayer_.get(), &QMediaPlayer::mediaStatusChanged, this,
        [this](QMediaPlayer::MediaStatus status) {
            if (status == QMediaPlayer::EndOfMedia || status == QMediaPlayer::InvalidMedia)
            {
                startNext();
            }
        });
}

TaskbarEarthquakeAudioPlayer::~TaskbarEarthquakeAudioPlayer()
{
    // First release the player's reference to the output, then release the audio output to avoid accessing an invalid device during Qt Multimedia's destruction phase.
    mediaPlayer_.reset();
    audioOutput_.reset();
}

void TaskbarEarthquakeAudioPlayer::setEnabled(bool enabled)
{
    // Immediately stop playback and clear the waiting queue when switching to disabled to avoid playing stale reports upon re-enabling.
    if (enabled_ == enabled)
    {
        return;
    }

    enabled_ = enabled;
    if (!enabled_)
    {
        pendingPaths_.clear();
        mediaPlayer_->stop();
        mediaPlayer_->setSource(QUrl());
    }
}

void TaskbarEarthquakeAudioPlayer::enqueueReport(double magnitude, bool canceled)
{
    // Cancelled reports and closed states remain silent; resources outside the directory, embedded, and WindowsMarker are never used as fallback sources.
    if (!enabled_ || canceled)
    {
        return;
    }

    const QDir kSoundsDirectory(runtimeSoundsDirectory());
    const QStringList kCandidates = filesForMagnitude(magnitude);
    for (const QString& fileName : kCandidates)
    {
        const QString absolutePath = kSoundsDirectory.filePath(fileName);
        const QFileInfo fileInfo(absolutePath);
        if (fileInfo.isFile())
        {
            pendingPaths_.push_back(absolutePath);
        }
    }

    // When the directory is empty or the corresponding file is missing, there is no queue content; remain silent and do not report errors to avoid affecting WebSocket reception.
    if (mediaPlayer_->playbackState() != QMediaPlayer::PlayingState)
    {
        startNext();
    }
}

void TaskbarEarthquakeAudioPlayer::startNext()
{
    // Consume one item at a time; recursively advance to the next upon EndOfMedia to prevent multiple warning tones from playing simultaneously.
    if (!enabled_ || pendingPaths_.isEmpty())
    {
        return;
    }

    const QString kNextPath = pendingPaths_.takeFirst();
    mediaPlayer_->setSource(QUrl::fromLocalFile(kNextPath));
    mediaPlayer_->play();
}
