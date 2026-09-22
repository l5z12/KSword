#pragma once

// NotificationCardManager: Unifies management of log notifications and task progress cards.
// - Read incremental snapshots from the global log/progress manager;
// - Layout the card to the monitor workspace or the main window Dock client area;
// - Ensure full click-through for areas other than the copy button.

#include "../Framework.h"
#include "../settings_dock/AppearanceSettings.h"

#include <QObject>

#include <cstddef>
#include <memory>
#include <vector>

class QWidget;
class QTimer;

namespace ks::ui
{
    class NotificationCard;
    struct NotificationCardRecord;

    class NotificationCardManager final : public QObject
    {
    public:
        NotificationCardManager(QWidget* mainWindow, QWidget* clientAnchor, QObject* parent = nullptr);
        ~NotificationCardManager() override;

        NotificationCardManager(const NotificationCardManager&) = delete;
        NotificationCardManager& operator=(const NotificationCardManager&) = delete;

        // applySettings: Apply latest notification preferences. Disabling immediately removes all cards; position and orientation changes trigger immediate reordering.
        void applySettings(const ks::settings::AppearanceSettings& settings);

        // refreshVisuals: Refreshes the color and transparent background of existing cards after a theme switch.
        void refreshVisuals();

        // onHostGeometryChanged: Recalculate card positions after the main window is moved, resized, minimized, or restored.
        void onHostGeometryChanged();

        // clearCards: Immediately remove all current log and progress cards.
        void clearCards();

        bool isProgressTaskOverflowed(int pid) const;
        QWidget* hostWindow() const;

    private:
        void refreshFromManagers();
        void refreshLogCards();
        void refreshProgressCards();
        void removeExpiredLogCards();
        void reflowCards(bool animate);
        void trimLogCardsToMaximum(bool animate);

        void appendLogCard(const KEvent& eventItem);
        void appendProgressCard(const KProgressTask& taskItem);
        void removeRecordAt(std::size_t index, bool animate);

        QWidget* mainWindow_ = nullptr;
        QWidget* clientAnchor_ = nullptr;
        QTimer* refreshTimer_ = nullptr;
        ks::settings::AppearanceSettings settings_;
        std::size_t lastLogRevision_ = 0;
        std::size_t knownLogCount_ = 0;
        std::size_t lastProgressRevision_ = 0;
        std::vector<std::unique_ptr<NotificationCardRecord>> cards_;
        std::vector<int> overflowProgressTaskIds_;
    };

    // For KProgress::UI to query: use a non-modal option dialog only when the corresponding progress card exceeds the area.
    bool isProgressTaskNotificationOverflowed(int pid);
    QWidget* notificationCardHostWindow();
}
