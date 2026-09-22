#pragma once

// ProgressDockWidget: The 'progress task card list' in the current operation panel.
// Control responsibility:
// 1) Periodically read the global kPro task snapshot.
// 2) Render each task as a card containing 'task name + step + progress bar'.
// 3) Automatically hide completed tasks (controlled by kPro.set(..., progress=1.0)).

#include "../Framework.h"

#include <QString>
#include <QWidget>

class QLabel;
class QScrollArea;
class QTimer;
class QVBoxLayout;

class ProgressDockWidget final : public QWidget
{
public:
    // Constructor purpose:
    // - initialize the scroll area and card container.
    // - Start the periodic refresh task card.
    // Parameter parent: Qt parent object.
    explicit ProgressDockWidget(QWidget* parent = nullptr);

    // refreshThemeVisuals:
    // - Reapply the current panel's background and text styles after a theme switch.
    // - Force rebuild the card to prevent the old QLabel from retaining old theme colors.
    void refreshThemeVisuals();

private:
    // initializeUi:
    // - Create the main layout, scroll container, and 'empty list hint'.
    void initializeUi();

    // applyTransparentBackgroundPolicy:
    // - Make the root control, scroll area, and viewport of the 'Current Operation' panel fully transparent;
    // - Prevent the default background color from appearing in the Dock content area.
    void applyTransparentBackgroundPolicy();

    // initializeRefreshTimer:
    // - Create timer;
    // - Determine whether to refresh based on the Revision.
    void initializeRefreshTimer();

    // refreshTaskCards:
    // - Fetch snapshots from kPro and rebuild the card view.
    // - Supports on-demand refresh (forceRefresh).
    // Parameter forceRefresh:
    // - true: force refresh
    // - Skip refresh if the false revision remains unchanged.
    void refreshTaskCards(bool forceRefresh);

    // clearCardLayout:
    // - Remove old cards to avoid memory leaks and clear the view.
    void clearCardLayout();

    // createTaskCardWidget:
    // - Create a card widget based on a single task item.
    // Parameter taskItem: task snapshot data.
    // Return value: Pointer to the newly created card QWidget (parent ownership managed by the layout).
    QWidget* createTaskCardWidget(const KProgressTask& taskItem) const;

    // buildHighContrastTextHex:
    // - Return high-contrast black/white text color based on the light/dark theme;
    // - Prevents gray text from becoming unreadable on a transparent background.
    // Return value: A color string directly writable to QSS.
    QString buildHighContrastTextHex() const;

    // buildCardBackgroundHex:
    // - Provide a lightweight semi-transparent background for borderless cards;
    // - Maintain text readability on the transparent Dock.
    // Return value: rgba string directly writable to QSS.
    QString buildCardBackgroundHex() const;

    // buildProgressBarStyleSheet:
    // - Unify progress bar style generation.
    // - Ensure text, track, and progress block remain clear in both light and dark themes.
    // Return value: QProgressBar stylesheet text.
    QString buildProgressBarStyleSheet() const;

    // retranslateUi purpose: Immediately rebuild empty state and in-progress task cards upon language switch.
    void retranslateUi();

protected:
    void changeEvent(QEvent* event) override;

private:
    QVBoxLayout* rootLayout_ = nullptr;        // Root layout.
    QScrollArea* scrollArea_ = nullptr;        // Scroll container.
    QWidget* scrollContent_ = nullptr;         // Root control for scroll content.
    QVBoxLayout* cardLayout_ = nullptr;        // Card vertical layout.
    QLabel* emptyTipLabel_ = nullptr;          // Label for the "No tasks available" tip.
    QTimer* refreshTimer_ = nullptr;           // Refresh timer.
    std::size_t lastRevision_ = 0;             // Revision at the last refresh.
};
