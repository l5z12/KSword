#ifndef TASKBAR_H
#define TASKBAR_H

#include "SpectrumWidget.h"
#include "TaskbarSharedState.h"
#include "TaskbarNotificationService.h"

#include <QMainWindow>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTimer>
#include <QString>
#include <QRect>
#include <QColor>
#include <QPixmap>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QList>
#include <functional>
#include <windows.h>
#include <shellapi.h>
#include <QCloseEvent>
#include <qpushbutton.h>
#include <cstdint>

class QScreen;
class QStackedLayout;
class QVariantAnimation;
class QResizeEvent;
class TaskbarSettingsDialog;
class GlowIconButton;

#pragma comment(lib, "shell32.lib")

class Taskbar : public QMainWindow
{
    Q_OBJECT

public:
    explicit Taskbar(QScreen* targetScreen, TaskbarSharedState* sharedState,
        TaskbarNotificationService* notificationService, QWidget* parent = nullptr);
    ~Taskbar() override;

private:
    SpectrumWidget* leftSpectrum_;      // Left spectrum component
    SpectrumWidget* rightSpectrum_;     // Right spectrum widget.
    TaskbarSharedState* sharedState_;   // Audio, CPU, and network sampling state shared across multiple windows
    TaskbarNotificationService* notificationService_; // Shared notification service and earthquake alert status across multiple windows.
    QRect targetScreenGeometry_;        // Target display rectangle bound when the current window starts.
    QString targetScreenName_;          // Qt screen name used to match the corresponding Win32 monitor.
    qreal targetDevicePixelRatio_;      // Scale factor used when converting Qt DIP geometry to native pixels.

    QWidget* cpuBarContainer_;            // CPU bar chart container
    QVector<QLabel*> cpuBars_;            // Collection of CPU per-core bars.
    QTimer* timer_;                       // Time refresh timer
    QLabel* timeLabel_;                   // Time text label
    QLabel* contentLabel_;                // Left-side current username text; in alert state, it synchronously turns white like other Taskbar text.
    QLabel* logoLabel_;                   // Left-side logo label.
    QPixmap logoPixmap_;                  // Original left-side logo image, preserving the alpha channel for alert-state coloring.

    QWidget* networkSpeedContainer_;      // Network speed display container
    QLabel* uploadSpeedLabel_;            // Upload speed text label.
    QLabel* downloadSpeedLabel_;          // Download speed text label.
    QTimer* networkUiTimer_;              // UI label refresh timer.

    bool isAppBarRegistered_;             // Whether ABM_NEW is already registered.

    QWidget* centralWidget_;
    QWidget* normalCenterWidget_;         // The normal central page for saving spectrum and clock data.
    QWidget* notificationCenterWidget_;   // Notification center page displaying source, title, and body.
    QStackedLayout* centerStackLayout_;   // Use StackAll to allow cross-fading between the two pages.
    QGraphicsOpacityEffect* normalCenterOpacity_; // Normal center page opacity effect.
    QGraphicsOpacityEffect* notificationCenterOpacity_; // Opacity effect for the notification center page.
    QLabel* notificationSourceLabel_;     // Notification source short text.
    QLabel* notificationTitleLabel_;      // Notification title text.
    QLabel* notificationBodyLabel_;       // Notification body text.
    QList<QPropertyAnimation*> centralAnimations_; // All opacity animations for the current central area.
    TaskbarNotificationView displayedNotification_; // Rendered notification; used to ignore duplicate refreshes.
    bool notificationVisible_;             // Whether the central area has switched to the notification page.
    bool earthquakePresentation_;          // Whether the central area is currently taken over by earthquake warning without fade-in.
    QVariantAnimation* alertFlashAnimation_; // A 500ms gradient animation from bright red to dark red during the earthquake.
    bool alertFlashBright_;                   // Current flash phase; true indicates a momentary switch to a bright red background.
    QWidget* notificationFlashWidget_;       // A subtle highlight layer covering the entire Taskbar when a new message is generated.
    QGraphicsOpacityEffect* notificationFlashOpacity_; // Opacity effect for the highlight layer.
    QPropertyAnimation* notificationFlashAnimation_;  // A 500ms animation fading the highlight layer from bright to dark.

    QWidget* rightBtnContainer_;          // Right-side button group container
    QHBoxLayout* rightBtnLayout_;         // Right-side button group layout

    QPushButton* exitBtn_;                // Exit button
    GlowIconButton* lockBtn_;              // Lock workstation icon button.
    GlowIconButton* toolBtn_;              // Icon button to open Command Prompt.
    GlowIconButton* settingsBtn_;          // Open the notification settings icon button.
    GlowIconButton* userBtn_;              // Reserved user extension icon button.
    TaskbarSettingsDialog* settingsDialog_; // Non-modal settings window for the current display.

    // AppBar registration and system message handling.
    // AppBar thickness helper: no input; converts logical window height to native pixels; returns pixel height.
    int appBarThicknessInNativePixels() const;

    // Target monitor helper: no input; resolves the Win32 monitor rectangle; returns native pixel geometry.
    QRect targetScreenNativeGeometry() const;

    // Target logical geometry helper: no input; resolves the Qt screen rectangle used for QWidget placement; returns logical coordinates.
    QRect targetScreenLogicalGeometry() const;

    // Spectrum minimum width helper: no input; adapts to logical screen width; returns a Qt DIP width.
    int spectrumMinimumWidthForScreen() const;

    // Spectrum maximum width helper: no input; caps elastic spectrum width; returns a Qt DIP width.
    int spectrumMaximumWidthForScreen() const;

    void registerAsAppBar();
    void removeAppBar();
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;
    UINT appBarMessageId_;
    QTimer* cpuUpdateTimer_;

    // Auxiliary logic related to sampling and display.
    QString formatNetworkSpeed(std::uint64_t bytesPerSecond) const;
    void updateNetworkSpeedLabels();
    void updateNotificationPresentation();
    void updateNotificationText(const TaskbarNotificationView& notification);
    void transitionToNotification(const TaskbarNotificationView& notification);
    void transitionToNormalCenter();
    void showEarthquakePresentation(const TaskbarNotificationView& notification);
    void animateOpacity(QGraphicsOpacityEffect* effect, qreal startOpacity, qreal endOpacity,
        const std::function<void()>& completed);
    void stopCentralAnimations();
    void applyTaskbarTheme(bool earthquakeAlert, const QColor& backgroundColor);
    void startAlertFlashCycle();
    void flashNotificationBackground();
    void showSettingsDialog();

protected:
    // Ensure AppBar deregistration and safe background thread termination on window close.
    void closeEvent(QCloseEvent* event) override;
    // Synchronize the coverage range of the entire Taskbar highlight layer when the window size changes.
    void resizeEvent(QResizeEvent* event) override;

private slots:
    void onSpectrumDataReady(const QVector<float>& spectrumData);
    void onExitClicked();
    void updateTime();
    void updateCPUUsage();
    void onNotificationPresentationChanged();
};

#endif
