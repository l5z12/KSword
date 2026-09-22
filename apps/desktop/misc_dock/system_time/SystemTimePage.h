#pragma once

// ============================================================
// SystemTimePage.h
// Purpose:
// 1) Provides global system acceleration, deceleration, and recovery entry points under 'miscellaneous'.
// 2) Queries and controls R0 timer remapping via ArkDriverClient.
// 3) Continuously display high-risk warnings, takeover status, and conflict diagnostics.
// ============================================================

#include "../../Framework.h"

#include <QElapsedTimer>
#include <QWidget>

class QCheckBox;
class QHideEvent;
class QLabel;
class QProcess;
class QPushButton;
class QRadioButton;
class QShowEvent;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    class SystemTimePage final : public QWidget
    {
    public:
        // Constructor: creates the page without actively accessing R0 to avoid triggering a driver prompt when opening 'Misc'.
        explicit SystemTimePage(QWidget* parent = nullptr);
        ~SystemTimePage() override = default;

    protected:
        // Query and poll status only when the page is truly visible; stop periodic IOCTLs after hiding.
        void showEvent(QShowEvent* event) override;
        void hideEvent(QHideEvent* event) override;
        // Semantic colors (Warning and its background) have no palette equivalent in theme.h; writing them to QSS
        // locks them to the theme at the moment of application. When switching themes, they must be reapplied;
        // otherwise, this permanent warning becomes unreadable (dark text on black or light text on white).
        void changeEvent(QEvent* event) override;

    private:
        // initializeUi: Create the permanent warning banner, multiplier controls, confirmation switch, and status evidence area.
        void initializeUi();
        // applyWarningBannerStyle: Dispatches a permanent warning banner style, shared between construction and theme switching.
        void applyWarningBannerStyle();
        // initializeConnections: Refresh, apply, restore, and periodic status queries.
        void initializeConnections();
        // refreshStatus: Retrieves the latest multiplier, generation, and takeover status via ArkDriverClient.
        void refreshStatus();
        // applyRequestedMode: Applies the current acceleration or deceleration rate after dual confirmation.
        void applyRequestedMode();
        // resetSystemTime: Stops variable speed without additional thresholds and maintains 1x with continuous counting.
        void resetSystemTime();
        // synchronizeFromTimeServer: Asynchronously requests immediate time synchronization via the Windows Time Service.
        void synchronizeFromTimeServer();
        // completeTimeSynchronization: Consolidate w32tm success, failure, and timeout results.
        void completeTimeSynchronization(
            QProcess* process,
            bool success,
            const QString& detailText);
        // resetCalibratedClock: Rebuild the rate calibration anchor using the current system wall clock.
        void resetCalibratedClock();
        // updateCalibratedTimeDisplay: Reverse-corrects QPC elapsed time based on the current multiplier.
        void updateCalibratedTimeDisplay();
        // confirmHighRisk: Displays the selected plan and risk list, requiring a fixed confirmation phrase.
        bool confirmHighRisk(
            const QString& modeText,
            const QString& backendText,
            const QString& schemeText,
            unsigned long factor);
        // updateStatusDisplay: converts protocol fields into user-readable status and diagnostic evidence.
        void updateStatusDisplay(
            unsigned long status,
            unsigned long stateFlags,
            unsigned long generation,
            unsigned long command,
            unsigned long factor,
            unsigned long osBuildNumber,
            long lastStatus,
            unsigned long resolutionMode,
            unsigned long backend,
            unsigned long long counterSourceAddress,
            unsigned long long primarySlotAddress,
            unsigned long long secondarySlotAddress,
            unsigned long long hypervisorSharedPageAddress,
            unsigned long long hypervisorTimeUpdateLock,
            unsigned long long hypervisorOriginalMultiplier,
            unsigned long long hypervisorOriginalBias,
            unsigned long long hypervisorCurrentMultiplier,
            unsigned long long hypervisorCurrentBias);
        // updateButtons: Update buttons based on busy status, protocol support, and risk confirmation state.
        void updateButtons();
        // setBusy: Prevents repeated clicks while a synchronous IOCTL is not yet complete.
        void setBusy(bool busy);

    private:
        QLabel* warningLabel_ = nullptr; // m_warningLabel: Permanent system instability warning.
        QLabel* persistenceLabel_ = nullptr; // m_persistenceLabel: Note explaining that the state is not automatically restored upon leaving the page.
        QLabel* currentModeLabel_ = nullptr; // m_currentModeLabel: Current 1x/acceleration/deceleration status.
        QLabel* calibratedTimeLabel_ = nullptr; // m_calibratedTimeLabel: Wall-clock time after reverse calibration by scale factor.
        QLabel* backendLabel_ = nullptr; // m_backendLabel: Build and parse policy summary.
        QLabel* diagnosticLabel_ = nullptr; // m_diagnosticLabel: Slot address and NTSTATUS evidence.
        QLabel* operationLabel_ = nullptr; // m_operationLabel: Latest refresh or control result.
        QRadioButton* hypervBackendRadio_ = nullptr; // m_hypervBackendRadio: Selects the Hyper-V shared QPC backend.
        QRadioButton* halBackendRadio_ = nullptr; // m_halBackendRadio: Select the original HAL-compatible backend.
        QRadioButton* compatRadio_ = nullptr; // m_compatRadio: Radio button to select compatibility positioning mode.
        QRadioButton* guardedResolutionRadio_ = nullptr; // m_guardedResolutionRadio: Select enhanced verification positioning.
        QRadioButton* speedUpRadio_ = nullptr; // m_speedUpRadio: Selects N-times acceleration.
        QRadioButton* slowDownRadio_ = nullptr; // m_slowDownRadio: Select 1/N slowdown.
        QSpinBox* factorSpin_ = nullptr; // m_factorSpin: Multiplier input ranging from 2 to the protocol limit.
        QCheckBox* acknowledgeCheck_ = nullptr; // m_acknowledgeCheck: Persistent risk acknowledgment switch.
        QPushButton* refreshButton_ = nullptr; // m_refreshButton: Iconified status refresh button.
        QPushButton* timeSyncButton_ = nullptr; // m_timeSyncButton: Immediately updates the time from a Windows time server.
        QPushButton* applyButton_ = nullptr; // m_applyButton: Apply the selected mode and rate.
        QPushButton* resetButton_ = nullptr; // m_resetButton: Emergency recovery 1x.
        QTimer* refreshTimer_ = nullptr; // m_refreshTimer: Status poller when the page is visible.
        QTimer* clockTimer_ = nullptr; // m_clockTimer: Refresh calibration time when the page is visible.
        QProcess* timeSyncProcess_ = nullptr; // m_timeSyncProcess: The current asynchronous w32tm process.
        QElapsedTimer calibratedElapsedTimer_; // m_calibratedElapsedTimer: QPC elapsed time affected by global speed multiplier.
        qint64 calibratedAnchorEpochMs_ = 0; // m_calibratedAnchorEpochMs: Local wall-clock milliseconds at the calibration anchor point.
        unsigned long generation_ = 0UL; // m_generation: Concurrency control generation of the most recent query.
        unsigned long calibrationGeneration_ = ~0UL; // m_calibrationGeneration: Generation corresponding to the calibration anchor point.
        unsigned long currentCommand_ = 0UL; // m_currentCommand: Current speed command used for calibration.
        unsigned long currentFactor_ = 1UL; // m_currentFactor: current multiplier used for calibration.
        unsigned long currentBackend_ = 0UL; // m_currentBackend: R0 current or default backend.
        bool active_ = false; // m_active: Whether R0 currently owns the counter slot.
        bool supported_ = false; // m_supported: Whether R0 currently parses and supports this feature.
        bool hypervAvailable_ = false; // m_hypervAvailable: Whether Microsoft Hv and the shared QPC page are both available.
        bool busy_ = false; // m_busy: Prevent duplicate operations during synchronization control.
    };
}
