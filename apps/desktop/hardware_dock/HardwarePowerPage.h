#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QByteArray>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QGroupBox;
class QLabel;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QTableWidget;

// HardwarePowerPage: A separate page for Windows power schemes and controlled R0 CPU power management.
class HardwarePowerPage final : public QWidget
{
public:
    explicit HardwarePowerPage(QWidget* parent = nullptr);

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void initializeConnections();
    void refreshAll();
    void refreshPowerSchemes();
    void applySelectedPowerScheme();
    void restoreInitialState();
    void refreshCpuPower();
    void applySnapshotToUi(const ksword::ark::CpuPowerResult& result);
    void updateControlAvailability();
    void setStatus(const QString& text, bool isError = false);
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST buildControlRequest(
        unsigned long applyFlags) const;
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST buildRestoreControlRequest(
        unsigned long applyFlags) const;
    unsigned long restorableCpuApplyFlags() const;
    bool executeControlRequest(
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request);
    void sendControlRequest(
        unsigned long applyFlags,
        const QString& confirmationText);
    void raisePowerLimitsToPlatformMaximum();

    bool loadedOnce_ = false;                        // m_loadedOnce: Automatically refresh once upon first display.
    bool hasSnapshot_ = false;                       // m_hasSnapshot: Indicates if the expected raw MSR is valid.
    KSWORD_ARK_CPU_POWER_RESPONSE snapshot_{};       // m_snapshot: Snapshot of the most recent locked R0.
    bool hasRestoreCpuSnapshot_ = false;             // m_hasRestoreCpuSnapshot: Whether the first valid CPU snapshot has been captured.
    KSWORD_ARK_CPU_POWER_RESPONSE restoreCpuSnapshot_{}; // m_restoreCpuSnapshot: One-click restore target.
    QByteArray restorePowerSchemeGuid_;               // m_restorePowerSchemeGuid: First active Windows power scheme.

    QLabel* statusLabel_ = nullptr;                  // m_statusLabel: Page operation and error status.
    QComboBox* powerSchemeCombo_ = nullptr;          // m_powerSchemeCombo: Available Windows power schemes.
    QPushButton* refreshAllButton_ = nullptr;        // m_refreshAllButton: Refresh both the scheme and R0 simultaneously.
    QPushButton* applyPowerSchemeButton_ = nullptr;  // m_applyPowerSchemeButton: Activates the selected scheme.
    QPushButton* restoreInitialStateButton_ = nullptr; // m_restoreInitialStateButton: Restore the initial capture state.
    QTableWidget* snapshotTable_ = nullptr;          // m_snapshotTable: Summary of CPU capabilities and current values.

    QDoubleSpinBox* pl1Spin_ = nullptr;              // m_pl1Spin: PL1 long-term power consumption (W).
    QDoubleSpinBox* pl2Spin_ = nullptr;              // m_pl2Spin: PL2 short-term power consumption in watts.
    QCheckBox* pl1EnableCheck_ = nullptr;            // m_pl1EnableCheck: Enable PL1.
    QCheckBox* pl1ClampCheck_ = nullptr;             // m_pl1ClampCheck: Allow PL1 clamp.
    QCheckBox* pl2EnableCheck_ = nullptr;            // m_pl2EnableCheck: Enable PL2.
    QCheckBox* pl2ClampCheck_ = nullptr;             // m_pl2ClampCheck: Allow PL2 clamp.
    QPushButton* applyPowerLimitsButton_ = nullptr;  // m_applyPowerLimitsButton: Submits PL1/PL2.
    QPushButton* raisePowerLimitsButton_ = nullptr;  // m_raisePowerLimitsButton: Raise to SKU maximum.

    QCheckBox* turboEnableCheck_ = nullptr;           // m_turboEnableCheck: Target for the Turbo switch.
    QPushButton* applyTurboButton_ = nullptr;         // m_applyTurboButton: Submit Turbo switch button.
    QSpinBox* turboRatioSpin_ = nullptr;              // m_turboRatioSpin: Target ratios for all implemented steps.
    QPushButton* applyTurboRatioButton_ = nullptr;    // m_applyTurboRatioButton: Submit Turbo Ratio button.
    QSpinBox* requestedMultiplierSpin_ = nullptr;     // m_requestedMultiplierSpin: IA32_PERF_CTL requested multiplier.
    QPushButton* applyRequestedMultiplierButton_ = nullptr; // m_applyRequestedMultiplierButton: Submits the requested multiplier.

    QSpinBox* hwpMinimumSpin_ = nullptr;              // m_hwpMinimumSpin：HWP minimum performance。
    QSpinBox* hwpMaximumSpin_ = nullptr;              // m_hwpMaximumSpin：HWP maximum performance。
    QSpinBox* hwpDesiredSpin_ = nullptr;              // m_hwpDesiredSpin: HWP desired value (0 = automatic).
    QSpinBox* hwpEppSpin_ = nullptr;                  // m_hwpEppSpin: HWP EPP, 0 for performance/255 for energy saving.
    QPushButton* applyHwpButton_ = nullptr;           // m_applyHwpButton: Button to submit HWP for all logical processors.
};
