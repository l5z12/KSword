#pragma once

// ============================================================
// DisableDsePage.h
// Purpose:
// 1) Provides a Driver Signature Enforcement (DSE) toggle in the 'Misc' section for temporarily loading unsigned drivers;
// 2) Display CI / HVCI / Secure Boot posture, and block non-compliant cases before the button;
// 3) Locate CI.dll!g_CiOptions and display the full resolution trace for the user to verify address trustworthiness.
// 4) Record the original value before disabling to provide one-click restoration; if the page is still in the disabled state during destruction, it will automatically write back.
//
// Risk note: g_CiOptions is monitored by PatchGuard; keeping it modified for a long time triggers a
// CRITICAL_STRUCTURE_CORRUPTION BSOD. This page's logic is derived from runtime disassembly. Before
// writing, we verify that the forced signature bit of the read-back value is consistent with the system's
// self-reported status, but users must restore the original state immediately after loading the driver.
// ============================================================

#include "DisableDseBackend.h"

#include "../../Framework.h"

#include <QWidget>

#include <cstdint>

class QLabel;
class QPushButton;
class QShowEvent;
class CodeEditorWidget;

namespace ks::misc
{
    // DisableDsePage：
    // - Purpose: DSE toggle page; the only system modification is the 4 bytes of CI.dll!g_CiOptions;
    // - Note: This page loads no third-party vulnerable drivers; all kernel access uses KswordARK's native R0 transaction channel.
    class DisableDsePage final : public QWidget
    {
    public:
        // Constructor: builds only the UI, does not access the driver, avoiding a kernel query when 'Misc' is opened.
        explicit DisableDsePage(QWidget* parent = nullptr);
        // Destructor: If DSE was disabled on this page and has not yet been restored, perform a final write-back
        // here to prevent PatchGuard from flagging kernel data tampering if the user forgets to restore it.
        ~DisableDsePage() override;

    protected:
        // Read system posture only once when the page becomes truly visible for the first time.
        void showEvent(QShowEvent* event) override;
        // Semantic colors (Error/Warning and their backgrounds) have no palette equivalent in theme.h. Writing them into
        // QSS fixes them to the theme at the moment of distribution, requiring re-distribution upon theme switching.
        void changeEvent(QEvent* event) override;

    private:
        // initializeUi: builds the risk banner, posture area, positioning area, and operation area.
        void initializeUi();
        // applyBannerStyle: Pushes the risk banner style; constructed during initialization and theme switching.
        void applyBannerStyle();
        // initializeConnections: connect the four buttons to their respective handler functions.
        void initializeConnections();

        // refreshPosture: Synchronously query CI/HVCI posture and refresh it to the UI.
        void refreshPosture();
        // runLocate: Locate g_CiOptions on a background thread and immediately read back to verify upon success.
        void runLocate();
        // runApply: Write g_CiOptions to desiredValue in a background thread.
        //   isRestore affects only the message text and status accounting; the write path is identical.
        void runApply(std::uint32_t desiredValue, bool isRestore);

        // LocateOutcome: Combined result of a locate operation plus read-back validation; passed only between threads.
        struct LocateOutcome
        {
            disable_dse::TargetLocation location;      // location: Location result.
            disable_dse::ReadbackResult readback;      // readback: Readback result after successful location.
            disable_dse::CodeIntegrityPosture posture; // posture: The system posture used as the basis for consistency determination.
            bool valueMatched = false;                 // valueMatched: Whether the read-back value is consistent with the system state.
        };

        // applyLocateOutcome: Collates locate results on the UI thread.
        void applyLocateOutcome(const LocateOutcome& outcome);
        // applyApplyOutcome: Consolidate and write results on the UI thread.
        void applyApplyOutcome(const disable_dse::ApplyResult& result, bool isRestore);

        // appendTrace: Appends a line of diagnostic information to the trace box.
        void appendTrace(const QString& line);
        // setResultText: writes the conclusion of an operation to the bottom; isError determines the color scheme.
        void setResultText(const QString& text, bool isError);
        // setBusy: Disable buttons while an operation is in progress to prevent repeated clicks.
        void setBusy(bool busy);
        // updateButtons: Refresh button availability based on busy state, posture, and positioning results.
        void updateButtons();
        // updateStateDisplay: Refreshes the posture summary, block reason, and current value display.
        void updateStateDisplay();

    private:
        QLabel* warningLabel_ = nullptr;       // m_warningLabel: PatchGuard risk banner.
        QLabel* postureLabel_ = nullptr;       // m_postureLabel: CI / HVCI / Secure Boot summary.
        QLabel* optionsLabel_ = nullptr;       // m_optionsLabel: CodeIntegrityOptions bit decomposition.
        QLabel* blockLabel_ = nullptr;         // m_blockLabel: Reason why the operation is currently not allowed.
        QLabel* locationLabel_ = nullptr;      // m_locationLabel: Summary of g_CiOptions location results.
        QLabel* pendingLabel_ = nullptr;       // m_pendingLabel: Prominent notice when not yet restored.
        QLabel* resultLabel_ = nullptr;        // m_resultLabel: Conclusion of the most recent operation.
        CodeEditorWidget* traceEdit_ = nullptr; // m_traceEdit: Locates traces and transaction logs.
        QStringList traceLines_;               // m_traceLines: Retain Chinese source text to support repainting after runtime language switching.
        QPushButton* refreshButton_ = nullptr; // m_refreshButton: Re-query system posture.
        QPushButton* locateButton_ = nullptr;  // m_locateButton: Locate g_CiOptions and read back for verification.
        QPushButton* disableButton_ = nullptr; // m_disableButton: Disables Driver Signature Enforcement.
        QPushButton* restoreButton_ = nullptr; // m_restoreButton: Button to restore g_CiOptions to its original value.

        disable_dse::CodeIntegrityPosture posture_; // m_posture: The posture retrieved in the most recent query.
        disable_dse::TargetLocation location_;      // m_location: Most recent location result.

        std::uint32_t currentValue_ = 0;      // m_currentValue: Last read-back value of g_CiOptions.
        bool hasCurrentValue_ = false;        // m_hasCurrentValue: Whether m_currentValue is valid.
        std::uint32_t savedOriginalValue_ = 0;// m_savedOriginalValue: The original value before disabling DSE on this page.
        bool hasSavedOriginal_ = false;       // m_hasSavedOriginal: Flag indicating whether the original value to be restored has been recorded.
        bool valueMatched_ = false;           // m_valueMatched: Whether the read-back value matches the system-reported value; write is disabled if false.
        bool busy_ = false;                   // m_busy: Background operation in progress.

        // m_blockReason：
        // - The most recently computed admission decision: refreshed in updateStateDisplay and consumed in updateButtons;
        // - Cached to avoid opening a driver device handle every time the button is refreshed.
        disable_dse::BlockReason blockReason_ = disable_dse::BlockReason::kDriverUnavailable;
    };
}
