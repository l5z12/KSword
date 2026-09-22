#pragma once
#include "../../../../shared/ark_client/ArkDriverTypes.h"

#include "../../Framework.h"

#include <QWidget>

class QCheckBox;
class QLabel;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    // An opt-in BugCheck switch with persistent ignore mode. HVCI systems use a callback
    // backend; other systems may use the KeBugCheckEx entry hook. The page
    // never claims that either backend is a crash recovery mechanism.
    class BugcheckGuardPage final : public QWidget
    {
    public:
        explicit BugcheckGuardPage(QWidget* parent = nullptr);
        ~BugcheckGuardPage() override = default;

    protected:
        void showEvent(QShowEvent* event) override;
        // Semantic colors (Warning/Error and their backgrounds) have no palette equivalent in theme.h; writing them to QSS
        // hardcodes them to the theme at the time of distribution. When the theme changes, they must be redistributed; otherwise,
        // this risk banner may become unreadable (e.g., dark text on a dark background or light text on a light background).
        void changeEvent(QEvent* event) override;

    private:
        void initializeUi();
        void applyWarningBannerStyle();
        void refreshStatus();
        void enableGuard();
        void disableGuard();
        void pollForScreenshot();
        void attemptScreenshot();
        void updateFromResponse(
            const KSWORD_ARK_BUGCHECK_GUARD_RESPONSE& response);
        void updateButtons();
        void setBusy(bool busy);

        QLabel* warningLabel_ = nullptr;
        QLabel* persistenceLabel_ = nullptr;
        QLabel* delayLabel_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QLabel* detailLabel_ = nullptr;
        QSpinBox* delaySpin_ = nullptr;
        QCheckBox* tryIgnoreErrorCheck_ = nullptr;
        QCheckBox* screenshotOnTriggerCheck_ = nullptr;
        QCheckBox* acknowledgeCheck_ = nullptr;
        QPushButton* refreshButton_ = nullptr;
        QPushButton* enableButton_ = nullptr;
        QTimer* screenshotPollTimer_ = nullptr;
        ksword::ark::DriverHandle screenshotDriverHandle_;
        bool supported_ = false;
        bool active_ = false;
        bool busy_ = false;
        bool triggered_ = false;
        bool hvciEnabled_ = false;
        bool callbackBackend_ = false;
        bool screenshotWatcherArmed_ = false;
        bool screenshotAttempted_ = false;
        bool screenshotInputAccepted_ = false;
    };
}
