#pragma once

// KvmDock: Top-level feature page for KSwordVM (R-1 / hypervisor layer).
//
// The reason for existence is not "moving VT-x/EPT pages". This capability was previously split into two disconnected halves:
// - Right-click menu for the KVM button in the title bar: persistent start/stop, keep self-test,
//   prepare/release resources, plus six R-1 panels for View/Memory/MSR/CR/Domain/Events;
// - KernelDock's "VT-x/EPT" page: PREPARE, SELF_TEST, one-time
//   guest, TEARDOWN, and EPT rules (the only path to reach EPT rules).
// There are zero cross-references on both sides, creating an unavoidable dead path: the View, MSR, CR, and Domain panels all
// require 'resources prepared but not resident'. However, the only action available in the right-click menu, 'Start Resident',
// prepares the resources and immediately enters the resident state within the same call. Consequently, the four panels jump
// directly from 'not yet prepared' to 'cannot modify during resident state', skipping the only available window in the UI.
//
// Therefore, this page performs three tasks:
// - Consolidate the two halves of the entry into a single screen (keep the right-click menu unchanged to preserve muscle memory for existing users);
// - Show the lifecycle order: prepare resources -> install views / policies / domains -> start the resident hypervisor;
// - When a button is grayed out, indicate which step it is waiting for, rather than just showing a gray button.
//
// No business logic resides here: control commands are passed verbatim to the same implementation used by the right-click
// menu in mainWindow.Kvm.cpp (including confirmDestructiveAction for high-risk confirmation); status retrieval follows
// ksword::kvm facade. This page only defines the sequence and preconditions.

#include <QString>
#include <QWidget>

#include <functional>

class QHideEvent;
class QLabel;
class QPushButton;
class QShowEvent;
class QTimer;
class QTabWidget;
class KvmGuestVmPanel;
class KvmWatchPanel;

class KernelHvmTab;

namespace ksword::kvm
{
    struct KvmState;
}

class KvmDock final : public QWidget
{
public:
    // Action: All requests that can be issued from this page, with each one corresponding to an item in the right-click menu.
    enum class Action
    {
        kToggleResident,
        kSoak,
        kPrepareResources,
        kReleaseResources,
        kResetFault,
        kOpenHookWizard,
        kOpenViewDialog,
        kOpenDomainDialog,
        kOpenMsrPolicyDialog,
        kOpenCrPolicyDialog,
        kOpenMemoryDialog,
        kOpenEventDialog,
        // R-1 process handling and injection. Originally, this could only be triggered via the 'full command panel'—a probe path that
        // launched the main program as an hvm_ctl subprocess, which has now been completely removed. Since the capability has its own
        // dedicated IOCTL, it is now handled by the native panel, sharing the same dispatch path as the View/MSR/CR components.
        kOpenProcessDialog
    };

    // ActionHandler: The unique entry point for requests.
    //
    // Using std::function instead of signals/slots allows this class and its hosted KernelHvmTab
    // to remain free of Q_OBJECT, eliminating the need to register QtMoc in the vcxproj for an
    // access point that only manifests at runtime. KernelKnowledgeTab::setRouteHandler is an
    // existing pattern with the same shape in this repository.
    using ActionHandler = std::function<void(Action)>;

    explicit KvmDock(QWidget* parent = nullptr);
    ~KvmDock() override = default;

    void setActionHandler(ActionHandler handler);
    void setCommandOperationHandler(std::function<void(bool)> handler);

    // setOperationRunning: Disables all entry points on this page while a command is executing.
    //
    // This page's state polling cannot see this event: the driver-side state lock is exclusively held during command execution, so
    // queries must wait until after it completes before returning. Only the side that initiated the command (mainWindow) can notify it.
    void setOperationRunning(bool running);

    // refreshStateAsync: Reads a state snapshot once in a background thread.
    // queryState is a blocking IOCTL and must never be called directly on the UI thread.
    void refreshStateAsync();

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void initializeUi();
    void applyState(const ksword::kvm::KvmState& state);
    void updateLifecycleView();
    void requestAction(Action action);

    ActionHandler actionHandler_;
    std::function<void(bool)> commandOperationHandler_;
    QTabWidget* tabs_ = nullptr;
    KvmGuestVmPanel* guestVmPanel_ = nullptr;
    KvmWatchPanel* watchPanel_ = nullptr;
    QTimer* pollTimer_ = nullptr;

    // Keep only the derived bit instead of the entire KvmState: dragging KvmControl.h into
    // this header file would drag the ArkDriverClient include chain into mainWindow.h.
    bool driverRunning_ = false;      // The driver service is running (availability != DriverNotRunning).
    bool hardwareAvailable_ = false;  // Hardware gate passed (Available or NotPrepared).
    bool resourcesReady_ = false;     // Resources are ready, meaning the window from step 2 is open.
    bool residentActive_ = false;     // At least one logical processor is in VMX non-root mode.
    bool faulted_ = false;            // If a fault exists or a rollback is pending, it must be reset first.
    bool operationRunning_ = false;   // Flag indicating command execution in progress, propagated from mainWindow.
    bool queryInFlight_ = false;      // Merge concurrent polling to prevent request accumulation on the driver side.
    // m_amdBackend: The current backend is AMD SVM/NPT.
    //
    // The UI structure remains unchanged: the same set of pages and buttons; missing items are grayed out with an explanation.
    // Changing the UI entails divergent evolution of two paths. On AMD, the only real difference is 'which entries
    // currently lack implementation'; redrawing the entire interface is disproportionate to this single concern.
    bool amdBackend_ = false;
    QString availabilityText_;        // Reason for unavailability, taken directly from the facade.
    QString detailText_;              // Snapshot details, sourced from the same tooltip as the title bar button.

    QLabel* hintLabel_ = nullptr;
    QLabel* stepOneLabel_ = nullptr;
    QLabel* stepTwoLabel_ = nullptr;
    QLabel* stepThreeLabel_ = nullptr;
    QLabel* stateLabel_ = nullptr;
    QLabel* detailLabel_ = nullptr;

    QPushButton* prepareButton_ = nullptr;
    QPushButton* releaseButton_ = nullptr;
    QPushButton* evidenceButton_ = nullptr;
    QPushButton* hookWizardButton_ = nullptr;
    QPushButton* processButton_ = nullptr;
    QPushButton* viewButton_ = nullptr;
    QPushButton* domainButton_ = nullptr;
    QPushButton* msrButton_ = nullptr;
    QPushButton* crButton_ = nullptr;
    QPushButton* memoryButton_ = nullptr;
    QPushButton* eventButton_ = nullptr;
    QPushButton* residentButton_ = nullptr;
    QPushButton* soakButton_ = nullptr;
    QPushButton* resetFaultButton_ = nullptr;

    KernelHvmTab* hvmTab_ = nullptr;
};
