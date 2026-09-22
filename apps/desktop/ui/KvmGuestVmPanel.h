#pragma once

// On the "Run Third-Party VMs" page: present a checklist of steps required for VMware
// / VirtualBox / WSL2 compatibility in language understandable by non-experts.
//
// Why create a separate page: These four items were previously scattered across three locations, and nowhere was there a specified order.
// Three switches are located in the virtualization menu of the title bar (the 'Hide Identity' option lacks a tooltip). The
// 'Prepare', 'Self-Check', and 'Resident' options are on the 'Control' page. Restarting the vmx86 service is **not on the
// UI at all**—it exists only as a comment line in the deployment script. If someone unaware of these details toggles all
// switches, VMware still fails to launch, and VMware's stated reason ('Incompatible with Hyper-V') does not point to us.
//
// This page handles only orchestration and explanation, adding no new driver capabilities: every step calls existing interfaces.

#include <QWidget>

#include <functional>

class QLabel;
class QPushButton;

namespace ksword::kvm { struct KvmState; }

class KvmGuestVmPanel final : public QWidget
{
public:
    explicit KvmGuestVmPanel(QWidget* parent = nullptr);

    // Tab switching is disabled by the outer layer during busy states, following the same convention as the 'Full Operation' tab.
    std::function<void(bool)> onBusyChanged;

    void refreshAsync();

protected:
    void showEvent(QShowEvent* event) override;

private:
    // A step consists of three parts: the title is constant, while the status and button are recalculated on each refresh.
    struct StepRow
    {
        QLabel* status = nullptr;
        QPushButton* action = nullptr;
    };

    StepRow addStep(
        class QVBoxLayout* parentLayout,
        int number,
        const QString& title,
        const QString& explanation,
        const QString& actionText,
        const std::function<void()>& onClicked);

    void applyState(const ksword::kvm::KvmState& state);
    void setBusy(bool busy);

    // Run blocking work in a background thread, then refresh the UI thread upon completion.
    void runInBackground(const std::function<QString()>& work);

    void enableAllSwitches();
    void startMonitor();
    void restartVmwareDriver();

    // This page calls it every time the configuration is changed to invalidate the "Completed" status from Step 5.
    // Because the sole purpose of that step is to re-query capabilities after the last modification:
    // If the switch is toggled or KSwordVM is restarted, the answer obtained from the previous restart becomes stale.
    void markConfigurationChanged();

    QLabel* intro_ = nullptr;
    QLabel* verdict_ = nullptr;
    QLabel* lastMessage_ = nullptr;
    QPushButton* doAll_ = nullptr;
    QPushButton* refresh_ = nullptr;

    StepRow stepAllowNested_;
    StepRow stepHostGuests_;
    StepRow stepHideIdentity_;
    StepRow stepStartMonitor_;
    StepRow stepRestartVmware_;

    bool busy_ = false;
    bool queryInFlight_ = false;

    // m_backendSupported: These five steps on this page apply only to Intel nested VMX.
    //
    // The three switches (allow nesting, allow others to run beneath us, hide identity) modify bits on the VMX dispatch
    // path; the AMD SVM backend has no corresponding implementation. On AMD, clicking these does not error but does nothing,
    // causing users to believe they missed a step. Thus, disable them based on the backend and provide a clear explanation.
    //
    // Initial value is false: before the first status query returns, the backend state is unknown. Allowing
    // the button at this stage lets the user act on an interface where the backend has not yet been read.
    bool backendSupported_ = false;

    // This 'has it restarted?' flag is tracked per-session only: the service running now doesn't prove
    // it started after the three switches were toggled—that distinction is precisely why this step
    // exists. Prefer 'pending restart' over misrepresenting 'running' as 'capabilities re-queried'.
    // See markConfigurationChanged(): any modification resets it to false.
    bool vmwareDriverRestarted_ = false;
};
