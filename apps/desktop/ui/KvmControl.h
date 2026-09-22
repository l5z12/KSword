#pragma once

// KvmControl: capability facade for KSwordVM (R-1 / hypervisor layer).
//
// Reason for existence:
// - The KVM button in the title bar permission button row, the HVM page in KernelDock, and subsequent EPT memory protection,
//   hidden hooks, and memory hiding must all read the same state and go through the same confirmation and write permission gate.
//   Encapsulate them in a facade to avoid each call site manually constructing IOCTL parameters and checking availability.
// - All queries are synchronous blocking calls (IOCTL); callers must execute them on a background thread.
//   SOAK can hold the driver-side state lock for dozens of seconds; it must never be called from the UI thread.

#include <QByteArray>
#include <QMetaType>
#include <QString>
#include <QVector>

#include "../../../shared/ark_client/ArkDriverClient.h"

namespace ksword::kvm
{
    // KvmAvailability: Explains why KVM is unavailable, determining the button tooltip and click behavior.
    enum class KvmAvailability
    {
        kAvailable,          // Capabilities are complete; resident mode can be started.
        kDriverNotRunning,   // KswordARK driver service is not running (click R0 first).
        kUnsupportedCpu,     // Non-Intel CPUs, or those lacking VMX/EPT, or missing MSR bitmap, etc., represent hard constraints.
        kFirmwareDisabled,   // Virtualization is disabled in the firmware.
        kHypervisorConflict, // Hyper-V/VBS has occupied VMX root.
        kNotPrepared,        // Resources are not yet prepared (PREPARE not executed or already TEARDOWN).
        kFaulted,            // If a fault exists or a rollback is needed, a reset must be performed first.
        // Hardware supports virtualization, but this version lacks the corresponding backend (currently AMD SVM).
        // Separated from UnsupportedCpu: the former requires a machine change, while the latter requires waiting for software.
        kBackendNotImplemented,
        // The outer layer already has a hypervisor (inside a guest VM, or bare metal with VBS/HVCI enabled), but nested mode is not enabled.
        // This state can be resolved by the user, so it must be reported separately from 'not supported'.
        kNestedNotAllowed
    };

    // KvmState: A state snapshot. The UI reads this structure only and does not directly parse featureFlags.
    struct KvmState
    {
        KvmAvailability availability = KvmAvailability::kDriverNotRunning;
        // backend: The virtualization backend currently selected by the driver, taking values from KSWORD_ARK_HVM_BACKEND_*.
        //
        // Promoted to this level because the UI has a whole set of entries that apply only to Intel (EPT separation view, execution
        // domain, MSR/CR policies, stealth hooks), whereas previously determining "is this machine AMD" required each call site to
        // individually inspect the QUERY response. The cost of not promoting it is not inconvenience, but inconsistency:
        // The title bar menu, KVM page, and hardware virtualization evidence page each perform their own null checks independently.
        //
        // Note that this is not the same as availability: on AMD machines with SVM backend,
        // availability remains Available even if the backend is fully functional. BackendNotImplemented
        // means "the driver lacks a backend for this processor," which is a separate issue.
        unsigned long backend = KSWORD_ARK_HVM_BACKEND_NONE;
        bool residentActive = false;   // At least one logical processor is in VMX non-root mode.
        bool residentComplete = false; // All logical processors are in non-root mode.
        bool sustainedProven = false;  // Prove long-term residency via SOAK.
        bool msrBitmapReady = false;   // An MSR bitmap is required for resident operation to survive.
        bool exitEmulationReady = false; // The dispatcher can handle all unconditional exits.
        bool eptRulesReady = false;    // EPT rules backend available.
        bool faulted = false;          // FAULTED or ROLLBACK_REQUIRED.
        // hypervisorPresent: an outer hypervisor is present (inside a VM, or bare metal with VBS/HVCI enabled).
        bool hypervisorPresent = false;
        // nestedResident: Currently resident as L1 running under another, indicating a degraded mode.
        bool nestedResident = false;
        // nestedL2LaunchRefusedCount: Count of times we refused 'others trying to launch a VM beneath us'.
        //
        // Direction is opposite to nestedResident: the latter indicates who we run under, while this indicates **who wants to run under
        // us**. During residency, if VMware / VirtualBox / WSL2 / Docker on the machine attempts VMLAUNCH, the driver will reject it
        // (vmcs02 merging was intentionally left incomplete). The driver-side status flag is cleared immediately upon the subsequent
        // VMXOFF—a two-second polling cycle will almost certainly miss this. Thus, this is a monotonically increasing counter; a
        // non-zero value indicates we are blocking other VMs, and the user observes the symptom: 'VM suddenly fails to start'.
        unsigned long nestedL2LaunchRefusedCount = 0;
        // veArmed: EPT-violation #VE control bit is armed for this residency.
        // Note the semantics: This only indicates the control bit is set; it does not imply that #VE can be dispatched.
        // The two driver-side safeguards (full-leaf suppress-#VE and info-region lock busy) are independent of this bit.
        bool veArmed = false;
        // veSuppressedByDefault: the driver confirms that every EPT leaf it installs has suppress-#VE set.
        // When this bit is false, #VE must not be armed; this implies the foundation is not ready.
        bool veSuppressedByDefault = false;
        // vmFuncArmed: VMFUNC is armed for this session; the guest can switch EPT views independently.
        bool vmFuncArmed = false;
        // eptpSwitchingAvailable: Processor support for VM function 0 is only meaningful for domains.
        bool eptpSwitchingAvailable = false;
        // eptpSwitchArmed: EPTP switching backend was actually used in this runtime.
        // This bit is the only trusted backend criterion: the request bit only indicates what the caller wants; when
        // capabilities are insufficient, the driver keeps the default backend. The request bit is identical in both cases.
        bool eptpSwitchArmed = false;
        // localEptArmed: This runtime instance actually obtained per-processor private EPT hierarchy.
        //
        // Similar to eptpSwitchArmed, this bit is the only reliable criterion: the checkmark in the menu only indicates
        // **Request**, but when capabilities are insufficient, the driver maintains the shared layer; the request bits are identical in both scenarios.
        // Previously, the UI only showed a checkbox, making the message "Private EPT is enabled" visible to users but
        // potentially factually incorrect—the only feedback was a raw status code 21 upon starting the resident component.
        bool localEptArmed = false;
        // The following four flags are preconditions checked one by one when the driver installs EPT separation views (CLOAK/HOOK).
        // They are already in the QUERY response but were never promoted to this layer. Consequently, when installation fails, the UI
        // can only relay a protocol status code without specifying which constraint is missing. The UI's responsibility is to clearly
        // explain these constraints: they are determined by the driver, and the client cannot relax them or pretend to bypass them.
        //
        // resourcesReady: PREPARE has been executed and TEARDOWN has not occurred.
        bool resourcesReady = false;
        // eptReady: EPT hierarchy is established; it is the first hard gate for installing the view.
        bool eptReady = false;
        // inveptSingleReady: Processor supports single-context INVEPT. Both backends require this—whether
        // writing back leaf entries or switching EPTP, translations built from the old value must be discarded.
        bool inveptSingleReady = false;
        // monitorTrapFlagReady: Processor supports the Monitor Trap Flag.
        // Only the default backend (write leaf + single-step one instruction + write back) requires it; the EPTP switch backend does not.
        // To determine whether this machine can install a view, check eptpSwitchArmed
        // as well. This bit alone would incorrectly rule out nested Hyper-V guests.
        bool monitorTrapFlagReady = false;
        unsigned long generation = 0;  // For compare-before control requests.
        unsigned long processorCount = 0;
        unsigned long residentProcessorCount = 0;
        unsigned long eptRuleCount = 0;
        unsigned long long vmExitCount = 0;
        // eptPointer: The currently active EPT pointer (including EPTP type and level encoding bits).
        // It is the only observable value to determine which EPT hierarchy the driver is actually using: private EPT and
        // execution domains attach different pointers to different processors/domains, and the hardest-to-detect failure
        // is when the shared root is swapped but not invalidated. Promoting it allows the UI to display and verify it.
        unsigned long long eptPointer = 0;
        unsigned long soakElapsedMilliseconds = 0;
        unsigned long soakUnexpectedDevirtualizations = 0;
        QString shortStatus; // Button tooltip first line.
        QString detail;      // Button tooltip details.
    };

    // KvmCommandResult: result of a control command, ready for direct UI display.
    struct KvmCommandResult
    {
        bool ok = false;
        unsigned long protocolStatus = 0; // KSWORD_ARK_HVM_CONTROL_STATUS_*。
        long ntStatus = 0;
        QString message; // Localized failure reason or success summary.
    };

    // queryState: Read a complete state snapshot. Blocking; must be called from a background thread.
    KvmState queryState();

    // ensurePrepared: Executes PREPARE + SELF_TEST as needed to enable the resident component to start.
    // If already prepared, return success directly without re-allocating resources.
    KvmCommandResult ensurePrepared();

    // startResident/stopResident: Enter or exit full-core VMX non-root mode.
    // startResident calls ensurePrepared if necessary.
    KvmCommandResult startResident(unsigned long expectedGeneration);
    KvmCommandResult stopResident(unsigned long expectedGeneration);

    // runSoak: Starts a resident process, keeps it running for the specified milliseconds, then stops it to prove long-term residency.
    // The driver clamps the duration to the protocol bounds; the driver-side state lock is exclusively held during the call.
    KvmCommandResult runSoak(
        unsigned long expectedGeneration,
        unsigned long milliseconds);

    // resetFault: Clears recoverable faults and rollback markers. Rejected in resident mode.
    KvmCommandResult resetFault(unsigned long expectedGeneration);

    // releaseResources: TEARDOWN, release all reversible resources, and return to 'not ready'.
    //
    // This layer was added because the KVM menu originally **lacked** it. Without it, there is an unavoidable deadlock: the
    // View, MSR, CR, and Domain panels all require resources to be prepared, yet the only action available to the user in this
    // menu is "Start Resident." This action prepares the resources and immediately enters the resident state within the same
    // call, causing the four panels to instantly transition from "not yet prepared" to "cannot be modified during residency."
    // Note: The only available window in the middle cannot be triggered from this menu.
    //
    // It is the only way to make the backend switch take effect after it has been changed: the backend
    // is selected during PREPARE, and ensurePrepared does not resend PREPARE once resources are ready.
    KvmCommandResult releaseResources(unsigned long expectedGeneration);

    // Nested mode switch:
    // - Disabled by default; bare-metal exclusive VT-x remains the expected mode of operation;
    // - When enabled, PREPARE, SELF_TEST, and resident operations include ALLOW_NESTED, allowing execution inside a VM
    //   or on a machine with VBS enabled. The cost is that every VMX operation is emulated by the outer hypervisor,
    //   significantly degrading performance and limiting available capabilities to only those exposed by the outer layer.
    // - This is not a dangerous switch (it does not rewrite any system state), so it is separated from the write permission gate.
    bool isNestedAllowed();
    void setNestedAllowed(bool allowed);

    // Nested dispatch switch (ENABLE_NESTED_VMX):
    // - [Opposite of the above; do not confuse]: isNestedAllowed means "allow us to run underneath
    //   others" (we are the guest); this one means "allow others to run underneath us" (we are the host).
    //   Sharing a single switch would cause someone enabling the former to inadvertently enable the latter.
    // - When enabled, ring 0 code inside the guest can execute VMXON, maintain its own vmcs12, and run L2.
    //   VM exits first land here; based on ownership, we either handle them locally or dispatch to L1. When L1
    //   requires EPT, the shadow hierarchy (EPT01 ∘ EPT12) is synthesized on-demand. MSR and I/O interception
    //   are merged according to L1's own bitmaps and then routed. This is **not** a stub for failure.
    // - When disabled, VMX instructions trigger #UD. While this is architecturally correct when CPUID does
    //   not report VMX, it causes VMware / VirtualBox / WSL2 to become unopenable for running VMs without
    //   any hint pointing to us; therefore, the status panel must report that monotonous rejection count.
    // - Mutually exclusive with ENABLE_LOCAL_EPT: Nested virtualization synthesizes an EPT pointer from the guest's
    //   hierarchy and our hierarchy. Per-processor private roots make this synthesis processor-specific, causing the
    //   driver to return STATUS_INVALID_PARAMETER. Requests enabling both are rejected entirely with the generic reason
    //   "Invalid request" without specifying which bit caused it; thus, the request must be blocked before being sent.
    // - [Not Persistent]: Like #VE / VMFUNC, this enables a capability rather than
    //   describing an environmental fact; it must be re-enabled every time the client starts.
    bool isNestedDispatchEnabled();
    bool isHypervisorHidden();
    void setHypervisorHidden(bool enabled);
    void setNestedDispatchEnabled(bool enabled);

    // #VE switch (reflecting EPT violations as guest #VEs, vector 20):
    // - The guest here is the Windows instance currently running. Its IDT[20] lacks a #VE handler; triggering
    //   it once causes #GP -> #DF -> triple fault, resulting in an immediate power-off-style reboot.
    // - On the driver side, there are two safeguards unrelated to this switch: every EPT leaf (including empty slots for
    //   unmapped regions) has suppress-#VE enabled, and the per-CPU info area has its busy lock set at allocation time. When both
    //   are in place, even if the control bit is enabled, no #VE can be delivered; EPT violations fall back to regular VM-exits.
    // - Therefore, enabling it results in 'control bits armed', not '#VE active'. To actually receive #VE, you must
    //   first install the handler in the guest, clear the busy flag, and explicitly mark the target page as convertible;
    // - If hardware is unsupported, the driver directly rejects starting the resident component instead of silently downgrading;
    //   otherwise, the caller might mistakenly believe they are testing #VE when they are actually testing something else.
    // - [Non-persistent]: Must be re-enabled every time the client starts. This is intentional.
    bool isVeEnabled();
    void setVeEnabled(bool enabled);

    // VMFUNC switch:
    // - After being armed, a guest can switch between domains in the EPTP list using a single
    //   VMFUNC instruction without generating a VM exit, so the driver receives no notification.
    //   Since VMFUNC performs no CPL checks, "guest" here includes any ring 3 thread of any process.
    // - This is not an escalation path: a domain can only have permissions removed; entering it worst-case results in a self-triggered EPT violation.
    //   However, it is indeed a state transition unobservable by the driver, warranting a separate gate.
    // - Like #VE, it is not persisted; the setting reverts to disabled upon client restart.
    bool isVmFuncEnabled();
    void setVmFuncEnabled(bool enabled);

    // Private EPT switch (one EPT hierarchy per processor):
    // - Unlike #VE / VMFUNC, this switch does not expose any new capabilities; it ensures that existing
    //   EPT views with allow-once authorization remain safe across multiple cores: the flip occurs only
    //   on the processor that receives the exit, while other processors do not see that window.
    // - This must be enabled to install the EPT view on multi-core machines. When disabled, the view can
    //   only be installed on single-core topologies, which was the behavior before this switch existed.
    // - Mutually exclusive with VMFUNC and nested VMX: the former requires all processors to share a single
    //   EPTP list, while the latter requires synthesizing an EPT pointer independent of the processor;
    // - [Persistent]: It is not a dangerous switch; it represents a safer direction.
    bool isLocalEptEnabled();
    void setLocalEptEnabled(bool enabled);

    // EPTP switch backend toggle (selects which machine set to use for separated views):
    // - When disabled, behavior matches today's byte-by-byte approach: the default backend is
    //   'write EPT leaf + single-step one instruction using Monitor Trap Flag + write the leaf back'.
    // - Upon enabling, switch to 'EPTP switching': Both backends answer the same question, but the difference lies in required capabilities
    //   rather than performance—the default backend requires Monitor Trap Flag support, whereas this one only requires execute-only EPT leaf pages.
    // - Reason for existence: Nested Hyper-V guests cannot obtain MTF, so
    //   on such machines, only this backend can install CLOAK/HOOK views;
    // - Mutually exclusive with VMFUNC and private EPT; the driver rejects simultaneous requests before any allocation occurs.
    // - This bit is only triggered by PREPARE; the driver decides whether to arm resources during preparation.
    //   Therefore, changing this switch after resources are ready will only take effect after the next re-preparation.
    // - [Persistent]: It does not expose any new capabilities; it merely switches machines, behaving like private EPT.
    bool isEptpSwitchEnabled();
    void setEptpSwitchEnabled(bool enabled);

    // Write Access Gate:
    // - Disabled by default. When disabled, KVM operates in observation-only mode; any R-1 operation that would alter system state is rejected.
    // - Explicitly toggled by the title bar KVM menu and persisted to QSettings.
    // - This is the second gate within the process; the driver side still requires separate confirmation of the token and FILE_WRITE_ACCESS.
    bool isWriteAccessEnabled();
    void setWriteAccessEnabled(bool enabled);

    // describeAvailability: Turn the reason for unavailability into a sentence ready for display.
    QString describeAvailability(KvmAvailability availability);

    // KvmMemoryResult: The result of an R-1 memory operation.
    struct KvmMemoryResult
    {
        bool ok = false;
        // usedDirectWindow: Actually uses the private page table window (bypassing Mm* exports).
        // Note: When false, it degrades to MmCopyMemory; reading is still possible, but kernel-level Hook bypass is no longer performed.
        bool usedDirectWindow = false;
        // windowReady: Whether a private window was successfully created on the local machine.
        bool windowReady = false;
        unsigned long long physicalAddress = 0;
        QByteArray data;
        QString message;
    };

    // isMemoryWindowReady: Check if the private window is available without touching any memory.
    KvmMemoryResult queryMemoryWindow();

    // readPhysical/writePhysical: Physical memory read/write.
    // - The per-call limit is determined by the driver protocol (KSWORD_ARK_HVM_MEMORY_MAX_BYTES).
    // - writePhysical is constrained by write permission gates; it fails immediately without issuing an IOCTL when disabled.
    KvmMemoryResult readPhysical(
        unsigned long long physicalAddress,
        unsigned long length);
    KvmMemoryResult writePhysical(
        unsigned long long physicalAddress,
        const QByteArray& payload);

    // readVirtual/writeVirtual: First performs page table translation using the given page directory base, then performs the read/write.
    // When directoryBase is 0, resolve using the page table of the current process (i.e., the process where the driver calling thread resides).
    KvmMemoryResult readVirtual(
        unsigned long long directoryBase,
        unsigned long long virtualAddress,
        unsigned long length);
    KvmMemoryResult writeVirtual(
        unsigned long long directoryBase,
        unsigned long long virtualAddress,
        const QByteArray& payload);

    // translate: Performs virtual-to-physical translation only; does not access target memory.
    KvmMemoryResult translate(
        unsigned long long directoryBase,
        unsigned long long virtualAddress);

    // KvmViewEntry: An installed EPT split view entry.
    struct KvmViewEntry
    {
        unsigned long viewId = 0;
        unsigned long kind = 0;
        unsigned long flags = 0;
        unsigned long long physicalAddress = 0;
        unsigned long long shadowPhysicalAddress = 0;
        unsigned long long flipCount = 0;
    };

    // KvmViewShadowSeed: The source of initial shadow page content.
    enum class KvmViewShadowSeed
    {
        kZero,       // All zeros: the reader sees a blank screen.
        kFromTarget, // Freeze the target page's current content: readers see the state at the moment of installation.
        kExplicit    // Use the full page content provided by the caller.
    };

    // KvmViewResult: The result of a view operation.
    struct KvmViewResult
    {
        bool ok = false;
        unsigned long viewId = 0;
        unsigned long viewCount = 0;
        // protocolStatus/lastStatus: Two-level failure codes uploaded as-is.
        //
        // message is a human-readable sentence; once translated, the information about 'which step failed' is lost.
        // The same protocolStatus can be generated by multiple different branches (MULTIPROCESSOR_UNSAFE
        // may mean "currently resident" or "topology/capability mismatch"). Only when paired with
        // lastStatus can they be distinguished. Callers must use these two values to precisely backtrack
        // to the step that caused the failure, rather than guessing based on strings.
        // protocolStatus takes KSWORD_ARK_HVM_VIEW_STATUS_*, lastStatus is NTSTATUS.
        //
        // Only read them if ok is false, and check ok first: The two paths rejected by the client
        // (write permission gate and shadow page length) never sent an IOCTL, so both fields remain
        // zero—which happens to be VIEW_STATUS_OK. We do not invent a sentinel value not defined in
        // the protocol, as that would imply a driver status code that is never returned.
        unsigned long protocolStatus = 0;
        long lastStatus = 0;
        QVector<KvmViewEntry> views;
        QString message;
    };

    // listViews: Read installed views; write permission not required.
    KvmViewResult listViews();

    // addView: Install a view. Subject to write permission gate constraints.
    // shadow is used only when seed is Explicit and must be exactly one page (4096 bytes).
    KvmViewResult addView(
        unsigned long kind,
        unsigned long long physicalAddress,
        KvmViewShadowSeed seed,
        const QByteArray& shadow);

    // removeView/clearViews: remove a single view or all views. Subject to write permission gate constraints.
    KvmViewResult removeView(unsigned long viewId);
    KvmViewResult clearViews();

    // KvmDomainEntry: A slot in the EPTP list.
    struct KvmDomainEntry
    {
        unsigned long domainIndex = 0;
        bool active = false;
        // The number of page tables forked from the shared hierarchy: 0 indicates full consistency with the default view.
        unsigned long privateTableCount = 0;
        unsigned long long eptPointer = 0;
    };

    // KvmDomainResult: result of a single domain operation execution.
    struct KvmDomainResult
    {
        bool ok = false;
        unsigned long domainIndex = 0;
        unsigned long domainCount = 0;
        QVector<KvmDomainEntry> domains;
        QString message;
    };

    // Execute the domain (EPT execution domain):
    // - The domain is published in the EPTP list; the guest can switch to it via a single VMFUNC instruction, which
    //   performs no CPL check—any ring 3 thread can switch without triggering a VM exit, and the driver is not notified.
    // - Therefore, the interface only supports privilege reduction: a domain starts with full default permissions and can only have
    //   them removed thereafter. Threads entering the domain structurally cannot gain access rights they did not originally possess.
    // - Creating the domain itself does not change any behavior. To make VMFUNC actually usable,
    //   a resident boot with ENABLE_VMFUNC is required, which is a separate independent switch.
    KvmDomainResult listDomains();
    KvmDomainResult createDomain();
    // restrictDomain: Removes permissions for a specific physical range from a domain.
    // deniedAccess uses KSWORD_ARK_HVM_EPT_ACCESS_* bits. Removing read permission requires processor support for
    // execute-only translation; otherwise the driver rejects it (such leaf entries would cause VM entry to fail).
    KvmDomainResult restrictDomain(
        unsigned long domainIndex,
        unsigned long long physicalAddress,
        unsigned long long byteCount,
        unsigned long deniedAccess);
    KvmDomainResult resetDomains();

    // KvmMsrPolicyEntry: An installed MSR policy.
    struct KvmMsrPolicyEntry
    {
        unsigned long policyId = 0;
        unsigned long msrIndex = 0;
        unsigned long access = 0;
        unsigned long action = 0;
        unsigned long long fakeValue = 0;
        unsigned long long hitCount = 0;
    };

    // KvmMsrPolicyResult: Result of a single MSR policy operation.
    struct KvmMsrPolicyResult
    {
        bool ok = false;
        unsigned long policyId = 0;
        unsigned long policyCount = 0;
        QVector<KvmMsrPolicyEntry> policies;
        QString message;
    };

    // listMsrPolicies: Read installed policies. Write permissions are not required.
    KvmMsrPolicyResult listMsrPolicies();

    // addMsrPolicy: Install a policy. Constrained by write-access gates.
    // When action is LOG, write direction is not allowed: replaying WRMSR in VMX root has no safe fallback.
    KvmMsrPolicyResult addMsrPolicy(
        unsigned long msrIndex,
        unsigned long access,
        unsigned long action,
        unsigned long long fakeValue);

    // removeMsrPolicy/clearMsrPolicies: Remove one or all policies. Constrained by write permission gate.
    KvmMsrPolicyResult removeMsrPolicy(unsigned long policyId);
    KvmMsrPolicyResult clearMsrPolicies();

    // KvmEventEntry: A single HVM event. sequence is monotonically increasing and serves as the consumer cursor.
    struct KvmEventEntry
    {
        unsigned long long sequence = 0;
        unsigned long long timestamp = 0;
        unsigned long long guestPhysicalAddress = 0;
        unsigned long long guestLinearAddress = 0;
        unsigned long long guestRip = 0;
        unsigned long long qualification = 0;
        unsigned short processorGroup = 0;
        unsigned char processorNumber = 0;
        unsigned long type = 0;
        unsigned long exitReason = 0;
        unsigned long access = 0;
        // ruleId carries the viewId for EPT view flipping: both share this column.
        unsigned long ruleId = 0;
        long status = 0;
        // Stack pointer and address space at the moment of a hit. Must be captured during the VM-exit context:
        // once VMRESUME returns, they describe a different thread. 0 indicates the driver failed to read the value
        // (the outer hypervisor may reject certain guest state encodings), not that the value is inherently 0.
        unsigned long long guestRsp = 0;
        unsigned long long guestCr3 = 0;
        // See KSWORD_ARK_HVM_EPT_WATCH_STATE_*; meaningful only for watch hit lines.
        unsigned long watchState = 0;
        // See KSWORD_ARK_HVM_EVENT_FLAG_*.
        unsigned long eventFlags = 0;
    };

    // KvmEventResult: Result of a single event read.
    struct KvmEventResult
    {
        bool ok = false;
        // droppedRows: Number of rows overwritten or unavailable in this snapshot; non-zero indicates consumer lag.
        unsigned long droppedRows = 0;
        unsigned long availableRows = 0;
        unsigned long long newestSequence = 0;
        QVector<KvmEventEntry> events;
        QString message;
    };

    // readEvents: Reads events after afterSequence. Read-only; no write permission required.
    // When clear is true, the ring buffer is also cleared to begin a clean observation.
    KvmEventResult readEvents(
        unsigned long long afterSequence,
        bool clear);

    // KvmCrPolicyResult: Current configuration and count for control register policies.
    struct KvmCrPolicyResult
    {
        bool ok = false;
        unsigned long long cr0PinnedMask = 0;
        unsigned long long cr4PinnedMask = 0;
        unsigned long long cr0PinnedValue = 0;
        unsigned long long cr4PinnedValue = 0;
        unsigned long long refusedWriteCount = 0;
        unsigned long long cr3SwitchCount = 0;
        unsigned long long debugAccessCount = 0;
        bool trackCr3 = false;
        bool interceptDr = false;
        bool log = false;
        QString message;
    };

    // readCrPolicy: Read current configuration and count. Read-only.
    KvmCrPolicyResult readCrPolicy();

    // applyCrPolicy: Sets pinned masks and interception switches. Constrained by write permission gates.
    // The masks and switches are consumed when building the VMCS; during residency, the driver will reject any modifications.
    KvmCrPolicyResult applyCrPolicy(
        unsigned long long cr0PinnedMask,
        unsigned long long cr4PinnedMask,
        bool trackCr3,
        bool interceptDr,
        bool log);

    // clearCrPolicy: Clears all configurations and counts. Constrained by write permission gates.
    KvmCrPolicyResult clearCrPolicy();

    // ——— R-1 Process Disposition and Injection ———
    //
    // Previously, the only entry point for these two groups in the GUI was the 'Full Command Panel', which launched the probe as a
    // child process of the main program using hvm_ctl—this is a probe invocation pattern, not a product one. After the probe is
    // detached from the main program, these capabilities do not follow; they each have dedicated IOCTLs, and the driver implements
    // the full production path. Therefore, we add a direct interface here, matching the shape of the View/MSR/CR groups:
    // Same write permission gate, same status code translation, and same table return.

    // KvmProcessDispositionEntry: An installed R-1 process disposition.
    struct KvmProcessDispositionEntry
    {
        unsigned long processId = 0;
        // disposition takes KSWORD_ARK_HVM_PROCESS_OP_FREEZE / _TERMINATE, and
        // _DISPOSITION_RELEASED (revoked during residency, hierarchy not yet reclaimed).
        unsigned long disposition = 0;
        unsigned long hierarchyIndex = 0;
        // directoryBase is the criterion for this record: PIDs can be recycled, but address spaces cannot.
        unsigned long long directoryBase = 0;
        unsigned long long guestPhysicalAddress = 0;
        unsigned long long guestLinearAddress = 0;
        // If interceptCount continues to grow while frozen, it proves the target thread is still spinning.
        unsigned long long interceptCount = 0;
    };

    // KvmProcessResult: Result of a single process handling operation. Each operation fills the entire table.
    struct KvmProcessResult
    {
        bool ok = false;
        // protocolStatus takes values from KSWORD_ARK_HVM_PROCESS_STATUS_*. It is only read when ok is false, consistent
        // with the comment on KvmViewResult: the path where the client locally rejects does not send an IOCTL.
        unsigned long protocolStatus = 0;
        long lastStatus = 0;
        unsigned long rowCount = 0;
        QVector<KvmProcessDispositionEntry> dispositions;
        QString message;
    };

    // listProcessDispositions: Reads the disposition table. Read-only; write permissions are not required.
    KvmProcessResult listProcessDispositions();

    // freezeProcess/terminateProcess: Installs a disposition. Constrained by write permission gates.
    //
    // guestLinearAddress set to 0 indicates the driver should fetch the entry page of the main image. Specification is allowed because there
    // is no universal answer to 'which page represents this process': the entry page is valid for a freshly started process, but may never be
    // executed again for a process already running in a message loop; refusing to execute an unexecuted page is equivalent to doing nothing.
    KvmProcessResult freezeProcess(
        unsigned long processId,
        unsigned long long guestLinearAddress);
    KvmProcessResult terminateProcess(
        unsigned long processId,
        unsigned long long guestLinearAddress);

    // releaseProcessDisposition/releaseAllProcessDispositions: Revoke.
    // During residency, this is a 'release' rather than a full rollback; see the protocol header comments for driver-side semantics.
    KvmProcessResult releaseProcessDisposition(unsigned long processId);
    KvmProcessResult releaseAllProcessDispositions();

    // KvmInjectionEntry: An installed R-1 injection.
    struct KvmInjectionEntry
    {
        unsigned long processId = 0;
        unsigned long payloadBytes = 0;
        unsigned long long directoryBase = 0;
        unsigned long long guestLinearAddress = 0;
        unsigned long long guestPhysicalAddress = 0;
        // caveOffset: Offset of the shell within the page, i.e., the location where RIP will be pointed.
        unsigned long caveOffset = 0;
        unsigned long caveBytes = 0;
        // executionCount: Number of times the payload was executed. Should be 1 after one-time injection is complete.
        unsigned long long executionCount = 0;
        unsigned long viewId = 0;
        // caveFiller: filler bytes originally in the gap (0x00 / 0xCC / 0x90), used for attribution during troubleshooting.
        unsigned long caveFiller = 0;
    };

    // KvmInjectResult: Result of a single injection operation.
    struct KvmInjectResult
    {
        bool ok = false;
        unsigned long protocolStatus = 0; // KSWORD_ARK_HVM_INJECT_STATUS_*。
        long lastStatus = 0;
        unsigned long rowCount = 0;
        QVector<KvmInjectionEntry> injections;
        QString message;
    };

    // listInjections: Read the injection table. Read-only; write permissions are not required.
    KvmInjectResult listInjections();

    // injectDll: Loads a DLL into the target process via detached view + thread hijacking.
    //
    // guestLinearAddress **Required**: Any address within the page to be hijacked. The driver does not guess this page;
    // guessing wrong results in the payload being installed but never executing—externally indistinguishable from
    // success. Take a location where a target thread is currently executing; by definition, that page will be executed.
    //
    // Passing 0 to loadLibraryAddress indicates that the client should resolve it locally: kernel32 has the same base address
    // for all processes within a single startup, so the LoadLibraryW resolved in this process is valid for the target as well.
    KvmInjectResult injectDll(
        unsigned long processId,
        unsigned long long guestLinearAddress,
        unsigned long long loadLibraryAddress,
        const QString& dllPath);

    // releaseInjection/releaseAllInjections: Revoke injections. Constrained by write permission gate.
    KvmInjectResult releaseInjection(unsigned long processId);
    KvmInjectResult releaseAllInjections();

    // ——— R-1 Memory monitoring (first access attribution) ———
    //
    // It answers a question other mechanisms cannot: after a kernel object is modified,
    // **who** modified it next and **from which instruction**. Snapshot-based detection
    // only reveals "it was A before, B after"; the intermediate action leaves no evidence.
    //
    // The boundary must be explicit, as it is easily mistaken for something else: this is observation and attribution, not protection.
    // It does not block access (the original access completes normally after a hit), is not a security boundary (EPT is
    // page-granular, DMA bypasses CPU EPT, and if the target replaces its own physical page, it is no longer on the monitored
    // page), and is not continuous monitoring (the first version only guarantees 'one reliable event per next access').

    // KvmWatchEntry: A complete snapshot of a watch entry.
    struct KvmWatchEntry
    {
        unsigned long watchId = 0;
        // See KSWORD_ARK_HVM_EPT_WATCH_STATE_*.
        unsigned long state = 0;
        // User-requested vs. actually installed access types. Both must be considered: EPT forbids
        // W=1 and R=0, so "read-only monitoring" inherently monitors writes in hardware. Display
        // only one: either modify the user's request or falsely claim finer monitoring than actual.
        unsigned long requestedAccess = 0;
        unsigned long effectiveAccess = 0;
        unsigned long addressKind = 0;
        unsigned long hitCount = 0;
        unsigned long long lastHitSequence = 0;
        // See KSWORD_ARK_HVM_EPT_WATCH_HIT_*. EVENT_LOST must be distinguished from 'never hit'.
        unsigned long lastHitStatus = 0;
        unsigned long armedGeneration = 0;
        // The segment requested by the user versus the page actually monitored by the hardware. The
        // former may be 8 bytes, while the latter is always 4096 — the interface must display both.
        unsigned long long requestedAddress = 0;
        unsigned long long requestedLength = 0;
        unsigned long long physicalPage = 0;
        unsigned long long pageCount = 0;
        unsigned long long lastHitRip = 0;
        unsigned long long lastHitGuestLinearAddress = 0;
        unsigned long long lastHitGuestPhysicalAddress = 0;
        unsigned long long lastHitCr3 = 0;
        unsigned long long lastHitRsp = 0;
        unsigned long long lastHitTimestamp = 0;
        unsigned short lastHitProcessorGroup = 0;
        unsigned char lastHitProcessorNumber = 0;
        bool lastHitGuestLinearValid = false;
        // The hit GLA falls within the requestedAddress/Length range, not just on the same page.
        bool lastHitRangeMatch = false;
    };

    // KvmWatchResult: Result of a single watch operation.
    struct KvmWatchResult
    {
        bool ok = false;
        unsigned long protocolStatus = 0; // KSWORD_ARK_HVM_EPT_RULE_STATUS_*。
        long lastStatus = 0;
        // Who occupies this page during a conflict; see KSWORD_ARK_HVM_WATCH_CONFLICT_*.
        unsigned long conflictOwnerId = 0;
        unsigned long conflictOwnerKind = 0;
        unsigned long watchCount = 0;
        QVector<KvmWatchEntry> watches;
        QString message;
    };

    // listWatches: Reads the entire watch table. Read-only; write permissions are not required.
    KvmWatchResult listWatches();

    // KvmWatchTarget: A watch installation request.
    struct KvmWatchTarget
    {
        // Note: If true, address is a kernel virtual address; translate to physical page before installation.
        bool virtualAddress = true;
        unsigned long long address = 0;
        // The byte count the user actually cares about. Passing 0 indicates a full page.
        unsigned long long length = 0;
        // Combination of KSWORD_ARK_HVM_EPT_ACCESS_*.
        unsigned long access = 0;
    };

    // addWatch: Install a one-time watch. Subject to write permission gate.
    //
    // The virtual address is translated once here and the result is recorded; **subsequent remappings are not tracked**. After
    // installation, if the guest page table points the same VA to a different physical page, this watch still monitors the
    // original page. The UI must detect this divergence and report it, rather than continuing to claim "monitoring this VA".
    KvmWatchResult addWatch(const KvmWatchTarget& target);

    // rearmWatch: Re-arms a triggered or expired watch, preserving its ID and history.
    KvmWatchResult rearmWatch(unsigned long watchId);

    // removeWatch/clearWatches: removal. clearWatches reuses the EPT rule CLEAR, so it also
    // clears standard EPT rules — the call site must inform the user of this behavior.
    KvmWatchResult removeWatch(unsigned long watchId);

    // KvmWatchAttribution: Attributes a guest RIP to a specific loaded kernel module.
    //
    // Only performs the step of "determining which module's image range the address falls into."
    // This is done in R3 normal context, not in VMX root: resolving Windows objects there risks the
    // entire machine, and delaying this step by a few milliseconds does not affect the conclusion.
    struct KvmWatchAttribution
    {
        bool resolved = false;
        QString moduleName;
        QString modulePath;
        unsigned long long moduleBase = 0;
        unsigned long long moduleSize = 0;
        // Offset relative to the module base; valid when resolved is true.
        unsigned long long relativeAddress = 0;
        // The most recent exported symbol and its relative offset.
        //
        // Only parse the export table, not PDBs: When there is no symbol server or local PDB, the export table is the
        // only symbol source bundled with the module that is offline-readable and requires no network connection.
        // While it cannot resolve static functions, it can resolve the vast majority of suspicious targets (dispatch,
        // callbacks, and SSDT routines are either exported or located immediately adjacent to exports).
        //
        // An empty string indicates no exported symbol precedes this address; in that
        // case, the caller should display only `module.sys+0xRVA` rather than fabricating
        // a recent name—a wrong function name is harder to correct than no name.
        QString symbolName;
        unsigned long long symbolOffset = 0;
    };

    // attributeKernelAddress: map a kernel address to a module.
    // When no loaded module can be resolved, the result is false—this is a conclusion ('unknown executable region'), not a failure.
    // Callers should use this to provide an entry point for opening memory or disassembly instead of just displaying 'Unknown'.
    KvmWatchAttribution attributeKernelAddress(unsigned long long address);

    // KvmProcessAttribution: Assign the CR3 from the hit context to a process.
    //
    // Four states, corresponding to the four required phrasings in Section 11 of issue #195. These are
    // not four degrees of the same thing, but four **distinct answers**. Mixing them would cause "this
    // address space no longer exists" and "this attribution never ran" to display as the same sentence.
    enum class KvmProcessAttributionKind
    {
        // No CR3 is available to map (the context was not recorded on a hit, or there was no hit at all).
        kUnavailable = 0,
        // Scanned; the CR3 of a certain process is bitwise equal to it.
        kResolved,
        // Scanned, but nothing matched. The address space has likely been torn down.
        kNotFound,
        // Failed to query any process: driver not loaded, snapshot unavailable, or insufficient permissions.
        kFailed,
    };

    struct KvmProcessAttribution
    {
        KvmProcessAttributionKind kind = KvmProcessAttributionKind::kUnavailable;
        unsigned long processId = 0;
        // Image name parsed from the interface's own process snapshot. It may be empty or point to another process if the
        // PID was recycled; thus, it is always used only as supplementary display, with the PID as the definitive criterion.
        QString imageName;
        // Actual count of processes queried via CR3. Distinguishes between 'none matched' and 'none scanned'.
        unsigned long scannedProcesses = 0;
    };

    // attributeProcessByCr3: Uses the driver to map CR3 to PID, then supplements the image name using the UI's own
    // process snapshot. This blocks on IOCTL and iterates all processes; must be called from a background thread.
    KvmProcessAttribution attributeProcessByCr3(unsigned long long directoryBase);

    // describeProcessAttribution: Translate the four-state result into a single, displayable sentence that does not
    // exaggerate certainty. It will never return phrasing like "Unknown" that collapses the four distinct answers into one.
    QString describeProcessAttribution(const KvmProcessAttribution& attribution);

    // toWin32ModulePath: Convert module paths from the kernel perspective to paths recognizable by File Explorer.
    // Return an empty string if unrecognized—the caller must silently give up rather than trying the original string:
    // the file explorer might open a default directory with a non-existent path, appearing to succeed completely.
    QString toWin32ModulePath(const QString& ntPath);

    // describeWatchState/describeWatchAccess: Translate protocol values into displayable text.
    QString describeWatchState(unsigned long state);
    QString describeWatchAccess(unsigned long access);
    // describeWatchConflict: Clarifies who owns the page when a conflict occurs.
    QString describeWatchConflict(unsigned long ownerKind, unsigned long ownerId);
}

// Store the entire snapshot row in Qt::UserRole for table rows: inferring
// values from localized cell text will fail on the first translated word.
Q_DECLARE_METATYPE(ksword::kvm::KvmWatchEntry)
