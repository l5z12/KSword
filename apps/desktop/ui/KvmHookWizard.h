#pragma once

// KvmHookWizard: A five-step wizard for viewing a single HOOK.
//
// Why it is needed:
// - The existing KvmViewDialog is a flat form that delegates six tasks to the user: 'calculate address, capture baseline,
//   check preconditions, assemble full-page shadow, install, and verify installation'. None of these steps trigger an error
//   if performed incorrectly. The driver only validates page alignment and the 8 TiB upper bound (hvm_ept_view.c:288-295).
//   The result of a misinstallation is a HOOK attached to unrelated memory, yet everything appears to function normally.
// - Therefore, switch to a non-skippable pipeline here: each step asks only one question, each step's output
//   goes into the same KvmHookPlan, and the next step reads only the previous step's output without recomputation.
//
// Note: Why use QDialog + QStackedWidget instead of QWizard:
//   Use QWizard exclusively. Introducing it means this dialog's appearance, theme
//   coloring, and button layout follow an unmaintained path. The shape is copied
//   from KvmViewDialog to ensure it looks identical to the six adjacent KVM panels.
//
// [CLOAK/HOOK is not a security boundary] — Finalized.
//   No user-facing text in this wizard may imply that HOOK can defend against a privileged adversary.
//   Failure allows pass: When InstructionLength is 0, the processor re-executes and reads the real page.
//
// [HOOK direction not tested] The project has **not tested** redirecting
//   execution to shadow pages; this is from the original roadmap.
//   In Step 5B, ExecutionRedirected is therefore always NoReading; do not change it to 'Verified'.
//
// [No escape on multi-core systems] The installation view requires ProcessorCount ==
//   1 || LocalEptArmed. ENABLE_LOCAL_EPT is read by PREPARE (hvm_runtime.c:1573-1582)
//   but is not in PREPARE's allowedFlags whitelist (:2682-2685). The driver comment
//   refers to this as a standing defect (:2674-2681).
//   Therefore, the Topology entry in Step 3 is unreachable via the protocol on multi-core machines. The UI's responsibility
//   is to present these three facts truthfully and **must not provide a button that pretends to offer a solution**.
//
// ===========================================================================
// [Division of labor among the three .cpp files — This section defines the contract; review it before writing code.]
//
//   KvmHookWizard.cpp: Skeleton + Step 1 (Select Target) + Step 4 (Install).
//   KvmHookWizard.Patch.cpp: Step 2 (Generate Patch) + One page of byte read and
//   assembly. KvmHookWizard.Verify.cpp: Step 3 (Pre-check) + Step 5 (Verification).
//
// Ownership for each member function is marked on its own declaration, in the format [W] / [P] / [V] at the end of the line:
//   [W] = KvmHookWizard.cpp
//   [P] = KvmHookWizard.Patch.cpp
//   [V] = KvmHookWizard.Verify.cpp
// No fourth slot exists. Declaring here without implementation in any of the three locations causes a link-time error; implementing
// in two locations causes a duplicate definition error at link time. Therefore, claim the marked slot before proceeding.
//
// Two points for cross-file reuse; do not duplicate them.
//   - readTargetPage() ([P] implementation): Read back one 4096-byte page from the R-1 channel fragment.
//     Used in step 2 to capture the baseline, in step 4 for TOCTOU re-read, and in step 5 for actual page comparison.
//   - KvmHookPlan::composedShadowPage() ([P] implementation, declared in KvmHookPlan.h):
//     Currently calculates the final shadow page. Used in Step 2 for preview and Step 4 for installation.
// ===========================================================================
//
// 【All ksword::kvm::* calls are blocking IOCTLs and must never be invoked directly from the UI
//   thread.】 Follow the pattern in KvmViewDialog.cpp:221-272: QPointer + std::thread + detach +
//   QMetaObject::invokeMethod(Qt::QueuedConnection) returns to the UI thread.
//   This class prepares three components, as described in the 'Asynchronous Skeleton' section below: debouncing timer, single-flight flag, and sequence number.
//   The sequence number is mandatory. In Step 1, typing a character in the input box may trigger a translation request immediately. Since
//   the return order is not guaranteed to match the send order, omitting the sequence number causes old addresses to overwrite new ones.

#include <QByteArray>
#include <QDialog>
#include <QString>
#include <QVector>

#include <cstdint>

#include "KvmControl.h"
#include "KvmEptLeafProbe.h"
#include "KvmHookPlan.h"

class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTableWidget;
class QTimer;
class QWidget;

// HexEditorWidget resides in the global namespace (see UI/HexEditorWidget.h), not within ks::ui.
class HexEditorWidget;

namespace ks::ui
{
    // readTargetPage: reads back the 4096-byte page starting at pageBasePhysical. [P]
    //
    // R-1: The channel has a per-call limit of 1024 bytes, so it is fixed into 4 sequential reads. If any chunk
    // fails, return an empty QByteArray and write the reason to failureOut—never return a partial page, as a
    // baseline with missing bytes would result in a shadow page containing a zero-filled segment when executed.
    //
    // Blocks (4 READ_PHYSICAL calls); **must be called from a background thread only**. Do not touch any controls.
    QByteArray readTargetPage(quint64 pageBasePhysical, QString* failureOut);

    // KvmHookWizard: The main five-step wizard.
    class KvmHookWizard final : public QDialog
    {
        Q_OBJECT

    public:
        // Step: Page order, corresponding one-to-one with the index of m_pageStack.
        enum class Step : int
        {
            kTarget = 0,   // Select target
            kPatch = 1,    // Patch
            kPreflight = 2,// Pre-check
            kInstall = 3,  // install
            kVerify = 4,   // Verify
            kCount = 5
        };

        // JumpTemplate: The two jump templates provided in step 2.
        //
        // Both are required. As documented in HookPatchCompose.h, the distance between kernel modules
        // often exceeds ±2 GiB. Providing only near jumps causes the most common patch form to fail
        // frequently, and these failures tempt developers to modify other areas to work around them.
        enum class JumpTemplate : int
        {
            kNone = 0,
            kRel32Near,    // E9 + int32, 5 bytes; displacement base is the **next instruction**
            kAbsolute14    // FF 25 00000000 followed by a little-endian 8-byte absolute address; 14 bytes total.
        };

        explicit KvmHookWizard(QWidget* parent = nullptr);                  // [W]
        ~KvmHookWizard() override;                                          // [W]

        // openWizard: The sole entry point to open a wizard from the menu or panel. [W] Internally
        // manages non-modal lifecycle and WA_DeleteOnClose; callers must not perform their own new.
        static void openWizard(QWidget* parent);

        // plan: Read-only access to the current plan, for external verification (e.g., testing or debug panels).
        const KvmHookPlan& plan() const noexcept { return plan_; }
        // currentStep: Current step in the process.
        Step currentStep() const noexcept { return currentStep_; }

    private:
        // -------------------------------------------------------------
        // Snapshot structure for background tasks.
        // All fields are copyable: the entire snapshot is copied from the background thread to the UI thread without re-issuing IOCTLs on the UI thread.
        // -------------------------------------------------------------

        // PreflightSnapshot: Readings collected in one go at step 3 (one QUERY + one LIST).
        // Synthesize a background task because the two readings must come from the same instant: taking them separately causes a
        // self-contradictory screen where 'the state says not resident' while 'the view table shows an old value from the resident period'.
        struct PreflightSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            bool viewsOk = false;
            unsigned long viewCount = 0;
            QString viewsMessage;
        };

        // InstallOutcome: Result of the entire installation process in step 4.
        //
        // Fixed order: Re-read the target page -> compare with baselinePage -> only emit addView if they match.
        // TOCTOU comparison is not a formality: Several minutes may pass between capturing the baseline in step 2 and reaching this point. If
        // the target page was modified during this interval, the shadow page we construct contains **stale original bytes**, yet this shadow
        // page is the one actually executed. If the comparison fails, execution must stop; it is not merely a warning to continue installation.
        struct InstallOutcome
        {
            bool rereadOk = false;
            QString rereadFailure;
            bool baselineMatches = false;
            // freshPage: The page re-read. Use it for diff display on comparison failure
            // and as the ready result for 're-grabbing baseline' to avoid re-reading.
            QByteArray freshPage;
            // addAttempted: true if addView was actually issued. If false, the process is stuck in re-reading or comparison;
            // in this case, both failure codes in addResult remain zero, which coincidentally equals VIEW_STATUS_OK.
            // Therefore, to correctly determine failure, one must check this flag before evaluating addResult.ok.
            bool addAttempted = false;
            ksword::kvm::KvmViewResult addResult;
            // listAfter: Immediately re-read after successful installation to
            // obtain shadowPhysicalAddress, which is missing from the ADD response.
            ksword::kvm::KvmViewResult listAfter;
        };

        // VerifyStaticSnapshot: Step 5A segment (four readings not permanently available).
        struct VerifyStaticSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            ksword::kvm::KvmViewResult views;
            QByteArray rereadPage;
            QString rereadFailure;
            EptLeafProbeResult leaf;
        };

        // VerifyResidentSnapshot: Step 5, Segment B (the three entries that exist only after becoming resident).
        struct VerifyResidentSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            ksword::kvm::KvmViewResult views;
            ksword::kvm::KvmEventResult events;
        };

        // =============================================================
        // Skeleton and navigation — all [W]
        // =============================================================

        // buildUi: Builds the page stack, navigation bar, and status bar, then inserts the controls
        // returned by the five buildXxxPage() functions into m_pageStack in Step order. [W]
        void buildUi();

        // goToStep: Switches pages. It is solely responsible for the page stack index, navigation button states, and step
        // titles. [W] What to do upon entering a step is dispatched by enterStep(); do not mix these two responsibilities.
        void goToStep(Step step);

        // enterStep: Dispatch of actions triggered upon entering a step. [W]
        // - Target: If the module list has not been fetched yet, send a module enumeration request once;
        // - Patch: If the baseline has not been captured yet (or the target has changed), trigger a baseline capture.
        // - Preflight: Perform one preflight refresh;
        // - Install: Rebuild the summary text;
        // - Verify: send one A-segment checksum.
        // The dispatch itself occurs in [W]; the dispatched functions reside in their own respective files.
        void enterStep(Step step);

        // canLeaveStep: Determines whether the current step allows proceeding. If not, reasonOut contains
        // the reason. [W] This only blocks items that the next step will definitely need but are not yet
        // available (e.g., target unresolved, baseline incomplete, pre-check blocking failures). It does
        // not relax any driver-side checks, nor does it invent new checks on behalf of the driver.
        bool canLeaveStep(Step step, QString* reasonOut) const;

        // updateNavigationState: Refreshes Previous/Next/Close based on the current step and busy state. [W]
        void updateNavigationState();

        // setBusy: disables navigation and all action buttons while busy. [W]
        void setBusy(bool busy);

        // setStatusText: writes to the bottom global status bar and colors it according to the three-state verdict. [W]
        void setStatusText(const QString& text, KvmCheckVerdict verdict);

        // failBackTo: Roll back a failure to the step that caused it. [W]
        //
        // Rationale: KvmViewResult's message is a human-readable sentence; translating it loses the "which
        // step failed" context. Since the same protocolStatus can be produced by multiple branches (e.g.,
        // MULTIPROCESSOR_UNSAFE could mean "already resident" or "topology/capability mismatch"), only
        // pairing it with lastStatus distinguishes them. Therefore, pass the two-level failure codes as-is
        // to the target step, letting it decide how to interpret them, rather than guessing from strings.
        void failBackTo(
            Step step,
            const QString& reason,
            unsigned long protocolStatus,
            long lastStatus);

        // stepForViewFailure: maps an addView failure to the step it should roll back
        // to. [W] Called only when ok is false. The two failure codes remain zero on the
        // client-side rejection path, and zero corresponds exactly to VIEW_STATUS_OK.
        static Step stepForViewFailure(
            unsigned long protocolStatus,
            long lastStatus);

        // =============================================================
        // Step 1: Select target — All [W]
        // =============================================================

        // buildTargetPage: Constructs the control tree for Step 1, returns the page container. [W]
        QWidget* buildTargetPage();

        // onTargetSourceChanged: switches the sub-page of m_sourceStack when switching among the four
        // entry points, and clears fields in m_plan belonging to the old entry point. Leaving old
        // values would cause the summary in Step 4 to display a target the user no longer selects.
        void onTargetSourceChanged();

        // scheduleTargetResolve: debounces input changes by kInputDebounceMilliseconds, only triggering the actual IOCTL
        // translation once the debounce period expires. Sending an IOCTL for every keystroke would cripple the UI.
        void scheduleTargetResolve();

        // startTargetResolve: Initiates a background normalization (VA -> translate -> page geometry). [W] Single-flight:
        // If m_targetResolveInFlight is true, do not dispatch again; the debounce timer will trigger another attempt.
        void startTargetResolve();

        // applyTargetResolve: Apply the translation result after returning to the UI thread. [W] If sequence
        // differs from m_targetResolveSequence, **discard immediately**: that is a stale address invalidated by
        // subsequent input; applying it would cause a mismatch between the page geometry and the input field.
        void applyTargetResolve(
            quint64 sequence,
            const KvmHookTargetResolution& resolution);

        // resolveTargetBlocking: Normalizes the pipeline core; blocking; called from a background thread. [W]
        // Static and value-only: It does not touch controls, so it can be copied entirely into std::thread.
        static KvmHookTargetResolution resolveTargetBlocking(
            KvmHookTargetSource source,
            quint64 virtualAddress,
            quint64 rawPhysicalAddress);

        // refreshModuleList: enumerate kernel modules in the background and populate m_moduleBox.
        // [W] Uses KernelThreadAuditTab::queryKernelModules (R3 NtQuerySystemInformation, no
        // driver dependency), then projects results into KvmHookModuleChoice.
        void refreshModuleList();

        // updateTargetReadout: Refreshes the four geometric values from m_plan onto the four read-only labels. [W] These four
        // numbers represent the manual calculation step eliminated by this workflow and must always remain visible to the user.
        void updateTargetReadout();

        // allocateRehearsalPage / releaseRehearsalPage: allocation and deallocation of the rehearsal page. [W]
        //
        // Allocate one page (naturally 4 KiB aligned) using VirtualAlloc. After allocation, you must **write one
        // byte first, then call VirtualLock**: a page that is not resident may yield a failed translation or a
        // physical frame that can be swapped out at any time, and we are about to attach an EPT view to that frame.
        // Release in the destructor, and must occur after removing the view.
        bool allocateRehearsalPage();
        void releaseRehearsalPage();

        // =============================================================
        // Step 2: Patching — All [P]
        // =============================================================

        // buildPatchPage: Constructs the control tree for step 2 and returns the page container. [P] The center is
        // a HexEditorWidget (setEditable(true)); passing pageBasePhysical as the base address ensures the address
        // column in the hex view directly shows physical addresses, eliminating the need for mental calculation.
        QWidget* buildPatchPage();

        // startBaselineCapture: Background capture of a baseline page (readTargetPage).
        // [P] Standalone + sequence number; rules are the same as Step 1.
        void startBaselineCapture();

        // applyBaselineCapture: Apply the baseline page. [P] On success, load the
        // entire page into m_shadowEditor and jumpToAbsoluteAddress to pageBasePhysical
        // + pageOffset—the user cares about specific bytes, not the page start.
        void applyBaselineCapture(
            quint64 sequence,
            const QByteArray& page,
            const QString& failure);

        // onShadowByteEdited: Recalculate the patch after the user modifies a byte. [P]
        void onShadowByteEdited(
            std::uint64_t absoluteAddress,
            std::uint8_t oldValue,
            std::uint8_t newValue);

        // recomputePatchFromEditor: Compare the editor's current value with the baseline page
        // byte-by-byte, extract the segment from the "first differing byte .. last differing
        // byte" as patchBytes, and update m_plan.pageOffset to the start of that segment.
        //
        // Why patches are difference ranges rather than full pages: A view may exactly cover one page, and the resulting shadow page must
        // indeed be a full page. However, **patches** are the entities referenced by geometric checks (cross-page / non-empty) and rejection
        // reasons. If patches were full pages, they would always "just fit," causing geometric checks to degenerate into always passing.
        void recomputePatchFromEditor();

        // updatePatchSummary: Refreshes the patch summary (start address, length, cross-page conclusion, non-null conclusion). [P]
        void updatePatchSummary();

        // refreshPatchDisassembly: Disassemble a segment before and after the patch range
        // for display. [P] Uses ks::ui::InstructionDecoder::decode(bytes, base, X64).
        //
        // It does not answer whether a patch has cut through an instruction. x86 uses variable-length instructions; linear decoding
        // from an arbitrary offset is necessarily heuristic. The InstructionDecoder in the repository only supports forward decoding.
        // Therefore, the title of this section must clearly state that it is a **reference**, not a criterion, and must not display a green checkmark.
        void refreshPatchDisassembly();

        // applyJumpTemplate: Write a single jump instruction into the editor's current offset based on the template. [P]
        //
        // The displacement base for a near jump is the **next instruction** (5 bytes for E9 itself). The source
        // address is taken from virtualAddress, so there is no trusted source address under the RawPa entry.
        // These two templates must be disabled (KvmHookPlan::hasVirtualAddress() is provided for this purpose).
        // If the displacement cannot fit in an int32, explicitly reject it with the message 'Please
        // use a 14-byte absolute jump' instead of silently converting it to an absolute jump.
        void applyJumpTemplate(JumpTemplate templateKind, quint64 targetVa);

        // revertPatch: Restore the editor to the baseline page and clear patchBytes. [P]
        void revertPatch();

        // updatePatchEnabledState: Refreshes the availability of all controls in Step 2 based on
        // whether the baseline is ready, if the entry has a virtual address, and whether [P] is busy.
        void updatePatchEnabledState();

        // =============================================================
        // Step 3: Preflight — all [V]
        // =============================================================

        // buildPreflightPage: Build the control tree for step 3, return the page container. [V]
        // Table columns fixed: Criteria / Current Reading / Conclusion / Fix. Do not change the
        // number or order of columns; step 5 reuses the same column set for both tables.
        QWidget* buildPreflightPage();

        // schedulePreflightRefresh / startPreflightRefresh: debounce + single-flight + sequence ID. [V]
        void schedulePreflightRefresh();
        void startPreflightRefresh();

        // applyPreflightResult: Apply preflight readings. [V]
        // Discard if sequence differs from m_preflightSequence.
        void applyPreflightResult(
            quint64 sequence,
            const PreflightSnapshot& snapshot);

        // collectPreflightSnapshot: Fetches QUERY + LIST data in one go; blocking; runs on a background thread. [V]
        static PreflightSnapshot collectPreflightSnapshot();

        // buildPreflightRows: Computes KvmHookPreflightCriterion from readings + plan in the 11 lines
        // above. Pure function, does not touch controls, so it can be called directly by unit tests.
        //
        // Three rules that must not be violated:
        // - If the Topology is invalid, the only remedy is ExplainLocalEptUnreachable.
        // - The backend must check state.eptpSwitchArmed first to determine which capability bit to inspect;
        //   checking monitorTrapFlagReady alone would incorrectly classify nested Hyper-V guests as unsolvable.
        // - PatchGeometry fails directly when crossing pages; the option to 'split into two views' is not provided.
        static QVector<KvmCheckRow> buildPreflightRows(
            const PreflightSnapshot& snapshot,
            const KvmHookPlan& plan);

        // runPreflightRemedy: Executes the button in the 4th column. The three items that change state (write
        // permission gate, ensurePrepared, stopResident) each run their own background tasks and automatically
        // re-run the pre-check upon completion; the two Explain* items only display a description.
        void runPreflightRemedy(KvmCheckRemedy remedy);

        // hasBlockingPreflightFailure: Checks for any blocking criteria that have not
        // passed. [V] canLeaveStep(Step::Preflight) relies on this. NoReading **does not
        // count as passed**, but it is also not equivalent to Fail: a blocking NoReading
        // still prevents proceeding to the next step because "unknown" is not "installable".
        bool hasBlockingPreflightFailure() const;

        // =============================================================
        // Step 4: Install — all [W]
        // =============================================================

        // buildInstallPage: Build the control tree for step 4, returning the page container. [W]
        QWidget* buildInstallPage();

        // buildInstallSummaryText: Display the pre-installation summary exactly as follows: [W]
        // Entry and Target (Module + Offset / VA / PA / Rehearsal), virtualAddress,
        // fullPhysicalAddress, pageBasePhysical, pageOffset, patch start/end and length, shadow
        // page seed (Explicit, full page 4096), current backend (Default / EPTP switch), and
        // the statement 'HOOK is not a security boundary; failure implies pass-through'.
        QString buildInstallSummaryText() const;

        // startInstall: Completes the flow of confirmation -> re-read -> compare -> addView -> re-read. [W]
        //
        // Order must not be changed. Confirm execution.
        // ks::ui::confirmDestructiveAction(this, key, actionTitle,
        //                                  targetDescription, riskDescription)
        // —— Five parameters with ks::ui:: qualification. Ensure the dialog is displayed on the UI thread; only start the background thread after the dialog completes.
        //
        // The call shape of addView is fixed:
        //   addView(KSWORD_ARK_HVM_VIEW_KIND_HOOK,
        //           plan.pageBasePhysical,
        //           KvmViewShadowSeed::Explicit,
        //           plan.composedShadowPage())
        // seed must be Explicit: The HOOK's shadow page is the one being executed. Zero causes the processor to
        // execute a page of zero bytes, while FromTarget causes it to execute a page of unpatched original bytes.
        // Under Explicit, the shadow must be exactly 4096 bytes (KvmControl.cpp:1142-1150).
        void startInstall();

        // applyInstallOutcome: Applies the installation result. [W]
        // - On read failure or mismatch: failBackTo(Step::Patch, ...) and treat freshPage as a new
        //   baseline for the user to recompile, rather than forcing them to restart from Step 1;
        // - addView failure: failBackTo(stepForViewFailure(...), ...) passes through the two-level failure codes as-is.
        // - Success: Writes installedViewId / shadowPhysicalAddress
        //   / installed, then calls goToStep(Step::Verify).
        void applyInstallOutcome(const InstallOutcome& outcome);

        // performInstallBlocking: re-read + compare + addView + re-read, blocking,
        // background thread. [W] Static and value-only, does not touch controls.
        static InstallOutcome performInstallBlocking(
            quint64 pageBasePhysical,
            const QByteArray& baselinePage,
            const QByteArray& shadowPage);

        // =============================================================
        // Step 5: Verify — all [V]
        // =============================================================

        // buildVerifyPage: Constructs the control tree for Step 5, returning the page container. [V] The
        // upper half is the A segment table (four rows, non-resident is acceptable), and the lower half
        // is the B segment QGroupBox (three rows, requires resident status, **collapsed by default**).
        QWidget* buildVerifyPage();

        // startVerifyStatic / applyVerifyStatic: Fetching and landing of Segment A. [V]
        void startVerifyStatic();
        void applyVerifyStatic(
            quint64 sequence,
            const VerifyStaticSnapshot& snapshot);

        // collectVerifyStaticSnapshot: Collects QUERY + LIST + re-read one page +
        // [V] readBaseEptLeaf in one go. Blocking, runs on a background thread.
        static VerifyStaticSnapshot collectVerifyStaticSnapshot(
            quint64 pageBasePhysical);

        // buildVerifyStaticRows: Computes the 4 rows of Segment A. Pure function. [V]
        //
        // The blind spot for each BaseEptLeafNotExecutable entry must be reported truthfully:
        // Note: When snapshot.state.localEptArmed or eptpSwitchArmed is true, the probe reads
        // **Base** layer, while running processors hang on a separate tree branching from the base; a probe
        // cannot read a single byte from them. In that case, this entry must be NoReading, and the reading
        // column must state: "This reading describes the base, not the currently running processor."
        // See the 'Known Blind Spots' section in the header of KvmEptLeafProbe.h.
        static QVector<KvmCheckRow> buildVerifyStaticRows(
            const VerifyStaticSnapshot& snapshot,
            const KvmHookPlan& plan);

        // startVerifyResident / applyVerifyResident: Fetching and committing data for Segment B. [V] Segment B is
        // only triggered when the user explicitly expands the group and clicks the button—it reads counts and events
        // from the resident period; automatic triggering would cause an IOCTL to fire behind a collapsed group.
        void startVerifyResident();
        void applyVerifyResident(
            quint64 sequence,
            const VerifyResidentSnapshot& snapshot);

        // collectVerifyResidentSnapshot: QUERY + LIST + readEvents. Blocking. [V]
        // Pass m_eventCursor for afterSequence; pass false for clear: clearing
        // would wipe out events currently being consumed by other panels.
        static VerifyResidentSnapshot collectVerifyResidentSnapshot(
            unsigned long long afterSequence);

        // buildVerifyResidentRows: Computes the 3 rows of Segment B. Pure function. [V]
        //
        // The three independent ternary rules: if written incorrectly, the entire B segment becomes a false predicate.
        // - FlipCount: if state.eptpSwitchArmed is true -> **NoReading**, the reading
        //   column displays "This backend does not generate this count" (the only increment
        //   point is hvm_ept_view.c:903; switching backends returns early at :821). Under
        //   the default backend, > 0 passes; == 0 is NoReading (page not touched), not Fail.
        // - FlipEventObserved: No row with ruleId == viewId exists in the event loop -> NoReading, not Fail. The
        //   target function was not executed within the observation window; it is neither success nor failure.
        // - ExecutionRedirected: **Always NoReading**, remedy = ExplainNotMeasured.
        //   "HOOK direction not yet tested" is the original roadmap text; the UI must label it exactly as is without modification.
        static QVector<KvmCheckRow> buildVerifyResidentRows(
            const VerifyResidentSnapshot& snapshot,
            const KvmHookPlan& plan);

        // fillCheckTable: Populate a four-column table with a set of rows and color the conclusion column based on three-state values. [V] The
        // pre-check table and validation table share this function, ensuring column semantics remain consistent across all three locations.
        static void fillCheckTable(
            QTableWidget* table,
            const QVector<KvmCheckRow>& rows);

        // =============================================================
        // Async skeleton
        // =============================================================
        //
        // Set of three: all three must be present for each async entry point.
        //   1) Debounce timer: required only for input-triggered actions (Step 1 and Step 3);
        //   2) Single-flight flag: Do not dispatch if already in flight to prevent two threads from competing for the same state lock simultaneously.
        //   3) Sequence number: **Required**. The return order is not guaranteed to match the send order; discard if sequence numbers do not match.
        //      A single in-flight flag is insufficient: it only guarantees at most one request is in
        //      flight, but not that the response still corresponds to the address the user currently wants.

        static constexpr int kInputDebounceMilliseconds = 250;

        QTimer* targetDebounce_ = nullptr;
        bool targetResolveInFlight_ = false;
        quint64 targetResolveSequence_ = 0;

        bool moduleQueryInFlight_ = false;
        quint64 moduleQuerySequence_ = 0;

        bool baselineInFlight_ = false;
        quint64 baselineSequence_ = 0;

        QTimer* preflightDebounce_ = nullptr;
        bool preflightInFlight_ = false;
        quint64 preflightSequence_ = 0;

        bool installInFlight_ = false;

        bool verifyStaticInFlight_ = false;
        quint64 verifyStaticSequence_ = 0;
        bool verifyResidentInFlight_ = false;
        quint64 verifyResidentSequence_ = 0;

        // =============================================================
        // Cross-step shared state.
        // =============================================================

        // m_plan: The single mutable state shared across the five steps. See KvmHookPlan.h for which section writes which part.
        KvmHookPlan plan_;

        // m_modules: Data source for the module dropdown in Step 1, corresponding one-to-one with the row order of m_moduleBox.
        QVector<KvmHookModuleChoice> modules_;

        // m_preflightRows / m_verifyStaticRows / m_verifyResidentRows：
        // Current contents of the three tables. Kept so that both the 'any blocking checks still failing' logic and the callback for
        // the 4th column button draw from the same data source, rather than reading string values from the table controls later.
        QVector<KvmCheckRow> preflightRows_;
        QVector<KvmCheckRow> verifyStaticRows_;
        QVector<KvmCheckRow> verifyResidentRows_;

        // m_eventCursor: Consumer cursor for B-segment read events (KvmEventEntry::sequence is monotonically increasing).
        unsigned long long eventCursor_ = 0;

        // m_rehearsalPage: Rehearsal entry page allocated by itself.
        // Allocated via VirtualAlloc, naturally 4 KiB aligned; after allocation, write one byte and
        // call VirtualLock, otherwise the translated frame may be swapped out at any time. Ownership
        // belongs to this dialog; release in the destructor (and only after removing the view).
        void* rehearsalPage_ = nullptr;

        Step currentStep_ = Step::kTarget;
        bool busy_ = false;

        // =============================================================
        // Control
        // =============================================================

        // ---- Skeleton (Create) ----
        QStackedWidget* pageStack_ = nullptr;
        QLabel* stepTitleLabel_ = nullptr;
        QLabel* stepHintLabel_ = nullptr;
        QPushButton* backButton_ = nullptr;
        QPushButton* nextButton_ = nullptr;
        QPushButton* closeButton_ = nullptr;
        QLabel* statusLabel_ = nullptr;

        // ---- Step 1 (Create) ----
        QComboBox* sourceBox_ = nullptr;
        QStackedWidget* sourceStack_ = nullptr;
        QComboBox* moduleBox_ = nullptr;
        QPushButton* moduleReloadButton_ = nullptr;
        QLineEdit* moduleOffsetEdit_ = nullptr;
        QLabel* moduleRangeLabel_ = nullptr;
        QLineEdit* kernelVaEdit_ = nullptr;
        QLineEdit* rawPaEdit_ = nullptr;
        QPushButton* rehearsalAllocButton_ = nullptr;
        QLabel* rehearsalLabel_ = nullptr;
        // Read-only display of the four normalized pipeline outputs—these four values represent
        // the manual calculation step eliminated by this flow and must remain visible.
        QLabel* readoutVaLabel_ = nullptr;
        QLabel* readoutFullPaLabel_ = nullptr;
        QLabel* readoutPageBaseLabel_ = nullptr;
        QLabel* readoutPageOffsetLabel_ = nullptr;
        QLabel* targetStatusLabel_ = nullptr;

        // ---- Step 2 (Create) ----
        HexEditorWidget* shadowEditor_ = nullptr;
        QPushButton* recaptureBaselineButton_ = nullptr;
        QPushButton* revertPatchButton_ = nullptr;
        QComboBox* jumpTemplateBox_ = nullptr;
        QLineEdit* jumpTargetEdit_ = nullptr;
        QPushButton* applyJumpButton_ = nullptr;
        QLabel* patchSummaryLabel_ = nullptr;
        QPlainTextEdit* patchDisassemblyView_ = nullptr;
        QLabel* patchStatusLabel_ = nullptr;

        // ---- Step 3 (Create) ----
        QTableWidget* preflightTable_ = nullptr;
        QPushButton* preflightRefreshButton_ = nullptr;
        QLabel* preflightStatusLabel_ = nullptr;

        // ---- Step 4 (Create) ----
        QPlainTextEdit* installSummaryView_ = nullptr;
        QPushButton* installButton_ = nullptr;
        QLabel* installStatusLabel_ = nullptr;

        // ---- Step 5 (Create) ----
        QTableWidget* verifyStaticTable_ = nullptr;
        QPushButton* verifyRefreshButton_ = nullptr;
        QGroupBox* verifyResidentGroup_ = nullptr; // Checkable, collapsed by default.
        QTableWidget* verifyResidentTable_ = nullptr;
        QPushButton* verifyResidentButton_ = nullptr;
        QLabel* verifyStatusLabel_ = nullptr;
    };
}
