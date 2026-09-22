#pragma once

// KvmHookPlan: All values from the moment a user selects a target to the moment the hook is installed, within a single HOOK view.
//
// Reason for existence:
// - Today, installing a single HOOK view requires the user to perform three manual steps: converting symbols/offsets to virtual addresses, translating virtual addresses
//   to physical addresses, and manually calculating page alignment for physical addresses. If any step is calculated incorrectly, the driver will not report an error:
//   It only checks for 'page-aligned' and 'less than 8 TiB' (hvm_ept_view.c:288-295), neither verifying if the
//   target page is RAM nor who owns it. The incorrect result is attaching a HOOK to an unrelated page of memory.
// - This layer makes those three steps mandatory and stores every intermediate result in the structure, so preflight
//   checks, installation summaries, and validation use the same values instead of recomputing them independently.
//
// This header contains no Qt widgets and sends no IOCTLs: it is a copyable value object that can
// be copied entirely into a background thread and back. The wizard shares this across steps.
//
// 【The shadow page for HOOK is the one being executed】: In the driver's steady state, the primary leaf = real page
//   | READ | WRITE (no EXECUTE); in the flipped state, the secondary leaf = shadow page | EXECUTE (hvm_ept_view.c:180
//   and :186-190). Therefore, the shadow page must be a complete 4096-byte page consisting of 'original page +
//   patch'. Every byte outside the patch interval must match the original page bit-by-bit; otherwise, the processor
//   will execute garbage when redirected there. Construction is handled by the arithmetic layer in shared/evidence.
//
// [CLOAK/HOOK is not a security boundary] This layer only ensures numerical correctness. Any
//   documentation referencing this must not imply that HOOK can defend against an authorized adversary.

#include <QByteArray>
#include <QString>
#include <QVector>
#include <QtGlobal>

#include <cstdint>

#include "../../../shared/evidence/HookPatchCompose.h"
#include "ThemeStatusRole.h"

namespace ks::ui
{
    // ---------------------------------------------------------------------
    // Target entry
    // ---------------------------------------------------------------------

    // KvmHookTargetSource: The entry point from which the user specified the target.
    //
    // All four entry points converge to the same normalized pipeline (see
    // KvmHookTargetResolution); the difference lies solely in how the virtual address is obtained:
    // - ModuleOffset: Module base address + offset. This is the most common method and the only one that
    //   prevents "off-by-one address errors" because the offset is bounded by the module's imageSize.
    // - KernelVa: User directly provides a kernel virtual address. No ownership validation is performed; only translation is done;
    // - RawPa: user provides physical address directly, skipping translation (virtualAddress remains 0).
    //   This is the only path where a virtual address cannot be obtained. Therefore, the patch's near/relative jump encoding
    //   lacks a trustworthy source address on this path; the upper layer must disable the jump template accordingly.
    // - Rehearsal: The target is a page allocated by this process itself, which will not affect anyone else when installed.
    //   It is the only entry point in this flow that can complete all five steps without risk, so it is not a toy:
    //   Preconditions, TOCTOU comparisons, and validation criteria must match the real target item-by-item during rehearsal.
    enum class KvmHookTargetSource : int
    {
        kModuleOffset = 0,
        kKernelVa,
        kRawPa,
        kRehearsal
    };

    // KvmHookModuleChoice: An item in the kernel module dropdown.
    //
    // It is a lightweight projection of KernelThreadAuditTab::ModuleRecord. It deliberately does not directly reuse that structure: that
    // header file includes Framework.h and Win32 dependencies, whereas this header file must be referenceable by the pure value layer.
    // Conversion is performed in KvmHookWizard.cpp.
    struct KvmHookModuleChoice
    {
        QString name;
        QString path;
        quint64 baseAddress = 0;
        // imageSize promoted to 64-bit: The upper bound of the offset must be compared using 64-bit; using 32-bit for
        // comparison would calculate an out-of-bounds offset as a seemingly valid address during the "base + offset" step.
        quint64 imageSize = 0;
        bool kernelImage = false;
    };

    // ---------------------------------------------------------------------
    // Output of the normalized pipeline
    // ---------------------------------------------------------------------

    // KvmHookTargetResolution: Result of a single 'virtual address -> physical address -> page geometry' resolution.
    //
    // Fixed three steps; order must not be changed:
    //   1) Calculate virtualAddress based on the entry point;
    //   2) translate(0, virtualAddress) to obtain fullPhysicalAddress (**including page offset**);
    //   3) pageBasePhysical = fullPhysicalAddress & ~0xFFFULL，
    //      pageOffset       = fullPhysicalAddress &  0xFFFULL。
    // Step 3 is the manual calculation step eliminated by this flow — it used to reside in the user's mind.
    //
    // directoryBase is always passed as 0: the driver uses __readcr3(), and kernel addresses can be resolved in any process page table.
    // The rehearsal entry target resides in the user space of this process, and the calling thread is already in this process, so the same holds true.
    struct KvmHookTargetResolution
    {
        bool ok = false;
        // resolvedVirtualAddress: Always 0 under the RawPa entry, as that path has no virtual address.
        quint64 virtualAddress = 0;
        quint64 fullPhysicalAddress = 0;
        quint64 pageBasePhysical = 0;
        quint32 pageOffset = 0;
        // usedDirectWindow: Indicates whether translation actually utilized the private page table
        // window. If false, it degraded to the MmCopyMemory path; translation still succeeds, but
        // kernel-level hooks are no longer bypassed. This is a truthful metric, not a failure.
        bool usedDirectWindow = false;
        // message: A localized conclusion or failure reason that can be displayed directly.
        QString message;
    };

    // ---------------------------------------------------------------------
    // Three-state verdict — pre-check and validation share the same set.
    // ---------------------------------------------------------------------

    // KvmCheckVerdict: The verdict of a single criterion.
    //
    // **NoReading must be a distinct state**: this is the sole reason this enum exists:
    // Target function not executed within the observation window is neither pass nor fail;
    // Even with the EPTP switch backend, flipCount remains 0; this is not considered a failure (the only increment point is...)
    // hvm_ept_view.c:903, the backend switch returns early at line :821).
    // With only two states, these two readings are forcibly painted green or red, and both painting methods are lies.
    enum class KvmCheckVerdict : int
    {
        kPass = 0,
        kFail,
        kNoReading
    };

    // KvmCheckRemedy: A 'remedy' action paired with a criterion.
    //
    // Note ExplainLocalEptUnreachable: it is **not a viable path**. On multi-core systems, installing the view
    // requires LocalEptArmed. Although ENABLE_LOCAL_EPT is read by PREPARE (hvm_runtime.c:1573-1582), it is
    // not in PREPARE's allowedFlags whitelist (:2682-2685). The driver comments describe this as a standing
    // defect (:2674-2681). Consequently, this check is unreachable via protocol on multi-core systems.
    // This button only opens an explanation; it must never pretend to fix the
    // issue. A useless 'Enable Private EPT' button is worse than no button at all.
    enum class KvmCheckRemedy : int
    {
        kNone = 0,
        // Enable the R-1 write access gate via ks::ui::requestKvmWriteAccess.
        kEnableWriteAccess,
        // Calls ensurePrepared() to ensure resources are ready.
        kPrepareResources,
        // Execute stopResident() to leave resident mode—the view table cannot be modified during resident mode.
        kStopResident,
        // Open EPTP switch backend: it is triggered only by PREPARE, so
        // releaseResources() + ensurePrepared() must be called for it to take effect.
        kSwitchToEptpBackend,
        // Open the view panel to make room (view table is full, max KSWORD_ARK_HVM_MAX_VIEWS = 32).
        kOpenViewPanel,
        // Return to step 1 to reselect the target.
        kReturnToTargetStep,
        // Return to step 2 to recompile the patch.
        kReturnToPatchStep,
        // Re-capture the baseline page.
        kRecaptureBaseline,
        // Explain only, do not fix. See the section above.
        kExplainLocalEptUnreachable,
        // Explain only, do not fix: this criterion itself means 'not measured in this project'.
        kExplainNotMeasured
    };

    // KvmCheckRow: A row in the pre-check or validation table. Four columns: criterion, current reading, conclusion, and fix button.
    struct KvmCheckRow
    {
        // criterionId: the index of the criterion corresponding to this line. The pre-check table uses KvmHookPreflightCriterion,
        // the A-segment verification uses KvmHookVerifyCriterion, and the B-segment uses KvmHookResidentCriterion.
        // Store as int to allow the three tables to share the same row structure without mutually including each other's enums.
        int criterionId = 0;
        // criterion: the criterion itself, one sentence (column 1).
        QString criterion;
        // reading: **Current measured reading**, must include specific numeric values/status bits (column 2).
        // Do not write the conclusion in this column; only record what was read. The conclusion belongs in the next column.
        QString reading;
        // verdict: Three-state conclusion (semantic source from column 3).
        KvmCheckVerdict verdict = KvmCheckVerdict::kNoReading;
        // conclusion: One-sentence summary of the conclusion (text from column 3).
        // When NoReading, it must be clear why there is no reading; otherwise, it appears as a failure.
        QString conclusion;
        // remedy / remedyLabel: Column 4 button. No button is placed when remedy is None.
        KvmCheckRemedy remedy = KvmCheckRemedy::kNone;
        QString remedyLabel;
        // blocking: Whether to continue installation if this check fails.
        // Only the few cases where the driver truly rejects are blocking; observational readings (e.g., whether translation
        // used a private window) are not. The UI must not relax driver-side preflight checks, nor should it invent new ones.
        bool blocking = false;
    };

    // KvmHookPreflightCriterion: Set of pre-check criteria for Step 3 (order corresponds to row order; frozen).
    //
    // The first seven items correspond one-to-one with the pre-installation checks in the driver installation
    // view; see KvmControl.h for KvmState's resourcesReady / eptReady / inveptSingleReady / monitorTrapFlagReady
    // bits and hvm_ept_view.c. The last four items are geometric and content checks specific to this layer.
    enum class KvmHookPreflightCriterion : int
    {
        // R-1 write access gate is open (the second gate on the client side; the driver side must additionally verify the token).
        kWriteAccessGate = 0,
        // PREPARE has been executed and TEARDOWN has not occurred (KvmState::resourcesReady).
        kResourcesPrepared,
        // NotResident: during residency, the driver refuses to modify the view table (KvmState::residentActive is false).
        kNotResident,
        // EPT hierarchy is established (KvmState::eptReady).
        kEptReady,
        // Topology: processorCount == 1 || localEptArmed.
        // If not satisfied, remedy = ExplainLocalEptUnreachable; see above.
        kTopology,
        // Single-context INVEPT is available (KvmState::inveptSingleReady). Both backend implementations require it.
        kInveptSingle,
        // Backend capabilities: when eptpSwitchArmed is true, check execute-only (determined by the driver; this
        // only relays the status bit); when false, check monitorTrapFlagReady. **Must be evaluated together with
        // eptpSwitchArmed**—checking MTF alone may misclassify nested Hyper-V guests as unsolvable.
        kBackend,
        // View table capacity: installed count < KSWORD_ARK_HVM_MAX_VIEWS (32).
        kViewTableCapacity,
        // Target page geometry: pageBasePhysical is page-aligned and < 8 TiB. The driver checks only these two conditions.
        kTargetPageGeometry,
        // Patch geometry: classifyCrossPage is classified as InPage, and the patch is non-null.
        // Cross-page operations fail-closed and are rejected directly under both backends; do not split into two views.
        kPatchGeometry,
        // Baseline page complete: exactly 4096 bytes and the exact copy read back from the target page.
        kBaselineComplete,
        kCount
    };

    // KvmHookVerifyCriterion: Step 5, Segment A (the four readings that are not permanently resident and available).
    enum class KvmHookVerifyCriterion : int
    {
        // This viewId exists in listViews() and kind == HOOK.
        kViewPresent = 0,
        // shadowPhysicalAddress is non-zero and not equal to pageBasePhysical.
        kShadowDistinct,
        // Real page unchanged: re-reading pageBasePhysical should yield a page identical byte-by-byte to baselinePage.
        // HOOK does not modify the real page; if this fails, it indicates something else has modified it.
        kRealPageUnchanged,
        // Base EPT leaf readback: steady-state primary leaf = true page | R | W, **no X**.
        // Thus, the criterion is reachedLeaf && !executable.
        // [Blind spot] When localEptArmed or eptpSwitchArmed is true, the probe reads the base, while
        // the running processor is attached to a different tree—under these conditions, this entry must
        // be treated as NoReading, neither passing nor failing. See the header of KvmEptLeafProbe.h.
        kBaseEptLeafNotExecutable,
        kCount
    };

    // KvmHookResidentCriterion: Step 5, Segment B (the three items present only when resident mode is enabled, folded by default).
    //
    // It is collapsed by default because this section requires the user to explicitly activate a resident component, which incurs a cost.
    // Two of the three criteria are destined to be NoReading under common configurations; expanding them by default only creates anxiety.
    enum class KvmHookResidentCriterion : int
    {
        // flipCount > 0. **Incremented only under the default backend (write-leaf + MTF)** (the sole increment point).
        // hvm_ept_view.c:903); The EPTP switch backend returns early at :821, so flipCount remains constantly 0.
        // Before reading this entry, must check eptpSwitchArmed: under a switched backend,
        // this means 'this backend does not generate this count' = NoReading, not a failure.
        kFlipCount = 0,
        // A flip event occurred in the event loop where ruleId == viewId (readEvents;
        // KvmEventEntry's ruleId carries the viewId for view flips). If no such event
        // occurred, the target page was not touched within the observation window = NoReading.
        kFlipEventObserved,
        // HOOK direction—whether execution is truly redirected to a shadow page—**not yet tested in this project**.
        // This entry is always NoReading; use the exact wording from the roadmap document; do not change it to "verified".
        kExecutionRedirected,
        kCount
    };

    // ---------------------------------------------------------------------
    // Plan body
    // ---------------------------------------------------------------------

    // KvmHookPlan: The single mutable state shared by the five-step wizard.
    //
    // It is a pure value: can be copied entirely to a background thread for computation and copied back, containing no pointers, no
    // controls, and owning no system resources (ownership of rehearsal pages lies with the wizard; here we only record its virtual address).
    struct KvmHookPlan
    {
        // ---- Step 1: Target ----
        KvmHookTargetSource targetSource = KvmHookTargetSource::kRehearsal;
        // Three values for the module entry point. For other entry points, moduleName is empty and moduleBase/imageSize are 0.
        QString moduleName;
        quint64 moduleBase = 0;
        quint64 imageSize = 0;
        // offset: Offset within the module under the module entry point; 0 for other entry points.
        quint64 offset = 0;
        // virtualAddress: Output of normalization pipeline step 1. Under RawPa entry, it is 0.
        quint64 virtualAddress = 0;
        // fullPhysicalAddress: return value of translate, **including page offset**.
        quint64 fullPhysicalAddress = 0;
        // pageBasePhysical / pageOffset: Output from Step 3; pageBasePhysical is used during installation.
        quint64 pageBasePhysical = 0;
        quint32 pageOffset = 0;
        // resolved: True if the normalization pipeline completed successfully. If false, pageBasePhysical is untrusted.
        bool resolved = false;

        // ---- Step 2: Patch ----
        // baselinePage: The current 4096-byte target page, read back from the R-1 channel fragment.
        // It serves as both the shadow page baseline and the TOCTOU comparison baseline for step 4.
        QByteArray baselinePage;
        // patchBytes: The actual user-modified segment, starting at pageOffset.
        // It represents the difference between the 'finished shadow page' and the 'baseline page', not the entire page. The full page is computed on-the-fly by composedShadowPage().
        QByteArray patchBytes;

        // ---- Step 4: Installation Result ----
        // installedViewId: The viewId after addView succeeds. 0 indicates not yet installed.
        unsigned long installedViewId = 0;
        // shadowPhysicalAddress: The shadow page physical address allocated by the driver, read back from listViews.
        quint64 shadowPhysicalAddress = 0;
        // installed: Indicates addView returned success. Note that this only means the driver accepted the
        // request, not that the leaf was actually modified—that requires reading the result in step 5.
        bool installed = false;

        // ---- Trivial inline evaluation ----

        // baselineIsComplete: The baseline page is exactly one full page. Fragmented reads fail if even one page is missing;
        // using an incomplete baseline to construct shadow pages will introduce a zero-byte segment in the executed page.
        bool baselineIsComplete() const noexcept
        {
            return baselinePage.size()
                == static_cast<qsizetype>(ksword::evidence::kPatchPageBytes);
        }

        // patchIsEmpty: An empty patch produces shadow pages bitwise identical to the original pages. This leaves the HOOK view
        // unchanged, misleading users into thinking the patch was applied. This is a caller error, not a valid identity patch.
        bool patchIsEmpty() const noexcept { return patchBytes.isEmpty(); }

        // patchLength / patchEndOffset: Used for geometric validation. Promoting both to 64-bit ensures that wraparound from
        // 32-bit addition does not incorrectly calculate an obviously out-of-bounds request as a small sum within a single page.
        quint64 patchLength() const noexcept
        {
            return static_cast<quint64>(patchBytes.size());
        }
        quint64 patchEndOffset() const noexcept
        {
            return static_cast<quint64>(pageOffset) + patchLength();
        }

        // pageIsAligned: The driver only checks this condition and the 8 TiB upper bound, so this check must be performed on the client side first.
        bool pageIsAligned() const noexcept
        {
            return (pageBasePhysical & 0xFFFULL) == 0ULL;
        }

        // hasVirtualAddress: Virtual addresses cannot be obtained from RawPa entries; since there is
        // no trusted source address on the jump encoding path, the jump template must be disabled.
        bool hasVirtualAddress() const noexcept
        {
            return targetSource != KvmHookTargetSource::kRawPa
                && virtualAddress != 0ULL;
        }

        // ---- Non-trivial evaluation: implementation in KvmHookWizard.Patch.cpp ----

        // composedShadowPage: Computes a complete shadow page = baseline page + patch.
        //
        // Computed on-the-fly without caching, because cached composite pages can become inconsistent with
        // the baseline and patch; the inconsistent version is precisely the one executed by the processor.
        //
        // Internally uses ksword::evidence::composePage; the check order is fixed by the unit tests of that layer:
        // Original page pointer -> patch pointer -> geometry -> empty patch.
        // Note: Return an empty QByteArray on failure (do not return a half-baked page that is
        // 'almost usable'). If failureReasonOut is non-null, write a localized rejection reason.
        QByteArray composedShadowPage(QString* failureReasonOut = nullptr) const;

        // classifyPatchGeometry: Whether the patch fits in this page.
        // Implemented in KvmHookWizard.Patch.cpp; this is just a forwarding layer for classifyCrossPage. It
        // is kept here so that the pre-check and the immediate prompt in step 2 reference the same judgment.
        ksword::evidence::CrossPageClassification classifyPatchGeometry() const;
    };

    // ---------------------------------------------------------------------
    // Free functions (implementation locations see respective comments)
    // ---------------------------------------------------------------------

    // describeHookTargetSource: Entry name, localized. Implementation in KvmHookWizard.cpp.
    QString describeHookTargetSource(KvmHookTargetSource source);

    // describeCheckVerdict: A localized one-line description of the three-state verdict. Implementation is in KvmHookWizard.Verify.cpp.
    QString describeCheckVerdict(KvmCheckVerdict verdict);

    // checkVerdictStatusRole: Mapping from three-state verdicts to semantic status colors for table and status bar coloring.
    //
    // Fixed convention: Pass -> StatusRole::Success, Fail -> StatusRole::Error,
    // NoReading -> StatusRole::Idle. NoReading must use a neutral color—red
    // implies failure, green implies success, but neither applies.
    // Implemented in KvmHookWizard.Verify.cpp.
    StatusRole checkVerdictStatusRole(KvmCheckVerdict verdict);
}
