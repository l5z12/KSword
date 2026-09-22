/*++

Module Name:

    hvm_ept_view.h

Abstract:

    Declares EPT split views: one guest-physical page backed by two different
    frames depending on whether it is executed or read.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_ept.h"

EXTERN_C_START

/*
 * Execute one versioned EPT view operation, acquiring lifecycle ownership.
 * Mutating operations are refused while any processor is resident, because the
 * VM-exit path reads the view table without taking this PASSIVE_LEVEL lock.
 */
NTSTATUS
kswordArkHvmEptViewControl(
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* response
    );

/* Execute one versioned EPT view operation under the runtime lock. */
NTSTATUS
kswordArkHvmEptViewControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* response
    );

/* Restore every leaf and release every shadow before EPT pages are freed. */
VOID
kswordArkHvmEptViewResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/*
 * Report whether every installed view is served by switching EPT_POINTER
 * rather than by flipping a shared leaf.
 *
 * This is the property the multicore gates actually care about. A leaf flip
 * edits a table every processor walks, so on a shared hierarchy the window is
 * visible machine-wide; a hierarchy switch writes only this processor's VMCS
 * and its index is per-VCPU, so it carries no such window.
 *
 * Asking the views directly, rather than asking whether the switching backend
 * is armed, is deliberate. The two agree today - an armed install that cannot
 * build or verify its hierarchy is refused outright and never falls back to
 * the base (hvm_ept_view.c, the EptpSwitchArmed branch of the add path) - but
 * that is three separate facts holding at once, and the failure mode if any of
 * them ever stops holding is a shared-leaf flip on a multicore box: silent
 * data corruption with no exit, no event and no bugcheck. A predicate over the
 * installed records cannot be broken that way.
 *
 * An empty table returns TRUE: there is nothing that could flip a leaf.
 * Caller must hold the runtime lock.
 */
BOOLEAN
kswordArkHvmEptViewAllSwitchBackedLocked(
    _In_ const KswHvmRuntime* runtime
    );

/*
 * Which service method was selected upon view hit.
 *
 * Note: The reason for existence is that the two backends **must take different cleanup paths** on exit: the leaf-write mechanism requires armed handling.
 * Only monitor-trap can return; once the EPTP switching mechanism is armed, it
 * will fail on the next VM entry (on machines without MTF, VMWRITE succeeds but VM
 * entry fails). Using a single return value to represent both outcomes delegates
 * this distinction to the caller; the cost of forgetting is silently exiting VMX.
 */
typedef struct KswHvmEptViewSwitch
{
    /* TRUE indicates the EPTP switch service is responsible: the caller must NOT arm monitor-trap. */
    BOOLEAN requested;
    /* Maintain natural alignment for the subsequent 32-bit member. */
    UCHAR reserved0[3];
    /* Slot number of the violation leaf in the view table (0-based), i.e., hierarchy index minus one. */
    ULONG leafSlot;
    /* The kind of this view; the switch scheduler uses it to fetch primary/secondary permissions. */
    ULONG kind;
    /* Ensure the structure is explicitly initialized for both architectures. */
    ULONG reserved1;
} KswHvmEptViewSwitch;

/*
 * Service one view violation.
 *
 * With the default backend this flips the view's leaf to its secondary value
 * for a single instruction and the caller arms monitor-trap to restore it,
 * which is the same mechanism allow-once rules use.
 *
 * With the EPTP-switching backend **no leaf is written**: the secondary value
 * already lives in that leaf's own hierarchy, so the function only reports
 * which leaf and which kind, and the caller switches the pointer instead.
 */
/*
 * Get the kernel virtual address of the shadow page for the specified view ID; return NULL if not found.
 *
 * This exists because R-1 injection must write a return address into the shadow page from within the VMX root. The shadow is
 * non-paged memory allocated by the driver, accessible at any IRQL; however, its pointer is known only to the view table. Since the
 * injection side only retains the view ID, forcing it to look up the view table would leak the internal layout of the view table.
 */
volatile UCHAR*
kswordArkHvmEptViewShadowForViewId(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONG viewId
    );

BOOLEAN
kswordArkHvmEptViewHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access,
    _In_opt_ const KswHvmEptLocal* local,
    _Out_ KswHvmEptTransient* transient,
    _Out_ ULONG* viewId,
    _Out_ KswHvmEptViewSwitch* Switch
    );

EXTERN_C_END
