/*++

Module Name:

    hvm_ept_view.c

Abstract:

    EPT split views.

    A view gives one guest-physical page two backing frames and picks between
    them by access type.  CLOAK keeps execution on the real page and sends every
    read and write to a shadow, so code runs while memory scanners see the
    shadow's contents.  HOOK is the mirror: reads see the real page while
    execution runs from a shadow holding patched instructions, which is a
    breakpoint that byte comparison cannot find.

    The mechanism is the leaf flip.  The primary value denies exactly the access
    that must be redirected; the resulting EPT violation installs the secondary
    value, and the monitor-trap exit that follows restores the primary one.
    That reuses the allow-once transient machinery unchanged - a view flip is
    an allow-once grant whose restored value happens to point at a different
    frame.

    The consequence used to be inherited too: with one shared EPT hierarchy a
    second resident processor could execute through the secondary value during
    the one-instruction window, so views were refused unless exactly one VCPU
    was resident.

    hvm_ept_local.c removes that restriction where it is armed.  Each
    processor walks its own copy of the tables leading to a flippable leaf, so
    a flip reaches only the processor that took the exit.  The single-VCPU
    refusal therefore applies only when no private hierarchy was built.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root violations.

--*/

#include "hvm_ept_view.h"
#include "hvm_ept_switch.h"
/*
 * For kswordArkHvmResidentInvalidateEpt.  The view path must not issue INVEPT
 * itself: the instruction is #UD outside VMX operation, and both of the places
 * below run from the IOCTL path, where no processor need be in VMX operation at
 * all.  It is also per-logical-processor, so even when residency is up, issuing
 * it here would leave every other processor holding stale translations.
 */
#include "hvm_resident.h"

/* Return the active view that owns one page-aligned physical address. */
static KswHvmEptViewSlot*
kswordArkHvmEptViewFind(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalPage
    )
{
    ULONG index = 0UL;

    /* Search the bounded view table without allocation. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Match only installed views covering the exact page. */
        if (runtime->eptViews[index].active &&
            runtime->eptViews[index].physicalAddress == physicalPage) {
            /* Return the exact installed view. */
            return &runtime->eptViews[index];
        }
    }
    /* Report that no view covers the page. */
    return NULL;
}

/* Return the active view carrying one protocol identifier. */
static KswHvmEptViewSlot*
kswordArkHvmEptViewFindById(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG viewId
    )
{
    ULONG index = 0UL;

    /* Search the bounded view table without allocation. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Match only installed views with the exact identifier. */
        if (runtime->eptViews[index].active &&
            runtime->eptViews[index].viewId == viewId) {
            /* Return the exact installed view. */
            return &runtime->eptViews[index];
        }
    }
    /* Report that no view carries the identifier. */
    return NULL;
}

/* Return whether any active EPT rule covers one page. */
static BOOLEAN
kswordArkHvmEptViewPageHasRule(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalPage
    )
{
    ULONG index = 0UL;

    /* Rules and views both own the leaf value; they cannot share a page. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        const KswHvmEptRuleSlot* rule = &runtime->eptRules[index];
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->physicalAddress +
            (rule->pageCount * KSW_HVM_PAGE_BYTES);
        /* Report the first rule that contains the page. */
        if (physicalPage >= rule->physicalAddress &&
            physicalPage < ruleEnd) {
            /* Report a leaf-ownership conflict. */
            return TRUE;
        }
    }
    /* Report that no rule owns the page. */
    return FALSE;
}

/*
 * Build the two leaf values one view alternates between.  Permissions come
 * from the kind; the memory type and every other attribute are inherited from
 * the identity leaf so a view never changes how the page is cached.
 */
static NTSTATUS
kswordArkHvmEptViewBuildEntries(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG kind,
    _In_ ULONGLONG originalEntry,
    _In_ ULONGLONG shadowPhysical,
    _Out_ ULONGLONG* primaryEntry,
    _Out_ ULONGLONG* secondaryEntry
    )
{
    /* Preserve the memory type and non-permission attributes of the leaf. */
    const ULONGLONG kAttributes =
        originalEntry &
        ~(KSW_EPT_READ | KSW_EPT_WRITE | KSW_EPT_EXECUTE |
          KSW_EPT_PHYSICAL_MASK);
    /* Preserve the real frame the identity leaf already encodes. */
    const ULONGLONG kRealFrame = originalEntry & KSW_EPT_PHYSICAL_MASK;
    /* Encode the shadow frame that backs the redirected access. */
    const ULONGLONG kShadowFrame = shadowPhysical & KSW_EPT_PHYSICAL_MASK;
    /* Record whether the processor can encode execute-only leaves. */
    const BOOLEAN kExecuteOnly =
        (runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL;

    if (kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
        /*
         * Execution must reach the real page while reads are redirected, which
         * requires an execute-only leaf.  Without that encoding the primary
         * value would have to grant read as well, and nothing would be hidden.
         */
        if (!kExecuteOnly) {
            /* Report the missing architectural encoding. */
            return STATUS_NOT_SUPPORTED;
        }
        /* Primary: execute the real page, deny every read and write. */
        *primaryEntry = kAttributes | kRealFrame | KSW_EPT_EXECUTE;
        /* Secondary: read and write the shadow for one instruction. */
        *secondaryEntry =
            kAttributes | kShadowFrame | KSW_EPT_READ | KSW_EPT_WRITE;
        /* Report a complete pair. */
        return STATUS_SUCCESS;
    }
    if (kind == KSWORD_ARK_HVM_VIEW_KIND_HOOK) {
        /* Primary: read and write the real page, deny execution. */
        *primaryEntry =
            kAttributes | kRealFrame | KSW_EPT_READ | KSW_EPT_WRITE;
        /*
         * Secondary: execute the shadow.  Read is added when execute-only is
         * unavailable, because EPT cannot encode X without R on those parts.
         * The window is one instruction, so a reader would have to land inside
         * it to observe the shadow at all.
         */
        *secondaryEntry = kAttributes | kShadowFrame | KSW_EPT_EXECUTE;
        if (!kExecuteOnly) {
            /* Keep the secondary value architecturally legal. */
            *secondaryEntry |= KSW_EPT_READ;
        }
        /* Report a complete pair. */
        return STATUS_SUCCESS;
    }
    /* Report an unknown view kind. */
    return STATUS_INVALID_PARAMETER;
}

/* Release one view's shadow page and restore the leaf it owned. */
static VOID
kswordArkHvmEptViewReleaseLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptViewSlot* view
    )
{
    /* Restore the leaf before the shadow frame becomes reusable. */
    if (view->entry != NULL) {
        /* Publish the exact value captured before installation. */
        *view->entry = view->originalEntry;
        /* Order the restoration before the context is invalidated. */
        KeMemoryBarrier();
        /*
         * Drop cached translations that still point at the shadow, on every
         * processor and only while some processor is actually in VMX
         * operation.  A bare INVEPT here would be #UD on exactly the path this
         * runs on most - releasing a view after residency has stopped.
         */
        (void)kswordArkHvmResidentInvalidateEpt(runtime->eptPointer);
    }
    /*
     * Release this view's hierarchy before the record is cleared, while the
     * index is still readable.  Harmless when the view was served by the
     * default backend: the index is then 0, which names the base, and
     * releasing the base is defined as doing nothing.
     */
    kswordArkHvmEptSwitchReleaseLeaf(runtime, view->eptSwitchIndex);
    /* Release the shadow page after no leaf can reach it. */
    if (view->shadowVirtual != NULL) {
        /* Free the shadow allocation. */
        MmFreeContiguousMemory(view->shadowVirtual);
    }
    /* Clear the reusable slot completely. */
    RtlZeroMemory(view, sizeof(*view));
    /* Account the released view. */
    if (runtime->eptViewCount != 0UL) {
        /* Keep the published count consistent with the table. */
        runtime->eptViewCount -= 1UL;
    }
}

/* Publish one view row into a protocol response. */
static VOID
kswordArkHvmEptViewFillRow(
    _In_ const KswHvmEptViewSlot* view,
    _Out_ KSWORD_ARK_HVM_VIEW_ROW* row
    )
{
    /* Publish the stable protocol identifier. */
    row->viewId = view->viewId;
    /* Publish the view kind. */
    row->kind = view->kind;
    /* Publish the behavior flags. */
    row->flags = view->flags;
    /* Keep the reserved field deterministic. */
    row->reserved = 0UL;
    /* Publish the covered guest physical page. */
    row->physicalAddress = view->physicalAddress;
    /* Publish the shadow frame backing the redirected access. */
    row->shadowPhysicalAddress =
        (ULONGLONG)view->shadowPhysical.QuadPart;
    /* Publish how often the leaf flipped since installation. */
    row->flipCount = (ULONGLONG)view->flipCount;
}

/* Install one new view over a page that no rule or view already owns. */
static NTSTATUS
kswordArkHvmEptViewAddLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* response
    )
{
    const ULONGLONG kPhysicalPage =
        request->physicalAddress & ~(KSW_HVM_PAGE_BYTES - 1ULL);
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    KswHvmEptViewSlot* view = NULL;
    KswHvmEptSplit* split = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG primaryEntry = 0ULL;
    ULONGLONG secondaryEntry = 0ULL;
    ULONG index = 0UL;
    ULONG switchIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an unaligned or out-of-window target before allocating. */
    if (request->physicalAddress != kPhysicalPage ||
        kPhysicalPage >= KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A view the private hierarchies could not mirror must be refused here,
     * not at start.  Refusing at start would mean the caller learns a view
     * set is inadmissible only after every add already succeeded.
     */
    status = kswordArkHvmEptLocalCheckAdmission(
        runtime,
        kPhysicalPage,
        KSW_HVM_PAGE_BYTES);
    if (!NT_SUCCESS(status)) {
        /* Publish the stable table-full protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL;
        response->lastStatus = status;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse to share one leaf between a view and a rule or another view. */
    if (kswordArkHvmEptViewFind(runtime, kPhysicalPage) != NULL ||
        kswordArkHvmEptViewPageHasRule(runtime, kPhysicalPage)) {
        /* Publish the stable leaf-conflict protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT;
        /* Return the exact ownership conflict. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Reserve one bounded table slot before allocating a shadow. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Select the first inactive record. */
        if (!runtime->eptViews[index].active) {
            /* Bind the reusable zeroed record. */
            view = &runtime->eptViews[index];
            /* Stop after the first free slot. */
            break;
        }
    }
    /* Report bounded view capacity exhaustion. */
    if (view == NULL) {
        /* Publish the stable table-full protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL;
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Split the covering two-MiB leaf so the view owns four-KiB granularity. */
    status = kswordArkHvmEptEnsureSplitLocked(
        runtime,
        kPhysicalPage,
        &split);
    /* Stop when the baseline identity leaf cannot be split. */
    if (!NT_SUCCESS(status)) {
        /* Publish the stable split-failure protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED;
        /* Return the exact split failure. */
        return status;
    }
    /* Resolve the writable four-KiB leaf the view will flip. */
    entry = kswordArkHvmEptFindLeafEntry(runtime, kPhysicalPage);
    /* Fail closed when split metadata is unexpectedly unavailable. */
    if (entry == NULL) {
        /* Publish the stable split-failure protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED;
        /* Return the exact lookup failure. */
        return STATUS_NOT_FOUND;
    }
    /* Preserve the exact value that existed before installation. */
    originalEntry = *entry;
    /* Allocate the shadow frame that backs the redirected access. */
    highest.QuadPart = MAXLONGLONG;
    view->shadowVirtual = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    /* Report allocation failure without publishing a partial view. */
    if (view->shadowVirtual == NULL) {
        /* Clear the reusable record. */
        RtlZeroMemory(view, sizeof(*view));
        /* Publish the stable resource-failure protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
        /* Return the exact resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve the shadow frame encoded into the secondary leaf value. */
    view->shadowPhysical = MmGetPhysicalAddress(view->shadowVirtual);
    /* Seed the shadow before any leaf can reach it. */
    if ((request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO) != 0UL) {
        /* Present an empty page to whatever the view redirects. */
        RtlZeroMemory(
            view->shadowVirtual,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    } else if ((request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET) != 0UL) {
        MM_COPY_ADDRESS copyAddress;
        SIZE_T copied = 0U;

        /* Freeze the page's current contents into the shadow. */
        RtlZeroMemory(&copyAddress, sizeof(copyAddress));
        copyAddress.PhysicalAddress.QuadPart = (LONGLONG)kPhysicalPage;
        status = MmCopyMemory(
            view->shadowVirtual,
            copyAddress,
            (SIZE_T)KSW_HVM_PAGE_BYTES,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
        /* Refuse to install a view over a page that cannot be captured. */
        if (!NT_SUCCESS(status) ||
            copied != (SIZE_T)KSW_HVM_PAGE_BYTES) {
            /* Release the shadow that will never be installed. */
            MmFreeContiguousMemory(view->shadowVirtual);
            /* Clear the reusable record. */
            RtlZeroMemory(view, sizeof(*view));
            /* Publish the stable resource-failure protocol status. */
            response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
            /* Return the exact capture failure. */
            return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        }
    } else {
        /* Publish the caller-supplied shadow contents. */
        RtlCopyMemory(
            view->shadowVirtual,
            request->shadow,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    }
    /* Build the two values the view alternates between. */
    status = kswordArkHvmEptViewBuildEntries(
        runtime,
        request->kind,
        originalEntry,
        (ULONGLONG)view->shadowPhysical.QuadPart,
        &primaryEntry,
        &secondaryEntry);
    /* Stop when the requested kind cannot be encoded on this processor. */
    if (!NT_SUCCESS(status)) {
        /* Release the shadow that will never be installed. */
        MmFreeContiguousMemory(view->shadowVirtual);
        /* Clear the reusable record. */
        RtlZeroMemory(view, sizeof(*view));
        /* Distinguish the missing encoding from a malformed request. */
        response->status = status == STATUS_NOT_SUPPORTED
            ? KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED
            : KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        /* Return the exact encoding failure. */
        return status;
    }
    /*
     * Build this view's own hierarchy before anything is published.
     *
     * Done here rather than at start for the same reason the private-EPT
     * admission check is: refusing at start would mean the caller learns a
     * view set is inadmissible only after every add already reported success.
     *
     * Verified immediately, and the verification walks the built tables the
     * way the processor would rather than re-reading what was just written.
     * Every error this can catch - an index off by one level, a parent
     * repointed to the wrong page - produces a hierarchy that is still
     * structurally valid, so there is no later symptom to catch it by.
     */
    if (runtime->eptpSwitchArmed) {
        status = kswordArkHvmEptSwitchBuildLeaf(
            runtime,
            kPhysicalPage,
            primaryEntry,
            secondaryEntry,
            (const volatile ULONGLONG*)split->pageTable,
            &switchIndex);
        if (NT_SUCCESS(status)) {
            status = kswordArkHvmEptSwitchVerifyLeaf(
                runtime,
                switchIndex);
            /* A hierarchy that does not verify must not stay in the ledger. */
            if (!NT_SUCCESS(status)) {
                kswordArkHvmEptSwitchReleaseLeaf(runtime, switchIndex);
                switchIndex = 0UL;
            }
        }
        if (!NT_SUCCESS(status)) {
            /* Release the shadow that will never be installed. */
            MmFreeContiguousMemory(view->shadowVirtual);
            /* Clear the reusable record. */
            RtlZeroMemory(view, sizeof(*view));
            /* Publish the stable resource-failure protocol status. */
            response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
            response->lastStatus = status;
            /* Return the exact hierarchy failure. */
            return status;
        }
    }
    /* Preserve every recovery field before the leaf changes. */
    view->physicalAddress = kPhysicalPage;
    /* Preserve which hierarchy serves this view; 0 means the base. */
    view->eptSwitchIndex = switchIndex;
    /* Preserve the kind that selects the redirected access. */
    view->kind = request->kind;
    /* Preserve only defined behavior flags. */
    view->flags = request->flags &
        (KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET |
         KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO |
         KSWORD_ARK_HVM_VIEW_FLAG_LOG);
    /* Preserve the writable leaf for flips and restoration. */
    view->entry = entry;
    /* Preserve the exact pre-installation value. */
    view->originalEntry = originalEntry;
    /* Preserve the steady-state value. */
    view->primaryEntry = primaryEntry;
    /* Preserve the one-instruction redirection value. */
    view->secondaryEntry = secondaryEntry;
    /* Assign the next stable protocol identifier. */
    runtime->eptViewNextId += 1UL;
    /* Publish the assigned identifier. */
    view->viewId = runtime->eptViewNextId;
    /* Order every field before the record becomes reachable. */
    KeMemoryBarrier();
    /* Publish the installed view record. */
    view->active = TRUE;
    /* Account the installed view. */
    runtime->eptViewCount += 1UL;
    /* Install the steady-state value the view keeps. */
    *entry = primaryEntry;
    /* Order the leaf change before the context is invalidated. */
    KeMemoryBarrier();
    /*
     * Same reasoning as the release path, with a sharper edge: this runs after
     * Active, EptViewCount and the leaf value are already committed, so a #UD
     * here is not "installation failed" - it is "installation succeeded, then
     * the machine bugchecked".  That is why this call has to be the guarded,
     * all-processor one even though the leaf write above is local.
     */
    (void)kswordArkHvmResidentInvalidateEpt(runtime->eptPointer);
    /* Publish the assigned identifier to the caller. */
    response->viewId = view->viewId;
    /* Publish the successful installation. */
    response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
    /* Complete the installation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptViewControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* response
    )
{
    ULONG index = 0UL;
    ULONG rows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before touching any state. */
    if (runtime == NULL || request == NULL || response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->generation = runtime->generation;
    /* Validate the complete versioned request. */
    if (request->version != KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION ||
        request->size != sizeof(*request)) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Answer read-only queries before any confirmation requirement. */
    if (request->operation == KSWORD_ARK_HVM_VIEW_OP_QUERY) {
        /* Publish every installed view row. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_VIEWS &&
                rows < KSWORD_ARK_HVM_MAX_VIEWS;
             ++index) {
            /* Skip inactive records. */
            if (!runtime->eptViews[index].active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Publish one complete row. */
            kswordArkHvmEptViewFillRow(
                &runtime->eptViews[index],
                &response->rows[rows]);
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        response->returnedRows = rows;
        /* Publish the installed view count. */
        response->viewCount = runtime->eptViewCount;
        /* Publish the successful query. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete query answer. */
        return STATUS_SUCCESS;
    }
    /*
     * Every mutating operation redirects real memory accesses, so all of them
     * require the explicit confirmation token.
     */
    if (request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED) == 0UL) {
        /* Publish the stable confirmation-required protocol status. */
        response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Honor a generation-bound request exactly as the control path does. */
    if (request->expectedGeneration != 0UL &&
        request->expectedGeneration != runtime->generation) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Views need the split EPT hierarchy that preparation builds. */
    if ((runtime->stateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        /* Publish the stable not-prepared protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Release every installed view. */
    if (request->operation == KSWORD_ARK_HVM_VIEW_OP_CLEAR) {
        /* Restore and release each record in turn. */
        for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
            /* Skip inactive records. */
            if (!runtime->eptViews[index].active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Restore the leaf and free the shadow. */
            kswordArkHvmEptViewReleaseLocked(
                runtime,
                &runtime->eptViews[index]);
        }
        /* Publish the resulting count. */
        response->viewCount = runtime->eptViewCount;
        /* Publish the successful clear. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete clear result. */
        return STATUS_SUCCESS;
    }
    /* Release exactly one installed view. */
    if (request->operation == KSWORD_ARK_HVM_VIEW_OP_REMOVE) {
        KswHvmEptViewSlot* view =
            kswordArkHvmEptViewFindById(runtime, request->viewId);

        /* Report an unknown identifier without changing any leaf. */
        if (view == NULL) {
            /* Publish the stable not-found protocol status. */
            response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND;
            response->lastStatus = STATUS_NOT_FOUND;
            /* Return the complete protocol-level rejection. */
            return STATUS_SUCCESS;
        }
        /* Restore the leaf and free the shadow. */
        kswordArkHvmEptViewReleaseLocked(runtime, view);
        /* Publish the resulting count. */
        response->viewCount = runtime->eptViewCount;
        /* Publish the successful removal. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete removal result. */
        return STATUS_SUCCESS;
    }
    /* Reject every operation outside the defined vocabulary. */
    if (request->operation != KSWORD_ARK_HVM_VIEW_OP_ADD) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /*
     * A flip edits an EPT leaf for one instruction.  On a SHARED hierarchy
     * that window is visible to every other processor, so a view is only
     * safe on a single-processor topology - the same limit allow-once rules
     * already carry.
     *
     * hvm_ept_local.c lifts it by giving each processor its own copy of the
     * tables on the path to a flippable leaf, so the flip reaches only the
     * processor that took the exit.  The latch below is set at PREPARE time
     * from the capabilities that mechanism needs; residency additionally has
     * to be started with ENABLE_LOCAL_EPT, and a start that omits it is
     * refused while any view is installed on a multicore box.
     */
    /*
     * The EPTP-switching backend is the third way out, and it was being
     * refused here by a rule written for the other two.
     *
     * That backend never flips a leaf at run time: a violation on one of its
     * views returns from the handler having written nothing but this
     * processor's own EPT_POINTER, and the hierarchy index it selects is per
     * VCPU. There is no machine-wide window to protect against, which is why
     * the comment further down the resident start path already says a view
     * backed by it "needs no extra refusal here" - that comment described a
     * refusal that was removed, while this one stayed and kept refusing.
     *
     * The consequence was worse than a missing feature: the only backend that
     * works on a nested target was unreachable on any multicore box, and the
     * status it returned - MULTIPROCESSOR_UNSAFE - named a hazard that does
     * not apply to it. Measured 2026-09-07 on a 2 vCPU target: view-effect
     * reported "installed: false" while the backend was armed and capable.
     *
     * The predicate is the arm latch here, not the installed records, because
     * at this point the record for this view does not exist yet - the check
     * below is what decides whether it will be built with a hierarchy. The
     * resident start gate asks the records instead; see its own comment.
     */
    if (runtime->processorCount != 1UL &&
        !runtime->localEptArmed &&
        !runtime->eptpSwitchArmed) {
        /* Publish the stable multiprocessor-unsafe protocol status. */
        response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /*
     * Capability gate, one branch per backend.  The two do not need the same
     * controls, and conflating them is what made this look like "views need
     * the Monitor Trap Flag" - a statement that is only true of the default
     * backend.
     *
     *   write leaf + monitor-trap : INVEPT_SINGLE and MONITOR_TRAP_FLAG.
     *       The flip is bounded to one instruction by single-stepping, so the
     *       trap flag is not an optimisation - without it the leaf stays
     *       flipped forever and the shadow becomes permanent.
     *
     *   switch EPTP               : INVEPT_SINGLE only, plus the arm latch,
     *       which already proved execute-only leaves are encodable.  This
     *       backend never single-steps: it leaves the guest on a second
     *       hierarchy until an access of the opposite kind faults it back.
     *
     * INVEPT_SINGLE is common to both because either way the translations
     * built from the value being left have to be dropped.
     */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) == 0ULL ||
        (!runtime->eptpSwitchArmed &&
         (runtime->featureFlags &
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) == 0ULL)) {
        /* Publish the stable multiprocessor-unsafe protocol status. */
        response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Install the requested view. */
    status = kswordArkHvmEptViewAddLocked(
        runtime,
        request,
        response);
    /* Publish the resulting count on every path. */
    response->viewCount = runtime->eptViewCount;
    /* Preserve the authoritative installation status. */
    response->lastStatus = status;
    /* Return a protocol-level result successfully. */
    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkHvmEptViewAllSwitchBackedLocked(
    _In_ const KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Treat a missing runtime as "cannot prove it", never as safe. */
    if (runtime == NULL) {
        /* Report the conservative answer. */
        return FALSE;
    }
    /* Inspect every bounded record, not just the first EptViewCount of them. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Skip records that hold no installed view. */
        if (!runtime->eptViews[index].active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /*
         * Index zero means this view is served from the base hierarchy, and
         * that service is a leaf flip - the one thing the multicore gates
         * exist to refuse.
         */
        if (runtime->eptViews[index].eptSwitchIndex == 0UL) {
            /* Report that at least one view would flip a shared leaf. */
            return FALSE;
        }
    }
    /* Report that no installed view flips a leaf; an empty table qualifies. */
    return TRUE;
}

VOID
kswordArkHvmEptViewResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Restore and release every installed view before EPT pages are freed. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Skip inactive records. */
        if (!runtime->eptViews[index].active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Restore the leaf and free the shadow. */
        kswordArkHvmEptViewReleaseLocked(
            runtime,
            &runtime->eptViews[index]);
    }
    /* Leave the table and its counters deterministic. */
    RtlZeroMemory(runtime->eptViews, sizeof(runtime->eptViews));
    runtime->eptViewCount = 0UL;
}

BOOLEAN
kswordArkHvmEptViewHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access,
    _In_opt_ const KswHvmEptLocal* local,
    _Out_ KswHvmEptTransient* transient,
    _Out_ ULONG* viewId,
    _Out_ KswHvmEptViewSwitch* Switch
    )
{
    const ULONGLONG kPhysicalPage =
        guestPhysicalAddress & ~(KSW_HVM_PAGE_BYTES - 1ULL);
    KswHvmEptViewSlot* view = NULL;
    /*
     * Declared here but assigned only after the view is known to exist.
     * Initializing it from view->Entry at the block top would dereference
     * NULL on every violation that no view covers, which is most of them.
     */
    volatile ULONGLONG* entry = NULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (runtime == NULL ||
        transient == NULL ||
        viewId == NULL ||
        Switch == NULL) {
        /* Report an unhandled violation. */
        return FALSE;
    }
    /* Publish no view match before the bounded table scan. */
    *viewId = 0UL;
    RtlZeroMemory(Switch, sizeof(*Switch));
    /* Locate the view that owns the faulting page. */
    view = kswordArkHvmEptViewFind(runtime, kPhysicalPage);
    /* Report that no view covers the page. */
    if (view == NULL) {
        /* Leave the violation to the rule backend. */
        return FALSE;
    }
    /* Publish the matched view identity. */
    *viewId = view->viewId;
    /*
     * Served by its own hierarchy: report and return without touching a leaf.
     *
     * Everything below this point - the armed-transient check, the access
     * direction check, the flip and its invalidation - exists to bound a leaf
     * write to one instruction.  This backend performs no leaf write at run
     * time, so none of it applies; the secondary value is already sitting in
     * that leaf's hierarchy and the caller only has to point the processor at
     * it.  Falling through would flip the shared leaf as well, which is both
     * unnecessary and visible to every other processor.
     *
     * The access direction is deliberately **not** checked here.  The switch
     * planner decides it from the permissions of both values, and it is the
     * one place that knows which hierarchy is currently loaded - a fact this
     * function cannot see.
     */
    if (view->eptSwitchIndex != 0UL) {
        Switch->requested = TRUE;
        Switch->leafSlot = view->eptSwitchIndex - 1UL;
        Switch->kind = view->kind;
        /* Report a handled violation with no transient armed. */
        return TRUE;
    }
    /*
     * An armed transient means a previous flip has not been restored yet.
     * Restoring and failing closed is the only safe outcome; overwriting the
     * record would lose the only way back to the primary value.
     */
    if (transient->armed) {
        /* Attempt restoration; failure intentionally leaves it armed. */
        (void)kswordArkHvmEptRestoreTransient(runtime, transient);
        /* Force fail-closed devirtualization after an overlapping flip. */
        return FALSE;
    }
    /*
     * Only the access the primary value denies belongs to the secondary one.
     * Anything else reaching here means the leaf does not match the view, so
     * failing closed is safer than flipping on an unexpected access.
     */
    if (view->kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
        /* CLOAK denies read and write; execution must never fault. */
        if ((access &
                (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                 KSWORD_ARK_HVM_EPT_ACCESS_WRITE)) == 0UL) {
            /* Report an unexpected access for this view. */
            return FALSE;
        }
    } else {
        /* HOOK denies execution; reads and writes must never fault. */
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
            /* Report an unexpected access for this view. */
            return FALSE;
        }
    }
    /* Clear stale unarmed fields without calling vectorized helpers. */
    transient->reserved0[0] = 0U;
    transient->reserved0[1] = 0U;
    transient->reserved0[2] = 0U;
    /* Preserve the view identity for restoration telemetry. */
    transient->ruleId = view->viewId;
    /*
     * Redirect the flip to this processor's own copy of the leaf.  A view
     * whose leaf has no mirror is a build error, and flipping the shared
     * table instead would make the flip visible to every other processor -
     * the exact hazard the private hierarchy removes.
     */
    entry = view->entry;
    if (local != NULL) {
        entry = kswordArkHvmEptLocalTranslate(local, entry);
        if (entry == NULL) {
            /* Require immediate fail-closed devirtualization. */
            return FALSE;
        }
    }
    /* Preserve the writable leaf. */
    transient->entry = entry;
    /* Restore to the steady-state value, not to the pre-install one. */
    transient->restrictedValue = view->primaryEntry;
    /* Record which hierarchy must be invalidated when this flip ends. */
    transient->eptPointer = local != NULL ? local->eptPointer : 0ULL;
    /* Publish the armed recovery record before the leaf changes. */
    KeMemoryBarrier();
    transient->armed = TRUE;
    /* Redirect the access to the shadow for exactly one instruction. */
    *entry = view->secondaryEntry;
    /* Order the flip before the context is invalidated. */
    KeMemoryBarrier();
    /* Drop cached translations built from the primary value. */
    if (kswordArkHvmAsmInveptSingle(
            transient->eptPointer != 0ULL
                ? transient->eptPointer
                : runtime->eptPointer) != 0U) {
        /* Restore and invalidate; retain Armed if restoration also fails. */
        (void)kswordArkHvmEptRestoreTransient(runtime, transient);
        /* Require immediate fail-closed devirtualization. */
        return FALSE;
    }
    /* Account the completed flip. */
    InterlockedIncrement64(&view->flipCount);
    /* Report a handled violation whose restoration monitor-trap will finish. */
    return TRUE;
}

NTSTATUS
kswordArkHvmEptViewControl(
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* response
    )
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (request == NULL || response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = request->operation != KSWORD_ARK_HVM_VIEW_OP_QUERY;
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->lock);
    if (!runtime->initialized) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Publish the stable not-prepared protocol status. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating && runtime->busy) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Reuse the resource status for a transient lifecycle conflict. */
        response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No view, leaf or shadow was changed. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * Resident VM exits read the view table without taking this
         * PASSIVE_LEVEL lock.  Keep the table, every leaf and every shadow
         * immutable until all VCPUs have committed their guest-stack return.
         */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Publish the stable multiprocessor-unsafe protocol status. */
        response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No view, leaf or shadow was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded view operation under lifecycle ownership. */
        status = kswordArkHvmEptViewControlLocked(
            runtime,
            request,
            response);
    }
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&runtime->lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

volatile UCHAR*
kswordArkHvmEptViewShadowForViewId(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONG viewId
    )
{
    ULONG index = 0UL;

    /* Reject incomplete call contracts and impossible-to-hit identifiers. */
    if (runtime == NULL || viewId == 0UL) {
        /* Return miss. */
        return NULL;
    }
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        const KswHvmEptViewSlot* slot = &runtime->eptViews[index];

        if (slot->active &&
            slot->viewId == viewId &&
            slot->shadowVirtual != NULL) {
            /* Return the shadow page of this view. */
            return (volatile UCHAR*)slot->shadowVirtual;
        }
    }
    /* Return miss. */
    return NULL;
}
