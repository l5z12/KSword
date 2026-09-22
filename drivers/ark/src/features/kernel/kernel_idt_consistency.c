/*++

Module Name:

    kernel_idt_consistency.c

Abstract:

    Read-only collect the IDTR of each active logical processor, compute the 'majority' IDT table, and compare it against the IDT baseline
    captured at driver startup. It answers two questions: whether a specific core had its IDT replaced in isolation (a typical lidt
    takeover modifies only the current core), and whether the entire system's IDT table was moved to an address outside the startup period.

    This file only executes SIDT and structure comparisons; it does not write to IDTR or modify any descriptors.

Environment:

    Kernel mode, PASSIVE_LEVEL (thread group affinity switching is required during the collection process).

--*/

#include "kernel_idt_consistency.h"

#include "kernel_idt_baseline.h"
#include "src/platform/pool_compat.h"

#include <intrin.h>

// Private pool tag for this module.
#define KSW_IDT_CONSISTENCY_TAG 'cIsK'

#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__sidt)
#endif

#pragma pack(push, 1)
// Layout of the 10-byte SIDT write-back pseudo-descriptor.
typedef struct KswIdtConsistencyRegister
{
    USHORT limit;
    ULONG_PTR base;
} KswIdtConsistencyRegister, *PkswIdtConsistencyRegister;
#pragma pack(pop)

#if defined(_M_AMD64) || defined(_M_X64)

static VOID
kswordArkIdtConsistencyComputeMajority(
    _Inout_ KswIdtConsistencyView* view
    )
/*++

Routine Description:

    Find the most frequent (Base, Limit) combination among the collected samples to serve as the majority.

Arguments:

    View - Collection results with Cpus[] filled.

Return Value:

    None. Results are written to the View's Majority* fields.

--*/
{
    ULONG outerIndex = 0UL;

    /* Remains all zeros when no valid samples exist; callers use this to determine unusability. */
    if (view == NULL || view->capturedCount == 0UL) {
        return;
    }

    /* Note: With only a few hundred processors, an O(n^2) vote count is acceptable without additional allocation. */
    for (outerIndex = 0UL; outerIndex < view->cpuCount; ++outerIndex) {
        const KswIdtConsistencyCpu* candidate = &view->cpus[outerIndex];
        ULONG innerIndex = 0UL;
        ULONG votes = 0UL;

        /* Rows with failed capture do not participate in voting. */
        if (candidate->captured == 0UL) {
            continue;
        }

        /* Count the number of processors that match the candidate value exactly. */
        for (innerIndex = 0UL; innerIndex < view->cpuCount; ++innerIndex) {
            const KswIdtConsistencyCpu* other = &view->cpus[innerIndex];

            /* Similarly skip invalid samples to avoid counting zero values as a vote. */
            if (other->captured == 0UL) {
                continue;
            }

            /* Both Base and Limit must match to be considered the same table. */
            if (other->base == candidate->base && other->limit == candidate->limit) {
                votes += 1UL;
            }
        }

        /* Higher vote count wins; ties retain the earlier candidate to ensure stable results. */
        if (votes > view->majorityCount) {
            view->majorityCount = votes;
            view->majorityBase = candidate->base;
            view->majorityLimit = candidate->limit;
        }
    }
}

static VOID
kswordArkIdtConsistencyScoreRows(
    _Inout_ KswIdtConsistencyView* view
    )
/*++

Routine Description:

    Count processors deviating from the baseline based on majority and boot-time statistics.

Arguments:

    View - Collection results after majority calculation is complete.

Return Value:

    None. Results are written to View's DivergedCount / RelocatedCount.

--*/
{
    ULONG index = 0UL;

    /* When a majority is not established, perform no checks to avoid issuing unfounded alerts. */
    if (view == NULL || view->majorityCount == 0UL) {
        return;
    }

    /* Compare row by row, separately accumulating deviations from the majority and from the boot-time baseline. */
    for (index = 0UL; index < view->cpuCount; ++index) {
        const KswIdtConsistencyCpu* row = &view->cpus[index];

        /* Rows with failed collection produce no conclusions. */
        if (row->captured == 0UL) {
            continue;
        }

        /* Divergence is flagged if the address or length differs from the majority table. */
        if (row->base != view->majorityBase || row->limit != view->majorityLimit) {
            view->divergedCount += 1UL;
        }

        /* Only rows with a baseline are allowed to be marked as relocated. */
        if (row->baselineAvailable != 0UL &&
            (row->base != row->baselineBase || row->limit != row->baselineLimit)) {
            view->relocatedCount += 1UL;
        }
    }
}

#endif

NTSTATUS
kswordArkIdtConsistencyCollect(
    _Outptr_result_maybenull_ KswIdtConsistencyView** viewOut
    )
/*++

Routine Description:

    Iterate all active processors to execute SIDT and build a cross-CPU IDTR consistency view.

Arguments:

    ViewOut: Receives the view pointer that the caller must release on success.

Return Value:

    STATUS_SUCCESS or a failure status related to allocation/topology/architecture.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG activeCount = 0UL;
    ULONG globalIndex = 0UL;
    ULONG rowCount = 0UL;
    SIZE_T allocationBytes = 0U;
    KswIdtConsistencyView* view = NULL;

    /* Parameter validation: caller must provide an output slot. */
    if (viewOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the output first to ensure callers see NULL on failure paths. */
    *viewOut = NULL;

    /* Query the total count of active processors across all groups as the array upper bound. */
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Calculate the size of the variable-length structure and prevent multiplication overflow. */
    if (activeCount > (MAXULONG_PTR - sizeof(KswIdtConsistencyView)) / sizeof(KswIdtConsistencyCpu)) {
        return STATUS_NOT_SUPPORTED;
    }
    allocationBytes = sizeof(KswIdtConsistencyView) +
        ((SIZE_T)activeCount * sizeof(KswIdtConsistencyCpu));

    /* Collection occurs during affinity switching; results are stored in non-paged pool. */
    view = (KswIdtConsistencyView*)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_IDT_CONSISTENCY_TAG);
    if (view == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* After zeroing, all uncaptured rows have Captured naturally set to 0. */
    RtlZeroMemory(view, allocationBytes);

    /* Sample IDTR per processor and retrieve that processor's boot-time baseline. */
    for (globalIndex = 0UL; globalIndex < activeCount; ++globalIndex) {
        PROCESSOR_NUMBER processor;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        KswIdtConsistencyRegister idtr;
        KswIdtConsistencyCpu* row = &view->cpus[rowCount];
        ULONGLONG baselineBase = 0ULL;
        ULONG baselineLimit = 0UL;

        /* Resolve the stable global index into a Group:Core identifier. */
        RtlZeroMemory(&processor, sizeof(processor));
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(globalIndex, &processor))) {
            continue;
        }

        /* Note: Affinity masks are constructed bitwise; skip core numbers exceeding the bit width. */
        if (processor.Number >= sizeof(KAFFINITY) * 8UL) {
            continue;
        }

        /* Construct group affinity containing only the target processor. */
        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processor.Group;
        targetAffinity.Mask = ((KAFFINITY)1) << processor.Number;

        /* Switch to the target processor to execute SIDT, then restore the original affinity. */
        RtlZeroMemory(&idtr, sizeof(idtr));
        KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
        __sidt(&idtr);
        KeRevertToUserGroupAffinityThread(&previousAffinity);

        /* A base of zero indicates an invalid descriptor was retrieved; discard this sample. */
        if (idtr.base == 0U) {
            continue;
        }

        /* Record the identity and IDTR value of this sample. */
        row->group = processor.Group;
        row->number = processor.Number;
        row->base = (ULONGLONG)idtr.base;
        row->limit = (ULONG)idtr.limit;
        row->captured = 1UL;

        /* Baseline query for vector 0 is used solely to retrieve the startup table address and length for this CPU. */
        if (kswordArkIdtBaselineQuery(
                (USHORT)processor.Group,
                (UCHAR)processor.Number,
                0U,
                &baselineBase,
                &baselineLimit,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL)) {
            row->baselineBase = baselineBase;
            row->baselineLimit = baselineLimit;
            row->baselineAvailable = 1UL;
        }

        /* Only advance the index for rows successfully written. */
        rowCount += 1UL;
        view->capturedCount += 1UL;
    }

    /* Record the actual number of rows used; subsequent iterations use this as the boundary. */
    view->cpuCount = rowCount;

    /* If no valid samples exist, treat as unavailable, free the resource, and return an error. */
    if (view->capturedCount == 0UL) {
        ExFreePoolWithTag(view, KSW_IDT_CONSISTENCY_TAG);
        return STATUS_NOT_FOUND;
    }

    /* First compute the majority, then count deviations based on it. */
    kswordArkIdtConsistencyComputeMajority(view);
    kswordArkIdtConsistencyScoreRows(view);

    /* Ownership transferred to the caller. */
    *viewOut = view;
    return STATUS_SUCCESS;
#else
    /* Non-x64 platforms have no readable IDTR; report unsupported directly. */
    if (ViewOut != NULL) {
        *ViewOut = NULL;
    }
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
kswordArkIdtConsistencyRelease(
    _In_opt_ KswIdtConsistencyView* view
    )
/*++

Routine Description:

    Release the view returned by kswordArkIdtConsistencyCollect.

Arguments:

    View: Optional view pointer.

Return Value:

    None.

--*/
{
    /* Allowing NULL simplifies the caller's failure cleanup path. */
    if (view == NULL) {
        return;
    }

    /* Return memory using the same tag as during collection. */
    ExFreePoolWithTag(view, KSW_IDT_CONSISTENCY_TAG);
}

ULONG
kswordArkIdtConsistencyClassify(
    _In_opt_ const KswIdtConsistencyView* view,
    _In_ ULONG processorGroup,
    _In_ ULONG processorNumber
    )
/*++

Routine Description:

    Returns flags indicating deviation of the specified processor's relative majority from the boot-time baseline.

Arguments:

    View: Optional collection result.
    ProcessorGroup - Processor group number.
    ProcessorNumber - Processor number within the group.

Return Value:

    Bitwise combination of KSW_IDT_CONSISTENCY_RISK_*; returns 0 if there is no basis.

--*/
{
    ULONG index = 0UL;
    ULONG riskFlags = 0UL;

    /* No conclusion is generated when the view is missing or the majority is not established. */
    if (view == NULL || view->majorityCount == 0UL) {
        return 0UL;
    }

    /* Linearly search for the sampling row corresponding to the target processor. */
    for (index = 0UL; index < view->cpuCount; ++index) {
        const KswIdtConsistencyCpu* row = &view->cpus[index];

        /* Skip invalid rows and non-target processors. */
        if (row->captured == 0UL ||
            row->group != processorGroup ||
            row->number != processorNumber) {
            continue;
        }

        /* Differs from the majority table: only this core's IDT may have been replaced. */
        if (row->base != view->majorityBase || row->limit != view->majorityLimit) {
            riskFlags |= KSW_IDT_CONSISTENCY_RISK_DIVERGED;
        }

        /* Differs from the boot-time baseline: the entire table has been relocated to a new address. */
        if (row->baselineAvailable != 0UL &&
            (row->base != row->baselineBase || row->limit != row->baselineLimit)) {
            riskFlags |= KSW_IDT_CONSISTENCY_RISK_RELOCATED;
        }

        /* Each processor appears only once; stop searching after a match. */
        break;
    }

    return riskFlags;
}
