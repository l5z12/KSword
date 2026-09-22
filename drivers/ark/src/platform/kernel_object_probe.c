/*++

Module Name:

    kernel_object_probe.c

Abstract:

    Identity probes for kernel objects recovered by heuristic scanning.  Shape
    checks over a candidate's fields can never prove what the candidate is:
    every self-consistent LIST_ENTRY inside a writable image section looks like
    an ERESOURCE, and passing a non-resource to the Ex resource API bugchecks
    immediately.  The probes here establish identity from properties the object
    cannot fake, using bounded fault-tolerant reads only.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "kernel_object_probe.h"
#include "runtime_signature_scan.h"

#define KSW_KERNEL_PROBE_MAX_RESOURCE_LIST_STEPS 0x40000UL

static BOOLEAN
kswordArkKernelProbeIsKernelPointer(
    _In_ ULONG_PTR address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

BOOLEAN
kswordArkKernelProbeResourceIsSystemResource(
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Prove that a candidate address really is a live ERESOURCE before any Ex
    resource API touches it.  ExInitializeResourceLite links every resource
    onto one global list, so a driver-owned resource supplies an anchor and no
    ntoskrnl global has to be guessed.  The walk uses bounded fault-tolerant
    reads and gives up rather than trusting a torn or hostile link.

Arguments:

    Address - Candidate ERESOURCE address; SystemResourcesList sits at zero
        offset, so the list node and the resource share this address.

Return Value:

    TRUE only when the candidate is present on the global resource list.

--*/
{
    ERESOURCE anchor;
    LIST_ENTRY node;
    ULONG_PTR anchorHead = 0U;
    ULONG_PTR current = 0U;
    ULONG steps = 0UL;
    BOOLEAN found = FALSE;

    if (address == 0U || (address & (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkKernelProbeIsKernelPointer(address) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    RtlZeroMemory(&anchor, sizeof(anchor));
    if (!NT_SUCCESS(ExInitializeResourceLite(&anchor))) {
        return FALSE;
    }
    anchorHead = (ULONG_PTR)&anchor.SystemResourcesList;
    current = (ULONG_PTR)anchor.SystemResourcesList.Flink;
    for (steps = 0UL;
         steps < KSW_KERNEL_PROBE_MAX_RESOURCE_LIST_STEPS;
         ++steps) {
        if (current == anchorHead) {
            break;
        }
        if (current == address) {
            found = TRUE;
            break;
        }
        if ((current & (sizeof(PVOID) - 1U)) != 0U ||
            !kswordArkKernelProbeIsKernelPointer(current)) {
            break;
        }
        RtlZeroMemory(&node, sizeof(node));
        if (!kswordArkRuntimeReadMemory((const VOID*)current, &node, sizeof(node))) {
            break;
        }
        current = (ULONG_PTR)node.Flink;
    }
    ExDeleteResourceLite(&anchor);
    return found;
}

BOOLEAN
kswordArkKernelProbeRangeIsResident(
    _In_opt_ const volatile VOID* address,
    _In_ SIZE_T size
    )
/*++

Routine Description:

    Confirm that every page of a kernel range is resident.  Callers use this
    when IRQL is already at DISPATCH_LEVEL, where MmCopyMemory is unavailable
    and a fault would bugcheck rather than raise.  Probing only the first and
    last byte is not equivalent: a range spanning three or more pages can have
    a non-resident page in the middle, and an unaligned range shorter than a
    pointer can still straddle a page boundary.

Arguments:

    Address - Range start.
    Size - Range length in bytes.

Return Value:

    TRUE when the whole range is resident and safe to dereference.

--*/
{
    ULONG_PTR current = (ULONG_PTR)address;
    ULONG_PTR end = 0U;

    if (address == NULL || size == 0U ||
        !kswordArkKernelProbeIsKernelPointer(current) ||
        current > MAXULONG_PTR - size) {
        return FALSE;
    }
    end = current + size - 1U;
    for (;;) {
        if (!MmIsAddressValid((PVOID)current)) {
            return FALSE;
        }
        if ((current & ~(ULONG_PTR)(PAGE_SIZE - 1U)) ==
            (end & ~(ULONG_PTR)(PAGE_SIZE - 1U))) {
            break;
        }
        current = (current & ~(ULONG_PTR)(PAGE_SIZE - 1U)) + PAGE_SIZE;
    }
    return TRUE;
}

BOOLEAN
kswordArkKernelProbeListHeadIsSane(
    _In_ ULONG_PTR listHeadAddress
    )
/*++

Routine Description:

    Validate a list head and its immediate neighbours through fault-tolerant
    reads.  Callers use this before raising IRQL, because once a spin lock is
    held neither MmCopyMemory nor structured exception handling can contain an
    invalid kernel dereference.

Return Value:

    TRUE when the head and both neighbours link back consistently.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY forward;
    LIST_ENTRY backward;

    if (listHeadAddress == 0U ||
        (listHeadAddress & (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkKernelProbeIsKernelPointer(listHeadAddress)) {
        return FALSE;
    }
    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&forward, sizeof(forward));
    RtlZeroMemory(&backward, sizeof(backward));
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)listHeadAddress,
            &head,
            sizeof(head)) ||
        !kswordArkKernelProbeIsKernelPointer((ULONG_PTR)head.Flink) ||
        !kswordArkKernelProbeIsKernelPointer((ULONG_PTR)head.Blink) ||
        (((ULONG_PTR)head.Flink | (ULONG_PTR)head.Blink) &
         (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkRuntimeReadMemory(head.Flink, &forward, sizeof(forward)) ||
        !kswordArkRuntimeReadMemory(head.Blink, &backward, sizeof(backward)) ||
        forward.Blink != (PLIST_ENTRY)listHeadAddress ||
        backward.Flink != (PLIST_ENTRY)listHeadAddress) {
        return FALSE;
    }
    return TRUE;
}
