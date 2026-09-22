/*++

Module Name:

    kernel_idt_baseline.c

Abstract:

    Capture an immutable, per-CPU IDT baseline during driver initialization and
    provide compare-and-swap restoration for one verified descriptor.

Environment:

    Kernel mode, PASSIVE_LEVEL for initialize/restore callers.

--*/

#include "kernel_idt_baseline.h"
#include "src/platform/pool_compat.h"

#include <intrin.h>

#define KSW_IDT_BASELINE_TAG 'bIsK'
#define KSW_IDT_BASELINE_VECTOR_COUNT 256UL
#define KSW_IDT_BASELINE_ENTRY_BYTES 16UL

#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__sidt)
#pragma intrinsic(_InterlockedCompareExchange128)
#endif

#pragma pack(push, 1)
typedef struct KswIdtBaselineRegister
{
    USHORT limit;
    ULONG_PTR base;
} KswIdtBaselineRegister, *PkswIdtBaselineRegister;

typedef struct KswIdtBaselineEntry
{
    USHORT offsetLow;
    USHORT selector;
    USHORT istAndType;
    USHORT offsetMiddle;
    ULONG offsetHigh;
    ULONG reserved;
} KswIdtBaselineEntry, *PkswIdtBaselineEntry;
#pragma pack(pop)

typedef struct KswIdtBaselineCpu
{
    USHORT group;
    UCHAR number;
    UCHAR captured;
    ULONG vectorCount;
    KswIdtBaselineRegister idtr;
    KswIdtBaselineEntry entries[KSW_IDT_BASELINE_VECTOR_COUNT];
} KswIdtBaselineCpu, *PkswIdtBaselineCpu;

typedef struct KswIdtBaselineState
{
    PkswIdtBaselineCpu cpus;
    ULONG cpuCount;
    ULONG generation;
    BOOLEAN initialized;
} KswIdtBaselineState;

static KswIdtBaselineState gKswordArkIdtBaseline;

static ULONGLONG
kswordArkIdtBaselineHandler(
    _In_ const KswIdtBaselineEntry* entry
    )
/*++

Routine Description:

    Decode one x64 interrupt/trap gate handler address.

Arguments:

    Entry - Copied 16-byte IDT gate.

Return Value:

    Canonical handler value or zero for invalid input/architecture.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONGLONG handler = 0ULL;

    /* Validate the input pointer before decoding the fixed fields. */
    if (entry == NULL) {
        return 0ULL;
    }

    /* Combine the three offset fragments defined by an x64 gate. */
    handler = (ULONGLONG)entry->offsetLow;
    handler |= ((ULONGLONG)entry->offsetMiddle) << 16;
    handler |= ((ULONGLONG)entry->offsetHigh) << 32;
    return handler;
#else
    UNREFERENCED_PARAMETER(Entry);
    return 0ULL;
#endif
}

static PkswIdtBaselineCpu
kswordArkIdtBaselineFindCpu(
    _In_ USHORT processorGroup,
    _In_ UCHAR processorNumber
    )
/*++

Routine Description:

    Find one immutable baseline row by processor identity.

Arguments:

    ProcessorGroup - Windows processor group.
    ProcessorNumber - Processor number within the group.

Return Value:

    Baseline row or NULL.

--*/
{
    ULONG index = 0UL;

    /* Reject lookups until initialization has published the immutable array. */
    if (!gKswordArkIdtBaseline.initialized ||
        gKswordArkIdtBaseline.cpus == NULL) {
        return NULL;
    }

    /* Scan the bounded CPU array; the row count came from the kernel topology. */
    for (index = 0UL;
         index < gKswordArkIdtBaseline.cpuCount;
         ++index) {
        PkswIdtBaselineCpu row =
            &gKswordArkIdtBaseline.cpus[index];

        /* Return only a fully captured row with an exact group/number match. */
        if (row->captured != 0U &&
            row->group == processorGroup &&
            row->number == processorNumber) {
            return row;
        }
    }

    /* No captured row matched the requested processor. */
    return NULL;
}

NTSTATUS
kswordArkIdtBaselineInitialize(
    VOID
    )
/*++

Routine Description:

    Capture every active processor's IDTR and up to 256 gate descriptors before
    the control device begins accepting requests.

Arguments:

    None.

Return Value:

    STATUS_SUCCESS or a bounded allocation/topology/capture error.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG activeCount = 0UL;
    SIZE_T allocationBytes = 0U;
    PkswIdtBaselineCpu rows = NULL;
    ULONG globalIndex = 0UL;
    ULONG capturedCount = 0UL;

    /* Make repeated initialization idempotent. */
    if (gKswordArkIdtBaseline.initialized) {
        return STATUS_SUCCESS;
    }

    /* Query the exact active logical processor count across all groups. */
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL ||
        activeCount > MAXULONG_PTR / sizeof(KswIdtBaselineCpu)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate one fixed 4 KiB descriptor snapshot per active CPU. */
    allocationBytes =
        (SIZE_T)activeCount * sizeof(KswIdtBaselineCpu);
    rows = (PkswIdtBaselineCpu)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_IDT_BASELINE_TAG);
    if (rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Zero all rows before any processor-specific capture becomes visible. */
    RtlZeroMemory(rows, allocationBytes);

    /* Visit processors sequentially so the caller remains at PASSIVE_LEVEL. */
    for (globalIndex = 0UL;
         globalIndex < activeCount;
         ++globalIndex) {
        PROCESSOR_NUMBER processor;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        KswIdtBaselineRegister idtr;
        PkswIdtBaselineCpu row = &rows[capturedCount];
        ULONG vectorCount = 0UL;
        SIZE_T copyBytes = 0U;
        NTSTATUS processorStatus = STATUS_SUCCESS;

        /* Resolve the stable global topology index into group/number identity. */
        RtlZeroMemory(&processor, sizeof(processor));
        processorStatus =
            KeGetProcessorNumberFromIndex(globalIndex, &processor);
        if (!NT_SUCCESS(processorStatus) ||
            processor.Number >= sizeof(KAFFINITY) * 8UL) {
            continue;
        }

        /* Build a single-CPU group affinity for the read-only capture. */
        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processor.Group;
        targetAffinity.Mask =
            ((KAFFINITY)1) << processor.Number;

        /* Execute SIDT and descriptor copying on the selected processor. */
        KeSetSystemGroupAffinityThread(
            &targetAffinity,
            &previousAffinity);
        RtlZeroMemory(&idtr, sizeof(idtr));
        __sidt(&idtr);

        /* Bound the captured descriptor count to the architectural maximum. */
        vectorCount =
            ((ULONG)idtr.limit + 1UL) / KSW_IDT_BASELINE_ENTRY_BYTES;
        if (vectorCount > KSW_IDT_BASELINE_VECTOR_COUNT) {
            vectorCount = KSW_IDT_BASELINE_VECTOR_COUNT;
        }
        copyBytes =
            (SIZE_T)vectorCount * sizeof(KswIdtBaselineEntry);

        /* Copy the selected CPU's IDT under exception protection. */
        __try {
            if (idtr.base != 0U &&
                vectorCount != 0UL) {
                RtlCopyMemory(
                    row->entries,
                    (const VOID*)idtr.base,
                    copyBytes);
                row->group = processor.Group;
                row->number = processor.Number;
                row->vectorCount = vectorCount;
                row->idtr = idtr;
                row->captured = 1U;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            row->captured = 0U;
        }

        /* Restore the caller's original group affinity before continuing. */
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        if (row->captured != 0U) {
            capturedCount += 1UL;
        }
    }

    /* Reject an empty snapshot and release its private allocation. */
    if (capturedCount == 0UL) {
        ExFreePoolWithTag(rows, KSW_IDT_BASELINE_TAG);
        return STATUS_NOT_FOUND;
    }

    /* Publish the immutable state only after every successful row is complete. */
    RtlZeroMemory(
        &gKswordArkIdtBaseline,
        sizeof(gKswordArkIdtBaseline));
    gKswordArkIdtBaseline.cpus = rows;
    gKswordArkIdtBaseline.cpuCount = capturedCount;
    gKswordArkIdtBaseline.generation = 1UL;
    gKswordArkIdtBaseline.initialized = TRUE;
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
kswordArkIdtBaselineUninitialize(
    VOID
    )
/*++

Routine Description:

    Unpublish and release the immutable IDT baseline at driver unload.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PkswIdtBaselineCpu rows = gKswordArkIdtBaseline.cpus;

    /* Unpublish state before freeing the private array. */
    RtlZeroMemory(
        &gKswordArkIdtBaseline,
        sizeof(gKswordArkIdtBaseline));

    /* Release only an allocation owned by this module. */
    if (rows != NULL) {
        ExFreePoolWithTag(rows, KSW_IDT_BASELINE_TAG);
    }
}

BOOLEAN
kswordArkIdtBaselineQuery(
    _In_ USHORT processorGroup,
    _In_ UCHAR processorNumber,
    _In_ UCHAR vector,
    _Out_opt_ ULONGLONG* tableBaseOut,
    _Out_opt_ ULONG* tableLimitOut,
    _Out_opt_ ULONGLONG* entryAddressOut,
    _Out_opt_ ULONGLONG* rawLowOut,
    _Out_opt_ ULONGLONG* rawHighOut,
    _Out_opt_ ULONGLONG* handlerOut,
    _Out_opt_ ULONG* generationOut
    )
/*++

Routine Description:

    Return one descriptor from the immutable initialization snapshot.

Arguments:

    ProcessorGroup/ProcessorNumber/Vector - Exact descriptor identity.
    Remaining parameters - Optional typed baseline outputs.

Return Value:

    TRUE when the exact descriptor exists.

--*/
{
    PkswIdtBaselineCpu row = NULL;
    const KswIdtBaselineEntry* entry = NULL;
    ULONGLONG rawLow = 0ULL;
    ULONGLONG rawHigh = 0ULL;

    /* Resolve the requested processor against the immutable snapshot. */
    row = kswordArkIdtBaselineFindCpu(
        processorGroup,
        processorNumber);
    if (row == NULL || vector >= row->vectorCount) {
        return FALSE;
    }

    /* Copy the fixed gate halves without unaligned integer dereferences. */
    entry = &row->entries[vector];
    RtlCopyMemory(&rawLow, entry, sizeof(rawLow));
    RtlCopyMemory(
        &rawHigh,
        (const UCHAR*)entry + sizeof(rawLow),
        sizeof(rawHigh));

    /* Populate only outputs explicitly requested by the caller. */
    if (tableBaseOut != NULL) {
        *tableBaseOut = (ULONGLONG)row->idtr.base;
    }
    if (tableLimitOut != NULL) {
        *tableLimitOut = row->idtr.limit;
    }
    if (entryAddressOut != NULL) {
        *entryAddressOut =
            (ULONGLONG)row->idtr.base +
            ((ULONGLONG)vector * KSW_IDT_BASELINE_ENTRY_BYTES);
    }
    if (rawLowOut != NULL) {
        *rawLowOut = rawLow;
    }
    if (rawHighOut != NULL) {
        *rawHighOut = rawHigh;
    }
    if (handlerOut != NULL) {
        *handlerOut = kswordArkIdtBaselineHandler(entry);
    }
    if (generationOut != NULL) {
        *generationOut = gKswordArkIdtBaseline.generation;
    }
    return TRUE;
}

NTSTATUS
kswordArkIdtBaselineRestore(
    _In_ const KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST* request,
    _Out_ KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE* response
    )
/*++

Routine Description:

    Restore one IDT descriptor using an aligned CMPXCHG16B after exact CPU,
    table, immutable baseline and expected-current validation.

Arguments:

    Request - Fixed protocol request with exact expected current descriptor.
    Response - Fixed result including before/baseline/after halves.

Return Value:

    STATUS_SUCCESS when Response is valid; semantic status is in Response.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    PkswIdtBaselineCpu baselineCpu = NULL;
    const KswIdtBaselineEntry* baselineEntry = NULL;
    PROCESSOR_NUMBER requestedProcessor;
    PROCESSOR_NUMBER processor;
    ULONG processorIndex = MAXULONG;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    KswIdtBaselineRegister currentIdtr;
    volatile LONG64* destination = NULL;
    LONG64 comparand[2] = { 0, 0 };
    ULONGLONG currentLow = 0ULL;
    ULONGLONG currentHigh = 0ULL;
    ULONGLONG afterLow = 0ULL;
    ULONGLONG afterHigh = 0ULL;
    CHAR exchanged = 0;
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate fixed protocol identity before touching processor affinity. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->status =
        KSWORD_ARK_IDT_RESTORE_STATUS_INVALID_REQUEST;
    if (request->version != KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->confirmationToken !=
            KSWORD_ARK_IDT_RESTORE_CONFIRMATION_TOKEN) {
        return STATUS_SUCCESS;
    }

    /* Require the exact immutable processor/vector snapshot. */
    baselineCpu = kswordArkIdtBaselineFindCpu(
        request->processorGroup,
        request->processorNumber);
    if (baselineCpu == NULL ||
        request->vector >= baselineCpu->vectorCount) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_BASELINE_MISSING;
        response->lastStatus = STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    baselineEntry = &baselineCpu->entries[request->vector];
    response->baselineGeneration =
        gKswordArkIdtBaseline.generation;
    RtlCopyMemory(
        &response->baselineRawLow,
        baselineEntry,
        sizeof(response->baselineRawLow));
    RtlCopyMemory(
        &response->baselineRawHigh,
        (const UCHAR*)baselineEntry +
            sizeof(response->baselineRawLow),
        sizeof(response->baselineRawHigh));

    /* Resolve the processor identity again against the live topology. */
    RtlZeroMemory(&requestedProcessor, sizeof(requestedProcessor));
    RtlZeroMemory(&processor, sizeof(processor));
    requestedProcessor.Group = request->processorGroup;
    requestedProcessor.Number = request->processorNumber;
    processorIndex =
        KeGetProcessorIndexFromNumber(&requestedProcessor);
    if (processorIndex == MAXULONG) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        response->lastStatus = STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    status = KeGetProcessorNumberFromIndex(
        processorIndex,
        &processor);
    if (!NT_SUCCESS(status) ||
        processor.Group != request->processorGroup ||
        processor.Number != request->processorNumber) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    /* Pin the current thread to the exact processor owning this IDT. */
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
    targetAffinity.Group = request->processorGroup;
    targetAffinity.Mask =
        ((KAFFINITY)1) << request->processorNumber;
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &previousAffinity);

    /* Re-read IDTR and reject a table replacement since initialization. */
    RtlZeroMemory(&currentIdtr, sizeof(currentIdtr));
    __sidt(&currentIdtr);
    if (currentIdtr.base != baselineCpu->idtr.base ||
        currentIdtr.limit != baselineCpu->idtr.limit) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_TABLE_CHANGED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Calculate and validate the naturally aligned 16-byte gate address. */
    response->entryAddress =
        (ULONGLONG)currentIdtr.base +
        ((ULONGLONG)request->vector *
            KSW_IDT_BASELINE_ENTRY_BYTES);
    if ((response->entryAddress &
            (KSW_IDT_BASELINE_ENTRY_BYTES - 1UL)) != 0ULL) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED;
        response->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    destination =
        (volatile LONG64*)(ULONG_PTR)response->entryAddress;

    /* Copy the live descriptor under exception protection. */
    __try {
        RtlCopyMemory(
            &currentLow,
            (const VOID*)destination,
            sizeof(currentLow));
        RtlCopyMemory(
            &currentHigh,
            (const UCHAR*)destination + sizeof(currentLow),
            sizeof(currentHigh));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_WRITE_FAILED;
        response->lastStatus = status;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    response->beforeRawLow = currentLow;
    response->beforeRawHigh = currentHigh;

    /* Compare both halves with the UI snapshot to prevent stale restoration. */
    if (currentLow != request->expectedRawLow ||
        currentHigh != request->expectedRawHigh) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CURRENT_MISMATCH;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* The non-force call is a read-only preflight used for the first prompt. */
    if ((request->flags & KSWORD_ARK_IDT_RESTORE_FLAG_FORCE) == 0UL) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_FORCE_REQUIRED;
        response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Atomically replace the complete gate only if both observed halves match. */
    comparand[0] = (LONG64)currentLow;
    comparand[1] = (LONG64)currentHigh;
    exchanged = _InterlockedCompareExchange128(
        destination,
        (LONG64)response->baselineRawHigh,
        (LONG64)response->baselineRawLow,
        comparand);
    KeMemoryBarrier();
    if (exchanged == 0) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CURRENT_MISMATCH;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Read back both halves and require an exact baseline match. */
    __try {
        RtlCopyMemory(
            &afterLow,
            (const VOID*)destination,
            sizeof(afterLow));
        RtlCopyMemory(
            &afterHigh,
            (const UCHAR*)destination + sizeof(afterLow),
            sizeof(afterHigh));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_VERIFY_FAILED;
        response->lastStatus = status;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }
    response->afterRawLow = afterLow;
    response->afterRawHigh = afterHigh;
    if (afterLow != response->baselineRawLow ||
        afterHigh != response->baselineRawHigh) {
        response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_VERIFY_FAILED;
        response->lastStatus = STATUS_DATA_ERROR;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_SUCCESS;
    }

    /* Restore affinity after the atomic, verified update completes. */
    response->status = KSWORD_ARK_IDT_RESTORE_STATUS_OK;
    response->lastStatus = STATUS_SUCCESS;
    KeRevertToUserGroupAffinityThread(&previousAffinity);
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Request);
    if (Response != NULL) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version =
            KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_IDT_RESTORE_STATUS_CPU_UNAVAILABLE;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
#endif
}
