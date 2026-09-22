/*++

Module Name:

    mutation_transaction.c

Abstract:

    Controlled kernel mutation transaction backend.

Environment:

    Kernel-mode Driver Framework

--*/

#include "mutation_transaction.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_dyndata.h"
#include "ark/ark_log.h"
#include "ark/ark_safety.h"

#include <ntstrsafe.h>

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#define KSWORD_ARK_MUTATION_INITING 1L
#define KSWORD_ARK_MUTATION_READY 2L
#define KSWORD_ARK_MUTATION_FNV_OFFSET 14695981039346656037ULL
#define KSWORD_ARK_MUTATION_FNV_PRIME 1099511628211ULL
#define KSWORD_ARK_MUTATION_USER_TOP 0x00007FFFFFFFFFFFULL
#define KSWORD_ARK_MUTATION_KERNEL_BASE 0xFFFF800000000000ULL
#define KSWORD_ARK_MUTATION_TRANSACTION_TTL_SECONDS 120UL
#define KSWORD_ARK_MUTATION_TERMINAL_TTL_SECONDS 30UL

typedef struct KswordArkMutationSlot
{
    BOOLEAN inUse;
    BOOLEAN operationBusy;
    BOOLEAN commitAttempted;
    BOOLEAN commitSucceeded;
    BOOLEAN rollbackAttempted;
    ULONG flags;
    ULONG status;
    ULONG targetKind;
    ULONG ownerProcessId;
    PEPROCESS ownerProcessObject;
    PEPROCESS targetProcessObject;
    ULONG processId;
    ULONG bytes;
    ULONG riskFlags;
    NTSTATUS lastStatus;
    ULONGLONG transactionId;
    ULONGLONG targetAddress;
    ULONGLONG targetContext;
    ULONGLONG beforeHash;
    ULONGLONG afterHash;
    ULONGLONG timestampTick;
    UCHAR beforeBytes[KSWORD_ARK_MUTATION_MAX_BYTES];
    UCHAR afterBytes[KSWORD_ARK_MUTATION_MAX_BYTES];
} KswordArkMutationSlot;

typedef struct KswordArkMutationState
{
    EX_PUSH_LOCK lock;
    ULONGLONG nextTransactionId;
    ULONGLONG nextAuditSequence;
    KswordArkMutationSlot slots[KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY];
    KSWORD_ARK_MUTATION_AUDIT_ENTRY audit[KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY];
} KswordArkMutationState;

static KswordArkMutationState gKswordArkMutationState;
static volatile LONG gKswordArkMutationInitState;

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE processId, _Outptr_ PEPROCESS* process);

static VOID
kswordArkMutationEnsureInitialized(VOID)
/*++ Routine Description:
     Input none; initializes global lock, transaction ids, and audit sequence once.
     Processing is interlocked and wait-free after initialization. Return none. --*/
{
    LONG oldState = InterlockedCompareExchange((volatile LONG*)&gKswordArkMutationInitState, KSWORD_ARK_MUTATION_INITING, 0L);
    if (oldState == 0L) {
        RtlZeroMemory(&gKswordArkMutationState, sizeof(gKswordArkMutationState));
        ExInitializePushLock(&gKswordArkMutationState.lock);
        gKswordArkMutationState.nextTransactionId = 1ULL;
        gKswordArkMutationState.nextAuditSequence = 1ULL;
        InterlockedExchange((volatile LONG*)&gKswordArkMutationInitState, KSWORD_ARK_MUTATION_READY);
        return;
    }
    while (InterlockedCompareExchange((volatile LONG*)&gKswordArkMutationInitState, KSWORD_ARK_MUTATION_READY, KSWORD_ARK_MUTATION_READY) != KSWORD_ARK_MUTATION_READY) {
        YieldProcessor();
    }
}

VOID
kswordArkMutationInitialize(VOID)
/*++ Routine Description:
     Input none; exposes explicit initialization for future DriverEntry integration.
     Processing delegates to lazy init. Return none. --*/
{
    kswordArkMutationEnsureInitialized();
}

static VOID
kswordArkMutationClearSlotLocked(
    _Inout_ KswordArkMutationSlot* slot)
/*++ Routine Description:
     Clears one global transaction slot while the mutation lock is held. The
     global slot exclusively owns its process-object reference; stack snapshots
     copy the pointer only for comparison and never release it. --*/
{
    if (slot == NULL) {
        return;
    }
    if (slot->ownerProcessObject != NULL) {
        ObDereferenceObject(slot->ownerProcessObject);
        slot->ownerProcessObject = NULL;
    }
    if (slot->targetProcessObject != NULL) {
        ObDereferenceObject(slot->targetProcessObject);
        slot->targetProcessObject = NULL;
    }
    RtlSecureZeroMemory(slot, sizeof(*slot));
}

VOID
kswordArkMutationUninitialize(VOID)
/*++ Routine Description:
     Releases all process-object references retained by mutation transactions
     after IOCTL dispatch has stopped during driver unload. --*/
{
    ULONG index = 0UL;

    if (InterlockedCompareExchange(
            (volatile LONG*)&gKswordArkMutationInitState,
            KSWORD_ARK_MUTATION_READY,
            KSWORD_ARK_MUTATION_READY) !=
        KSWORD_ARK_MUTATION_READY) {
        return;
    }

    kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
    for (index = 0UL;
         index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
         index += 1UL) {
        kswordArkMutationClearSlotLocked(
            &gKswordArkMutationState.slots[index]);
    }
    kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
}

static ULONGLONG
kswordArkMutationTick(VOID)
/*++ Routine Description:
     Input none; reads a monotonic kernel tick for audit timestamps. Returns tick. --*/
{
    LARGE_INTEGER tick;
    KeQueryTickCount(&tick);
    return (ULONGLONG)tick.QuadPart;
}

static ULONGLONG
kswordArkMutationSecondsToTicks(_In_ ULONG seconds)
/*++ Routine Description:
     Converts a bounded wall-clock interval to KeQueryTickCount units. --*/
{
    const ULONGLONG kIncrement100ns =
        (ULONGLONG)KeQueryTimeIncrement();
    const ULONGLONG kInterval100ns =
        (ULONGLONG)seconds * 10000000ULL;

    if (kIncrement100ns == 0ULL) {
        return 1ULL;
    }
    return (kInterval100ns + kIncrement100ns - 1ULL) /
        kIncrement100ns;
}

static VOID
kswordArkMutationExpireSlotsLocked(_In_ ULONGLONG nowTick)
/*++ Routine Description:
     Clears nonbusy expired transactions while the caller holds the mutation
     lock. Rolled-back terminal state is retained briefly so replay is rejected
     explicitly; prepared/committed state remains available long enough for one
     owner-bound rollback. --*/
{
    const ULONGLONG kTransactionTtl =
        kswordArkMutationSecondsToTicks(
            KSWORD_ARK_MUTATION_TRANSACTION_TTL_SECONDS);
    const ULONGLONG kTerminalTtl =
        kswordArkMutationSecondsToTicks(
            KSWORD_ARK_MUTATION_TERMINAL_TTL_SECONDS);
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
         index += 1UL) {
        KswordArkMutationSlot* slot =
            &gKswordArkMutationState.slots[index];
        ULONGLONG ttl = kTransactionTtl;

        if (!slot->inUse || slot->operationBusy) {
            continue;
        }
        if (slot->rollbackAttempted) {
            ttl = kTerminalTtl;
        }
        if ((nowTick - slot->timestampTick) < ttl) {
            continue;
        }
        kswordArkMutationClearSlotLocked(slot);
    }
}

static ULONGLONG
kswordArkMutationHash(_In_reads_bytes_opt_(byteCount) const UCHAR* bytes, _In_ ULONG byteCount)
/*++ Routine Description:
     Input is a bounded byte buffer; computes FNV-1a as a compact non-crypto
     before/after marker. Returns a 64-bit hash. --*/
{
    ULONGLONG hashValue = KSWORD_ARK_MUTATION_FNV_OFFSET;
    ULONG index = 0UL;
    if (bytes == NULL || byteCount == 0UL) {
        return hashValue;
    }
    for (index = 0UL; index < byteCount; index += 1UL) {
        hashValue ^= (ULONGLONG)bytes[index];
        hashValue *= KSWORD_ARK_MUTATION_FNV_PRIME;
    }
    return hashValue;
}

static BOOLEAN
kswordArkMutationOffsetPresent(_In_ ULONG offset)
/*++ Routine Description:
     Input is a DynData offset; filters unavailable sentinels before private field
     access. Returns TRUE only for usable offsets. --*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkMutationKernelAddress(_In_ ULONGLONG address)
/*++ Routine Description:
     Input is a virtual address integer; checks x64 canonical kernel half only.
     Returns TRUE for accepted kernel addresses. --*/
{
    if (address <= KSWORD_ARK_MUTATION_USER_TOP) {
        return FALSE;
    }
    if (address < KSWORD_ARK_MUTATION_KERNEL_BASE) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkMutationRangeReadable(_In_ ULONGLONG address, _In_ ULONG bytes)
/*++ Routine Description:
     Inputs are address and byte count; verifies a canonical, non-wrapping small
     kernel range. MmCopyMemory performs the actual fault-contained read, so this
     predicate does not reject a valid pageable kernel mapping merely because it
     is not resident at this instant. Returns TRUE for a syntactically valid
     snapshot range. --*/
{
    /* Reject zero-length and protocol-oversized requests before address math. */
    if (bytes == 0UL || bytes > KSWORD_ARK_MUTATION_MAX_BYTES) {
        /* A transaction may never escape its fixed response and audit buffers. */
        return FALSE;
    }
    /* Reject unsigned wraparound at the end of the requested byte range. */
    if ((ULONGLONG)bytes > (((ULONGLONG)-1) - address + 1ULL)) {
        /* A wrapping target cannot be represented by one exact transaction. */
        return FALSE;
    }
    /* Both endpoints must stay inside the canonical x64 kernel half. */
    if (!kswordArkMutationKernelAddress(address) || !kswordArkMutationKernelAddress(address + (ULONGLONG)bytes - 1ULL)) {
        /* User addresses and the noncanonical hole are outside this target kind. */
        return FALSE;
    }
    /* The caller must use MmCopyMemory or an exception-guarded locked MDL next. */
    return TRUE;
}

static NTSTATUS
kswordArkMutationReadKernelBytes(_In_ ULONGLONG address, _Out_writes_bytes_(bytes) UCHAR* buffer, _In_ ULONG bytes)
/*++ Routine Description:
     Inputs are kernel virtual address and byte count; copies a checked system
     range with MmCopyMemory virtual mode. Processing is read-only. Returns full
     copy status or a validation failure. --*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    if (buffer == NULL || !kswordArkMutationRangeReadable(address, bytes)) {
        return STATUS_ACCESS_VIOLATION;
    }
    /* MmCopyMemory may fault pageable system addresses only at APC_LEVEL or below. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        /* Defer rather than touching a pageable target at elevated IRQL. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)address;
    status = MmCopyMemory(buffer, copyAddress, (SIZE_T)bytes, MM_COPY_MEMORY_VIRTUAL, &copied);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return (copied == (SIZE_T)bytes) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static NTSTATUS
kswordArkMutationWriteKernelBytes(
    _In_ ULONGLONG address,
    _In_reads_bytes_(bytes) const UCHAR* expectedBytes,
    _In_reads_bytes_(bytes) const UCHAR* buffer,
    _In_ ULONG bytes
    )
/*++

Routine Description:

    Writes one previously snapshotted kernel virtual-address range through a
    temporary writable MDL alias.  The caller has already compared the current
    bytes with the PREPARE snapshot and evaluated the central safety policy.
    This path never clears CR0.WP and never leaves a writable mapping behind.

Arguments:

    Address - Canonical kernel virtual address captured by PREPARE.
    ExpectedBytes - Bytes that must still be present immediately before copy.
    Buffer - Replacement or rollback bytes owned by the transaction slot.
    Bytes - Bounded transaction length.

Return Value:

    STATUS_SUCCESS after the alias write is visible, or an allocation, probe,
    mapping, protection, or exception status.

--*/
{
    /* The MDL describes the exact caller-selected virtual byte range. */
    PMDL mdl = NULL;
    /* The temporary system mapping is the only address used for the write. */
    PVOID writableAlias = NULL;
    /* Track whether MmProbeAndLockPages completed before cleanup unlocks it. */
    BOOLEAN pagesLocked = FALSE;
    /* Invalidate all processor mappings only after the alias is removed. */
    BOOLEAN writeCompleted = FALSE;
    /* Preserve the first concrete failure for the transaction response. */
    NTSTATUS status = STATUS_SUCCESS;

    /* Reapply the same canonical, nonwrapping and length gate used by PREPARE. */
    if (expectedBytes == NULL
        || buffer == NULL
        || !kswordArkMutationRangeReadable(address, bytes)) {
        /* Refuse an address that no longer satisfies the transaction boundary. */
        return STATUS_ACCESS_VIOLATION;
    }
    /* Page probing, locking and mapping are intentionally confined to PASSIVE. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* The R3 caller can retry through a passive execution-level queue. */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Probe operations raise for invalid mappings, so cleanup is exception safe. */
    __try {
        /* Allocate an MDL for the exact virtual range without attaching an IRP. */
        mdl = IoAllocateMdl(
            (PVOID)(ULONG_PTR)address,
            bytes,
            FALSE,
            FALSE,
            NULL);
        /* Allocation failure leaves the target untouched. */
        if (mdl == NULL) {
            /* Surface the resource failure to the audited transaction result. */
            status = STATUS_INSUFFICIENT_RESOURCES;
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /*
         * Probe the original mapping only for read access so a normal read-only
         * image section (for example, kernel .text) is not rejected. The locked
         * PFNs are then exposed through a separate temporary writable alias.
         */
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        /* Cleanup may now safely call MmUnlockPages. */
        pagesLocked = TRUE;

        /*
         * Build a distinct non-executable mapping so the original mapping's
         * execute permissions are not broadened and CR0.WP is never changed.
         */
        writableAlias = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        /* A missing alias means no byte has been modified. */
        if (writableAlias == NULL) {
            /* Report a bounded allocation/mapping failure. */
            status = STATUS_INSUFFICIENT_RESOURCES;
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /* Explicitly grant write access only to the temporary system alias. */
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        /* Protection failure leaves the original target mapping unchanged. */
        if (!NT_SUCCESS(status)) {
            /* Leave the guarded block through the common cleanup path. */
            __leave;
        }

        /*
         * Narrow the compare/write race by checking through the locked alias.
         * Generic live kernel memory cannot provide a true multi-byte atomic
         * CAS, so a concurrent change after this comparison remains an
         * explicitly reported risk.
         */
        if (RtlCompareMemory(
                writableAlias,
                expectedBytes,
                bytes) != bytes) {
            status = STATUS_REVISION_MISMATCH;
            __leave;
        }

        /* Copy only the transaction's bounded replacement or rollback bytes. */
        RtlCopyMemory(writableAlias, buffer, bytes);
        /* Publish the alias copy before its mapping is removed. */
        KeMemoryBarrier();
        writeCompleted = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Convert a probe, map, protection, or copy exception to NTSTATUS. */
        status = GetExceptionCode();
    }

    /* Remove the writable alias immediately after the bounded copy attempt. */
    if (writableAlias != NULL) {
        /* Unmap only the alias created by MmMapLockedPagesSpecifyCache. */
        MmUnmapLockedPages(writableAlias, mdl);
        /* Prevent cleanup from observing a stale writable virtual address. */
        writableAlias = NULL;
    }
    if (NT_SUCCESS(status) &&
        writeCompleted &&
        mdl != NULL &&
        pagesLocked) {
        /*
         * KeInvalidateRangeAllCaches flushes this physical range for every
         * virtual mapping on every processor and completes before returning.
         * It provides fetch visibility, not execution quiescence or atomicity.
         */
        KeInvalidateRangeAllCaches(
            (PVOID)(ULONG_PTR)address,
            bytes);
        KeMemoryBarrier();
    }
    /* Release physical-page locks only when the probe completed successfully. */
    if (mdl != NULL && pagesLocked) {
        /* Restore the pages to their normal memory-manager lifecycle. */
        MmUnlockPages(mdl);
        /* Prevent any accidental double unlock in future cleanup edits. */
        pagesLocked = FALSE;
    }
    /* Free the MDL descriptor after mapping and locking state is gone. */
    if (mdl != NULL) {
        /* The MDL contains no caller-owned buffer that needs separate freeing. */
        IoFreeMdl(mdl);
        /* Clear the local pointer before returning the final status. */
        mdl = NULL;
    }

    /* The commit path performs a fresh read and exact byte verification next. */
    return status;
}

static NTSTATUS
kswordArkMutationReadPplBytes(_In_ PEPROCESS processObject, _In_ const KswDynState* dynState, _Out_writes_bytes_(bytes) UCHAR* buffer, _In_ ULONG bytes)
/*++ Routine Description:
     Inputs are EPROCESS, DynData, output buffer, and count. Processing reads
     logical Protection, SignatureLevel, SectionSignatureLevel bytes by DynData
     offsets without contiguous-layout assumptions. Returns NTSTATUS. --*/
{
    ULONG offsets[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0UL };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (processObject == NULL || dynState == NULL || buffer == NULL || bytes == 0UL || bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    offsets[0] = dynState->kernel.epProtection;
    offsets[1] = dynState->kernel.epSignatureLevel;
    offsets[2] = dynState->kernel.epSectionSignatureLevel;
    __try {
        for (index = 0UL; index < bytes; index += 1UL) {
            if (!kswordArkMutationOffsetPresent(offsets[index])) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                break;
            }
            RtlCopyMemory(&buffer[index], (PUCHAR)processObject + offsets[index], sizeof(buffer[index]));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

static NTSTATUS
kswordArkMutationWritePplBytes(_In_ PEPROCESS processObject, _In_ const KswDynState* dynState, _In_reads_bytes_(bytes) const UCHAR* expectedBytes, _In_reads_bytes_(bytes) const UCHAR* buffer, _In_ ULONG bytes)
/*++ Routine Description:
     Inputs are EPROCESS, DynData, expected/source bytes, and count. Processing
     validates every DynData offset, compares each byte immediately before its
     individual write, verifies the full result, and best-effort compensates
     already-written fields after any partial failure. Multi-byte PPL updates are
     explicitly not atomic. Returns STATUS_PARTIAL_COPY whenever a write began
     but the requested final state was not fully verified. --*/
{
    ULONG offsets[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0UL };
    UCHAR current[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0U };
    UCHAR verify[KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES] = { 0U };
    ULONG index = 0UL;
    ULONG written = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (processObject == NULL ||
        dynState == NULL ||
        expectedBytes == NULL ||
        buffer == NULL ||
        bytes == 0UL ||
        bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    offsets[0] = dynState->kernel.epProtection;
    offsets[1] = dynState->kernel.epSignatureLevel;
    offsets[2] = dynState->kernel.epSectionSignatureLevel;
    for (index = 0UL; index < bytes; index += 1UL) {
        if (!kswordArkMutationOffsetPresent(offsets[index])) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    __try {
        /*
         * Snapshot all logical fields first, then repeat an individual compare
         * immediately before each byte write to narrow the concurrent-change
         * window without claiming a multi-byte atomic operation.
         */
        for (index = 0UL; index < bytes; index += 1UL) {
            RtlCopyMemory(
                &current[index],
                (PUCHAR)processObject + offsets[index],
                sizeof(current[index]));
        }
        if (RtlCompareMemory(
                current,
                expectedBytes,
                bytes) != bytes) {
            status = STATUS_REVISION_MISMATCH;
        }
        for (index = 0UL;
             NT_SUCCESS(status) && index < bytes;
             index += 1UL) {
            UCHAR beforeWrite = 0U;
            RtlCopyMemory(
                &beforeWrite,
                (PUCHAR)processObject + offsets[index],
                sizeof(beforeWrite));
            if (beforeWrite != expectedBytes[index]) {
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            RtlCopyMemory(
                (PUCHAR)processObject + offsets[index],
                &buffer[index],
                sizeof(buffer[index]));
            written = index + 1UL;
        }
        if (NT_SUCCESS(status)) {
            for (index = 0UL; index < bytes; index += 1UL) {
                RtlCopyMemory(
                    &verify[index],
                    (PUCHAR)processObject + offsets[index],
                    sizeof(verify[index]));
                if (verify[index] != buffer[index]) {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) && written != 0UL) {
        /*
         * Restore only bytes that still equal this transaction's requested
         * value. A third-party value is never overwritten during compensation.
         * A full reread follows even when one compensation step faults.
         */
        __try {
            for (index = 0UL; index < written; index += 1UL) {
                UCHAR observed = 0U;
                RtlCopyMemory(
                    &observed,
                    (PUCHAR)processObject + offsets[index],
                    sizeof(observed));
                if (observed == buffer[index]) {
                    RtlCopyMemory(
                        (PUCHAR)processObject + offsets[index],
                        &expectedBytes[index],
                        sizeof(expectedBytes[index]));
                }
            }
            RtlZeroMemory(verify, sizeof(verify));
            for (index = 0UL; index < bytes; index += 1UL) {
                RtlCopyMemory(
                    &verify[index],
                    (PUCHAR)processObject + offsets[index],
                    sizeof(verify[index]));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(verify, sizeof(verify));
        }
        return STATUS_PARTIAL_COPY;
    }
    return status;
}

static NTSTATUS
kswordArkMutationGetPplTarget(_In_ ULONG processId, _In_ ULONG bytes, _In_ ULONGLONG expectedAddress, _Out_ ULONGLONG* targetAddressOut, _Out_ ULONGLONG* targetContextOut, _Out_writes_bytes_(bytes) UCHAR* currentBytesOut)
/*++ Routine Description:
     Inputs are PID, byte count, optional address, and outputs. Processing checks
     DynData capability, resolves EPROCESS, requires optional address to equal
     EPROCESS+EpProtection, and reads the snapshot. Returns NTSTATUS. --*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (processId == 0UL || bytes == 0UL || bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES || targetAddressOut == NULL || targetContextOut == NULL || currentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkMutationOffsetPresent(dynState.kernel.epProtection) || !kswordArkMutationOffsetPresent(dynState.kernel.epSignatureLevel) || !kswordArkMutationOffsetPresent(dynState.kernel.epSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.kernel.epProtection;
    if (expectedAddress != 0ULL && expectedAddress != protectionAddress) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        status = kswordArkMutationReadPplBytes(processObject, &dynState, currentBytesOut, bytes);
    }
    if (NT_SUCCESS(status)) {
        *targetAddressOut = protectionAddress;
        *targetContextOut = processAddress;
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
kswordArkMutationReadPplForSlot(_In_ const KswordArkMutationSlot* slot, _Out_writes_bytes_(slot->bytes) UCHAR* currentBytesOut)
/*++ Routine Description:
     Inputs are a slot and output buffer. Processing re-resolves PID, refreshes
     DynData, rejects PID reuse by EPROCESS/address mismatch, then reads bytes.
     Returns NTSTATUS. --*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (slot == NULL || currentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkMutationOffsetPresent(dynState.kernel.epProtection) || !kswordArkMutationOffsetPresent(dynState.kernel.epSignatureLevel) || !kswordArkMutationOffsetPresent(dynState.kernel.epSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(slot->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.kernel.epProtection;
    if (processObject != slot->targetProcessObject ||
        processAddress != slot->targetContext ||
        protectionAddress != slot->targetAddress) {
        status = STATUS_REVISION_MISMATCH;
    }
    else {
        status = kswordArkMutationReadPplBytes(processObject, &dynState, currentBytesOut, slot->bytes);
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
kswordArkMutationWritePplForSlot(_In_ const KswordArkMutationSlot* slot, _In_reads_bytes_(slot->bytes) const UCHAR* expectedBytes, _In_reads_bytes_(slot->bytes) const UCHAR* bytes)
/*++ Routine Description:
     Inputs are a slot and source bytes. Processing revalidates PID, DynData, and
     target address before writing PPL fields. Returns guarded write status. --*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONGLONG processAddress = 0ULL;
    ULONGLONG protectionAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (slot == NULL ||
        expectedBytes == NULL ||
        bytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkMutationOffsetPresent(dynState.kernel.epProtection) || !kswordArkMutationOffsetPresent(dynState.kernel.epSignatureLevel) || !kswordArkMutationOffsetPresent(dynState.kernel.epSectionSignatureLevel)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = PsLookupProcessByProcessId(ULongToHandle(slot->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    processAddress = (ULONGLONG)(ULONG_PTR)processObject;
    protectionAddress = processAddress + (ULONGLONG)dynState.kernel.epProtection;
    if (processObject != slot->targetProcessObject ||
        processAddress != slot->targetContext ||
        protectionAddress != slot->targetAddress) {
        status = STATUS_REVISION_MISMATCH;
    }
    else {
        status = kswordArkMutationWritePplBytes(
            processObject,
            &dynState,
            expectedBytes,
            bytes,
            slot->bytes);
    }
    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
kswordArkMutationReadSlotBytes(_In_ const KswordArkMutationSlot* slot, _Out_writes_bytes_(slot->bytes) UCHAR* currentBytesOut)
/*++ Routine Description:
     Inputs are prepared slot and output buffer. Processing dispatches to PPL or
     kernel snapshot readers. Returns target-specific read status. --*/
{
    if (slot == NULL || currentBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (slot->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return kswordArkMutationReadPplForSlot(slot, currentBytesOut);
    }
    if (slot->targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL || slot->targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return kswordArkMutationReadKernelBytes(slot->targetAddress, currentBytesOut, slot->bytes);
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
kswordArkMutationWriteSlotBytes(
    _In_ const KswordArkMutationSlot* slot,
    _In_reads_bytes_(slot->bytes) const UCHAR* expectedBytes,
    _In_reads_bytes_(slot->bytes) const UCHAR* bytes)
/*++ Routine Description:
     Inputs are prepared slot and source bytes. Processing writes only supported
     guarded target kinds; all others fail closed. Returns NTSTATUS. --*/
{
    if (slot == NULL || expectedBytes == NULL || bytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (slot->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return kswordArkMutationWritePplForSlot(
            slot,
            expectedBytes,
            bytes);
    }
    if (slot->targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return kswordArkMutationWriteKernelBytes(
            slot->targetAddress,
            expectedBytes,
            bytes,
            slot->bytes);
    }
    return STATUS_NOT_SUPPORTED;
}

static ULONG
kswordArkMutationTargetRisk(_In_ ULONG targetKind)
/*++ Routine Description:
     Input is target kind; maps it to stable audit risk flags. Returns bitmask. --*/
{
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return KSWORD_ARK_MUTATION_RISK_KERNEL_PATCH_SURFACE |
            KSWORD_ARK_MUTATION_RISK_CANONICAL_REQUIRED |
            KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED |
            KSWORD_ARK_MUTATION_RISK_WRITABLE_MDL_ALIAS |
            KSWORD_ARK_MUTATION_RISK_EXECUTABLE_BYTES_MAY_BE_LIVE |
            KSWORD_ARK_MUTATION_RISK_WRITE_VERIFY_REQUIRED;
    }
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KSWORD_ARK_MUTATION_RISK_PROCESS_PROTECTION_SURFACE | KSWORD_ARK_MUTATION_RISK_DYNDATA_REQUIRED | KSWORD_ARK_MUTATION_RISK_DYNDATA_CONFIRMED | KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED;
    }
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return KSWORD_ARK_MUTATION_RISK_CALLBACK_UNLINK_SURFACE | KSWORD_ARK_MUTATION_RISK_PLAN_ONLY | KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN | KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED;
    }
    return KSWORD_ARK_MUTATION_RISK_NONE;
}

static ULONG
kswordArkMutationSafetyOp(_In_ ULONG targetKind)
/*++ Routine Description:
     Input is target kind; maps it to central safety operation id. Returns id. --*/
{
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        return KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    }
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        return KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
    }
    if (targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        return KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL;
    }
    return KSWORD_ARK_SAFETY_OPERATION_NONE;
}

static ULONG
kswordArkMutationFailureStatus(_In_ NTSTATUS status, _In_ ULONG defaultStatus)
/*++ Routine Description:
     Inputs are NTSTATUS and fallback status; maps known failures into shared
     mutation status codes. Returns shared status. --*/
{
    if (status == STATUS_REVISION_MISMATCH) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
    }
    if (status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_UNSUPPORTED_TARGET;
    }
    if (status == STATUS_NOT_FOUND) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND;
    }
    if (status == STATUS_DEVICE_BUSY) {
        return KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
    }
    return defaultStatus;
}

static VOID
kswordArkMutationFillResponse(_Out_ KSWORD_ARK_MUTATION_RESPONSE* response, _In_ const KswordArkMutationSlot* slot, _In_ ULONG status, _In_ NTSTATUS lastStatus, _In_ ULONG riskFlags)
/*++ Routine Description:
     Inputs are response, slot, status, NTSTATUS, and risk flags. Processing copies
     bounded transaction metadata and snapshots. Return none. --*/
{
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    response->status = status;
    response->targetKind = slot->targetKind;
    response->processId = slot->processId;
    response->bytes = slot->bytes;
    response->riskFlags = riskFlags;
    response->lastStatus = lastStatus;
    response->transactionId = slot->transactionId;
    response->targetAddress = slot->targetAddress;
    response->targetContext = slot->targetContext;
    response->beforeHash = slot->beforeHash;
    response->afterHash = slot->afterHash;
    response->timestampTick = slot->timestampTick;
    RtlCopyMemory(response->beforeBytes, slot->beforeBytes, sizeof(response->beforeBytes));
    RtlCopyMemory(response->afterBytes, slot->afterBytes, sizeof(response->afterBytes));
}

static VOID
kswordArkMutationAuditLocked(_In_ ULONG operation, _In_ const KswordArkMutationSlot* slot, _In_ ULONG status, _In_ NTSTATUS lastStatus, _In_ ULONG flags, _In_ ULONG riskFlags, _In_reads_bytes_opt_(slot->bytes) const UCHAR* byteData)
/*++ Routine Description:
     Inputs are event metadata and optional bytes. Processing appends one entry to
     the audit ring while caller holds the write lock. Return none. --*/
{
    ULONGLONG sequence = gKswordArkMutationState.nextAuditSequence;
    ULONG index = (ULONG)(sequence % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
    KSWORD_ARK_MUTATION_AUDIT_ENTRY* entry = &gKswordArkMutationState.audit[index];
    gKswordArkMutationState.nextAuditSequence += 1ULL;
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    entry->operation = operation;
    entry->status = status;
    entry->lastStatus = lastStatus;
    entry->targetKind = slot->targetKind;
    entry->riskFlags = riskFlags;
    entry->flags = flags;
    entry->processId = slot->processId;
    entry->bytes = slot->bytes;
    entry->transactionId = slot->transactionId;
    entry->sequence = sequence;
    entry->targetAddress = slot->targetAddress;
    entry->targetContext = slot->targetContext;
    entry->beforeHash = slot->beforeHash;
    entry->afterHash = slot->afterHash;
    entry->timestampTick = kswordArkMutationTick();
    if (byteData != NULL && slot->bytes <= KSWORD_ARK_MUTATION_MAX_BYTES) {
        RtlCopyMemory(entry->byteData, byteData, slot->bytes);
    }
}

static KswordArkMutationSlot*
kswordArkMutationFindSlotLocked(_In_ ULONGLONG transactionId)
/*++ Routine Description:
     Input is transaction id; scans active slots under caller-held lock. Returns
     matching slot pointer or NULL. --*/
{
    ULONG index = 0UL;
    if (transactionId == 0ULL) {
        return NULL;
    }
    for (index = 0UL; index < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY; index += 1UL) {
        if (gKswordArkMutationState.slots[index].inUse && gKswordArkMutationState.slots[index].transactionId == transactionId) {
            return &gKswordArkMutationState.slots[index];
        }
    }
    return NULL;
}

static NTSTATUS
kswordArkMutationValidatePrepare(_In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* request, _Out_ ULONG* protocolStatusOut, _Out_ ULONG* riskFlagsOut)
/*++ Routine Description:
     Inputs are PREPARE request and output status fields. Processing validates
     size, version, flags, target kind, and length limits. Returns NTSTATUS. --*/
{
    if (protocolStatusOut == NULL || riskFlagsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST;
    *riskFlagsOut = KSWORD_ARK_MUTATION_RISK_NONE;
    if (request == NULL || request->size < sizeof(KSWORD_ARK_MUTATION_PREPARE_REQUEST) || request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || request->reserved != 0UL || request->reserved2 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((request->flags & ~(KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED | KSWORD_ARK_MUTATION_FLAG_DRY_RUN | KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->targetKind != KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL && request->targetKind != KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES && request->targetKind != KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET;
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytes == 0UL || request->bytes > KSWORD_ARK_MUTATION_MAX_BYTES) {
        *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT;
        return STATUS_INVALID_PARAMETER;
    }
    if (request->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES && request->bytes > KSWORD_ARK_MUTATION_PROCESS_PROTECTION_MAX_BYTES) {
        *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT;
        return STATUS_INVALID_PARAMETER;
    }
    *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_PREPARED;
    *riskFlagsOut = KSWORD_ARK_MUTATION_RISK_READ_SNAPSHOT_TAKEN | kswordArkMutationTargetRisk(request->targetKind);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkMutationPrepareSnapshot(_In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* request, _Out_ ULONGLONG* targetAddressOut, _Out_ ULONGLONG* targetContextOut, _Out_writes_bytes_(request->bytes) UCHAR* beforeBytesOut, _Out_ ULONG* protocolStatusOut, _Inout_ ULONG* riskFlagsInOut)
/*++ Routine Description:
     Inputs are request and outputs. Processing validates target-specific address
     rules, reads before bytes, and checks optional expected-before. Returns status. --*/
{
    NTSTATUS status = STATUS_SUCCESS;
    if (request == NULL || targetAddressOut == NULL || targetContextOut == NULL || beforeBytesOut == NULL || protocolStatusOut == NULL || riskFlagsInOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *targetAddressOut = request->targetAddress;
    *targetContextOut = request->targetContext;
    if (request->targetKind == KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
        status = kswordArkMutationGetPplTarget(request->processId, request->bytes, request->targetAddress, targetAddressOut, targetContextOut, beforeBytesOut);
    }
    else if (request->targetKind == KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL) {
        status = kswordArkMutationReadKernelBytes(request->targetAddress, beforeBytesOut, request->bytes);
    }
    else if (request->targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
        *riskFlagsInOut |= KSWORD_ARK_MUTATION_RISK_PLAN_ONLY;
        status = kswordArkMutationReadKernelBytes(request->targetAddress, beforeBytesOut, request->bytes);
    }
    else {
        *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET;
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(status)) {
        *protocolStatusOut = kswordArkMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_READ_FAILED);
        return status;
    }
    if ((request->flags & KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT) != 0UL && RtlCompareMemory(beforeBytesOut, request->expectedBeforeBytes, request->bytes) != request->bytes) {
        *riskFlagsInOut |= KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH;
        *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH;
        return STATUS_REVISION_MISMATCH;
    }
    *protocolStatusOut = KSWORD_ARK_MUTATION_STATUS_PREPARED;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMutationPrepare(_In_opt_ WDFDEVICE device, _In_ ULONG requestorProcessId, _In_ PEPROCESS requestorProcessObject, _In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* request, _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _Out_ size_t* bytesWrittenOut)
/*++ Routine Description:
     Inputs are device, PREPARE request, output buffer, and length. Processing
     validates target, snapshots before bytes, assigns transactionId, and records
     audit without writing target memory. Returns NTSTATUS and response bytes. --*/
{
    KSWORD_ARK_MUTATION_RESPONSE* response = NULL;
    KswordArkMutationSlot slot;
    KswordArkMutationSlot* storedSlot = NULL;
    PEPROCESS targetProcessObject = NULL;
    ULONG protocolStatus = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_MUTATION_RISK_NONE;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    kswordArkMutationEnsureInitialized();
    if (bytesWrittenOut == NULL ||
        outputBuffer == NULL ||
        requestorProcessId == 0UL ||
        requestorProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_MUTATION_RESPONSE*)outputBuffer;
    RtlZeroMemory(&slot, sizeof(slot));
    status = kswordArkMutationValidatePrepare(request, &protocolStatus, &riskFlags);
    if (NT_SUCCESS(status)) {
        status = kswordArkMutationPrepareSnapshot(request, &slot.targetAddress, &slot.targetContext, slot.beforeBytes, &protocolStatus, &riskFlags);
    }
    slot.inUse = TRUE;
    slot.flags = (request != NULL) ? request->flags : 0UL;
    slot.status = protocolStatus;
    slot.targetKind = (request != NULL) ? request->targetKind : KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
    slot.ownerProcessId = requestorProcessId;
    slot.ownerProcessObject = requestorProcessObject;
    slot.processId = (request != NULL) ? request->processId : 0UL;
    slot.bytes = (request != NULL && request->bytes <= KSWORD_ARK_MUTATION_MAX_BYTES) ? request->bytes : 0UL;
    slot.riskFlags = riskFlags;
    slot.lastStatus = status;
    slot.timestampTick = kswordArkMutationTick();
    if (request != NULL && slot.bytes != 0UL) {
        RtlCopyMemory(slot.afterBytes, request->afterBytes, slot.bytes);
    }
    slot.beforeHash = kswordArkMutationHash(slot.beforeBytes, slot.bytes);
    slot.afterHash = kswordArkMutationHash(slot.afterBytes, slot.bytes);
    if (NT_SUCCESS(status)) {
        kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
        kswordArkMutationExpireSlotsLocked(
            kswordArkMutationTick());
        slot.transactionId = gKswordArkMutationState.nextTransactionId;
        gKswordArkMutationState.nextTransactionId += 1ULL;
        if (gKswordArkMutationState.nextTransactionId == 0ULL) {
            gKswordArkMutationState.nextTransactionId = 1ULL;
        }
        index = (ULONG)(slot.transactionId % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
        /*
         * An active transaction is never replaced merely because the ring
         * wrapped. Expiration above creates reusable slots; if all 64 slots
         * are still live, PREPARE fails closed with BUSY.
         */
        {
            ULONG probe = 0UL;
            storedSlot = NULL;
            for (probe = 0UL;
                 probe < KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
                 probe += 1UL) {
                ULONG candidate =
                    (index + probe)
                    % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
                if (!gKswordArkMutationState.slots[candidate].inUse) {
                    index = candidate;
                    storedSlot =
                        &gKswordArkMutationState.slots[candidate];
                    break;
                }
            }
        }
        if (storedSlot == NULL) {
            slot.transactionId = 0ULL;
            slot.status = KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
            slot.lastStatus = STATUS_DEVICE_BUSY;
            protocolStatus = slot.status;
            status = slot.lastStatus;
            kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
            kswordArkMutationFillResponse(
                response,
                &slot,
                protocolStatus,
                status,
                riskFlags);
            *bytesWrittenOut = sizeof(*response);
            return status;
        }
        if (slot.targetKind ==
            KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES) {
            status = PsLookupProcessByProcessId(
                ULongToHandle(slot.processId),
                &targetProcessObject);
            if (!NT_SUCCESS(status) ||
                targetProcessObject == NULL ||
                (ULONGLONG)(ULONG_PTR)targetProcessObject !=
                    slot.targetContext) {
                if (targetProcessObject != NULL) {
                    ObDereferenceObject(targetProcessObject);
                    targetProcessObject = NULL;
                }
                slot.transactionId = 0ULL;
                slot.status =
                    KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
                slot.lastStatus = NT_SUCCESS(status)
                    ? STATUS_REVISION_MISMATCH
                    : status;
                slot.riskFlags |=
                    KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
                protocolStatus = slot.status;
                status = slot.lastStatus;
                kswordArkReleasePushLockExclusive(
                    &gKswordArkMutationState.lock);
                kswordArkMutationFillResponse(
                    response,
                    &slot,
                    protocolStatus,
                    status,
                    slot.riskFlags);
                *bytesWrittenOut = sizeof(*response);
                return status;
            }
            /*
             * PsLookupProcessByProcessId returned the reference that the
             * global slot will own. Keeping the object alive prevents the old
             * EPROCESS address from being recycled into a same-PID target.
             */
            slot.targetProcessObject = targetProcessObject;
        }
        /*
         * Only the global slot owns this reference. Stack copies carry the
         * pointer solely for identity comparison and never release it.
         */
        kswordArkMutationClearSlotLocked(storedSlot);
        ObReferenceObject(requestorProcessObject);
        *storedSlot = slot;
        kswordArkMutationAuditLocked(KSWORD_ARK_MUTATION_OPERATION_PREPARE, storedSlot, KSWORD_ARK_MUTATION_STATUS_PREPARED, STATUS_SUCCESS, request->flags, storedSlot->riskFlags, storedSlot->beforeBytes);
        kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
    }
    kswordArkMutationFillResponse(response, &slot, protocolStatus, status, riskFlags);
    *bytesWrittenOut = sizeof(*response);
    if (device != NULL) {
        CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message), "Mutation prepare: tx=%I64u kind=%lu target=0x%I64X bytes=%lu status=%lu last=0x%08X.", response->transactionId, (unsigned long)response->targetKind, response->targetAddress, (unsigned long)response->bytes, (unsigned long)response->status, (unsigned int)response->lastStatus))) {
            (VOID)kswordArkDriverEnqueueLogFrame(device, NT_SUCCESS(status) ? "Info" : "Warn", message);
        }
    }
    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

static NTSTATUS
kswordArkMutationSafety(_In_opt_ WDFDEVICE device, _In_ const KswordArkMutationSlot* slot, _In_ ULONG requestFlags)
/*++ Routine Description:
     Inputs are optional device, transaction slot, and request flags. Processing
     maps target kind to safety policy and forwards the explicit UI_CONFIRMED
     bit independently of FORCE. Returns policy status. --*/
{
    KswordArkSafetyContext context;
    ULONG operation = KSWORD_ARK_SAFETY_OPERATION_NONE;
    if (slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    operation = kswordArkMutationSafetyOp(slot->targetKind);
    if (operation == KSWORD_ARK_SAFETY_OPERATION_NONE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&context, sizeof(context));
    context.operation = operation;
    context.targetProcessId = slot->processId;
    context.contextFlags =
        ((requestFlags & KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED) != 0UL)
        ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
        : 0UL;
    return kswordArkSafetyEvaluate(device, &context);
}

static NTSTATUS
kswordArkMutationCommitRollback(_In_opt_ WDFDEVICE device, _In_ ULONG requestorProcessId, _In_ PEPROCESS requestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* request, _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _Out_ size_t* bytesWrittenOut, _In_ BOOLEAN rollback)
/*++ Routine Description:
     Inputs are device, transaction request, output buffer, and rollback selector.
     Processing loads PREPARE state by transactionId, dry-runs without FORCE,
     enforces before-match and safety policy with FORCE, performs supported writes,
     verifies, and appends audit. Returns response status. --*/
{
    KSWORD_ARK_MUTATION_RESPONSE* response = NULL;
    KswordArkMutationSlot slot;
    KswordArkMutationSlot* storedSlot = NULL;
    UCHAR current[KSWORD_ARK_MUTATION_MAX_BYTES] = { 0U };
    UCHAR verify[KSWORD_ARK_MUTATION_MAX_BYTES] = { 0U };
    const UCHAR* desired = NULL;
    ULONG eventCode = rollback ? KSWORD_ARK_MUTATION_OPERATION_ROLLBACK : KSWORD_ARK_MUTATION_OPERATION_COMMIT;
    ULONG statusCode = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_MUTATION_RISK_NONE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    BOOLEAN operationClaimed = FALSE;
    BOOLEAN operationBusy = FALSE;
    BOOLEAN ownerMismatch = FALSE;
    BOOLEAN stateRejected = FALSE;
    BOOLEAN dryRun = FALSE;
    BOOLEAN writeAttemptStarted = FALSE;
    BOOLEAN rollbackCompletedWithoutWrite = FALSE;
    kswordArkMutationEnsureInitialized();
    if (bytesWrittenOut == NULL ||
        outputBuffer == NULL ||
        requestorProcessId == 0UL ||
        requestorProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request == NULL || request->size < sizeof(KSWORD_ARK_MUTATION_TRANSACTION_REQUEST) || request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || request->reserved != 0UL || request->transactionId == 0ULL || ((request->flags & ~(KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED | KSWORD_ARK_MUTATION_FLAG_DRY_RUN)) != 0UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    dryRun =
        ((request->flags & KSWORD_ARK_MUTATION_FLAG_DRY_RUN) != 0UL)
        ? TRUE
        : FALSE;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_MUTATION_RESPONSE*)outputBuffer;
    RtlZeroMemory(&slot, sizeof(slot));
    kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
    kswordArkMutationExpireSlotsLocked(
        kswordArkMutationTick());
    storedSlot = kswordArkMutationFindSlotLocked(request->transactionId);
    if (storedSlot != NULL) {
        if (storedSlot->ownerProcessObject != requestorProcessObject) {
            ownerMismatch = TRUE;
            kswordArkMutationAuditLocked(
                eventCode,
                storedSlot,
                KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY,
                STATUS_ACCESS_DENIED,
                request->flags,
                storedSlot->riskFlags |
                    KSWORD_ARK_MUTATION_RISK_POLICY_DENIED,
                NULL);
        }
        else if (storedSlot->operationBusy) {
            slot = *storedSlot;
            operationBusy = TRUE;
        }
        else if (storedSlot->rollbackAttempted ||
                 (!rollback && storedSlot->commitAttempted) ||
                 (rollback && !storedSlot->commitAttempted)) {
            slot = *storedSlot;
            stateRejected = TRUE;
        }
        else {
            storedSlot->operationBusy = TRUE;
            slot = *storedSlot;
            operationClaimed = TRUE;
        }
    }
    kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
    if (storedSlot == NULL) {
        slot.transactionId = request->transactionId;
        kswordArkMutationFillResponse(response, &slot, KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND, STATUS_NOT_FOUND, KSWORD_ARK_MUTATION_RISK_NONE);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (ownerMismatch) {
        RtlZeroMemory(&slot, sizeof(slot));
        slot.transactionId = request->transactionId;
        kswordArkMutationFillResponse(
            response,
            &slot,
            KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY,
            STATUS_ACCESS_DENIED,
            KSWORD_ARK_MUTATION_RISK_POLICY_DENIED);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (operationBusy) {
        slot.status = KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY;
        slot.lastStatus = STATUS_DEVICE_BUSY;
        slot.timestampTick = kswordArkMutationTick();
        kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
        kswordArkMutationAuditLocked(
            eventCode,
            &slot,
            slot.status,
            slot.lastStatus,
            request->flags,
            slot.riskFlags,
            NULL);
        kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
        kswordArkMutationFillResponse(
            response,
            &slot,
            slot.status,
            slot.lastStatus,
            slot.riskFlags);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if (stateRejected) {
        const ULONG kRejectedRisk =
            slot.riskFlags |
            KSWORD_ARK_MUTATION_RISK_POLICY_DENIED;
        kswordArkAcquirePushLockExclusive(
            &gKswordArkMutationState.lock);
        storedSlot = kswordArkMutationFindSlotLocked(
            request->transactionId);
        if (storedSlot != NULL &&
            storedSlot->ownerProcessObject == requestorProcessObject) {
            kswordArkMutationAuditLocked(
                eventCode,
                storedSlot,
                KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST,
                STATUS_INVALID_DEVICE_STATE,
                request->flags,
                kRejectedRisk,
                NULL);
        }
        kswordArkReleasePushLockExclusive(
            &gKswordArkMutationState.lock);
        kswordArkMutationFillResponse(
            response,
            &slot,
            KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST,
            STATUS_INVALID_DEVICE_STATE,
            kRejectedRisk);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    desired = rollback ? slot.beforeBytes : slot.afterBytes;
    riskFlags = slot.riskFlags;
    if (dryRun ||
        (request->flags & KSWORD_ARK_MUTATION_FLAG_FORCE) == 0UL) {
        riskFlags |= KSWORD_ARK_MUTATION_RISK_DRY_RUN;
        if ((request->flags &
             KSWORD_ARK_MUTATION_FLAG_FORCE) == 0UL) {
            riskFlags |=
                KSWORD_ARK_MUTATION_RISK_FORCE_REQUIRED;
        }
        statusCode = KSWORD_ARK_MUTATION_STATUS_DRY_RUN;
        lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
    }
    else {
        riskFlags |= KSWORD_ARK_MUTATION_RISK_FORCE_USED | KSWORD_ARK_MUTATION_RISK_POLICY_REQUIRED;
        status = kswordArkMutationReadSlotBytes(&slot, current);
        if (!NT_SUCCESS(status)) {
            riskFlags |= (status == STATUS_REVISION_MISMATCH) ? KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED : 0UL;
            statusCode = kswordArkMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_READ_FAILED);
            lastStatus = status;
        }
        else if (rollback && RtlCompareMemory(current, slot.beforeBytes, slot.bytes) == slot.bytes) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_ROLLBACK_IDEMPOTENT;
            statusCode = KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
            lastStatus = STATUS_SUCCESS;
            rollbackCompletedWithoutWrite = TRUE;
        }
        else if (rollback && RtlCompareMemory(current, slot.afterBytes, slot.bytes) != slot.bytes) {
            /*
             * Rollback is another expected-before conditional operation.  It is
             * not a multi-byte atomic CAS: a third party may have changed the
             * target after COMMIT, so restoring stale bytes would overwrite
             * evidence or live state that this transaction does not own.
             */
            riskFlags |= KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED;
            lastStatus = STATUS_REVISION_MISMATCH;
        }
        else if (!rollback && RtlCompareMemory(current, slot.beforeBytes, slot.bytes) != slot.bytes) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH;
            lastStatus = STATUS_REVISION_MISMATCH;
        }
        else if (slot.targetKind == KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN) {
            riskFlags |= KSWORD_ARK_MUTATION_RISK_PLAN_ONLY | KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN;
            statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_PLAN_ONLY;
            lastStatus = STATUS_NOT_SUPPORTED;
        }
        else {
            status = kswordArkMutationSafety(device, &slot, request->flags);
            if (!NT_SUCCESS(status)) {
                riskFlags |= KSWORD_ARK_MUTATION_RISK_POLICY_DENIED;
                statusCode = KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY;
                lastStatus = status;
            }
            else {
                kswordArkAcquirePushLockExclusive(
                    &gKswordArkMutationState.lock);
                storedSlot = kswordArkMutationFindSlotLocked(
                    request->transactionId);
                if (storedSlot == NULL ||
                    storedSlot->ownerProcessObject !=
                        requestorProcessObject ||
                    !storedSlot->operationBusy ||
                    (rollback
                        ? storedSlot->rollbackAttempted
                        : storedSlot->commitAttempted)) {
                    status = STATUS_INVALID_DEVICE_STATE;
                }
                else {
                    if (rollback) {
                        storedSlot->rollbackAttempted = TRUE;
                        slot.rollbackAttempted = TRUE;
                    }
                    else {
                        storedSlot->commitAttempted = TRUE;
                        slot.commitAttempted = TRUE;
                    }
                    writeAttemptStarted = TRUE;
                }
                kswordArkReleasePushLockExclusive(
                    &gKswordArkMutationState.lock);
                if (!writeAttemptStarted) {
                    statusCode =
                        KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST;
                    lastStatus = status;
                }
                else {
                    status = kswordArkMutationWriteSlotBytes(
                        &slot,
                        current,
                        desired);
                    if (!NT_SUCCESS(status)) {
                        if (status == STATUS_REVISION_MISMATCH) {
                            riskFlags |= KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED;
                        }
                        statusCode = kswordArkMutationFailureStatus(status, KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED);
                        lastStatus = status;
                    }
                    else {
                        status = kswordArkMutationReadSlotBytes(&slot, verify);
                        if (!NT_SUCCESS(status)) {
                            statusCode = KSWORD_ARK_MUTATION_STATUS_READ_FAILED;
                            lastStatus = status;
                        }
                        else if (RtlCompareMemory(verify, desired, slot.bytes) != slot.bytes) {
                            statusCode = KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED;
                            lastStatus = STATUS_UNSUCCESSFUL;
                        }
                        else {
                            statusCode = rollback ? KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK : KSWORD_ARK_MUTATION_STATUS_COMMITTED;
                            lastStatus = STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }
    slot.status = statusCode;
    slot.riskFlags = riskFlags;
    slot.lastStatus = lastStatus;
    slot.timestampTick = kswordArkMutationTick();
    kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
    storedSlot = kswordArkMutationFindSlotLocked(request->transactionId);
    if (storedSlot != NULL && operationClaimed) {
        storedSlot->status = slot.status;
        storedSlot->riskFlags = slot.riskFlags;
        storedSlot->lastStatus = slot.lastStatus;
        storedSlot->timestampTick = slot.timestampTick;
        if (rollbackCompletedWithoutWrite) {
            storedSlot->rollbackAttempted = TRUE;
        }
        if (!rollback &&
            statusCode ==
                KSWORD_ARK_MUTATION_STATUS_COMMITTED) {
            storedSlot->commitSucceeded = TRUE;
        }
        storedSlot->operationBusy = FALSE;
        kswordArkMutationAuditLocked(eventCode, storedSlot, statusCode, lastStatus, request->flags, riskFlags, desired);
    }
    kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
    kswordArkMutationFillResponse(response, &slot, statusCode, lastStatus, riskFlags);
    *bytesWrittenOut = sizeof(*response);
    if (device != NULL) {
        CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message), "Mutation %s: tx=%I64u kind=%lu status=%lu last=0x%08X.", rollback ? "rollback" : "commit", response->transactionId, (unsigned long)response->targetKind, (unsigned long)response->status, (unsigned int)response->lastStatus))) {
            (VOID)kswordArkDriverEnqueueLogFrame(device, (response->status == KSWORD_ARK_MUTATION_STATUS_COMMITTED || response->status == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK || response->status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE) ? "Info" : "Warn", message);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMutationCommit(_In_opt_ WDFDEVICE device, _In_ ULONG requestorProcessId, _In_ PEPROCESS requestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* request, _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _Out_ size_t* bytesWrittenOut)
/*++ Routine Description:
     Inputs are device, transaction request, and output buffer. Processing commits
     only by transactionId through shared commit/rollback logic. Returns NTSTATUS. --*/
{
    return kswordArkMutationCommitRollback(device, requestorProcessId, requestorProcessObject, request, outputBuffer, outputBufferLength, bytesWrittenOut, FALSE);
}

NTSTATUS
kswordArkMutationRollback(_In_opt_ WDFDEVICE device, _In_ ULONG requestorProcessId, _In_ PEPROCESS requestorProcessObject, _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* request, _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _Out_ size_t* bytesWrittenOut)
/*++ Routine Description:
     Inputs are device, transaction request, and output buffer. Processing restores
     the before snapshot when needed and reports idempotent success if already
     restored. Returns NTSTATUS. --*/
{
    return kswordArkMutationCommitRollback(device, requestorProcessId, requestorProcessObject, request, outputBuffer, outputBufferLength, bytesWrittenOut, TRUE);
}

NTSTATUS
kswordArkMutationQueryAudit(_Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _In_opt_ const KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST* request, _Out_ size_t* bytesWrittenOut)
/*++ Routine Description:
     Inputs are output buffer, length, optional query request, and byte counter.
     Processing copies recent audit entries from the ring; byteData is redacted
     unless INCLUDE_BYTES is set. Returns NTSTATUS and response bytes. --*/
{
    KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE* response = NULL;
    ULONGLONG startSequence = 0ULL;
    ULONGLONG oldestSequence = 0ULL;
    ULONGLONG nextSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG capacity = 0UL;
    ULONG maxEntries = KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY;
    ULONG returned = 0UL;
    ULONG total = 0UL;
    ULONG lost = 0UL;
    BOOLEAN includeBytes = FALSE;
    kswordArkMutationEnsureInitialized();
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request != NULL) {
        if (request->size < sizeof(KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST) || request->version != KSWORD_ARK_MUTATION_PROTOCOL_VERSION || ((request->flags & ~KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES) != 0UL)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (request->maxEntries != 0UL && request->maxEntries < maxEntries) {
            maxEntries = request->maxEntries;
        }
        startSequence = request->startSequence;
        includeBytes = ((request->flags & KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES) != 0UL) ? TRUE : FALSE;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY);
    capacity = (ULONG)((outputBufferLength - KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY));
    if (capacity < maxEntries) {
        maxEntries = capacity;
    }
    kswordArkAcquirePushLockExclusive(&gKswordArkMutationState.lock);
    kswordArkMutationExpireSlotsLocked(
        kswordArkMutationTick());
    nextSequence = gKswordArkMutationState.nextAuditSequence;
    oldestSequence = (nextSequence > KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY) ? (nextSequence - KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY) : 1ULL;
    if (startSequence == 0ULL || startSequence < oldestSequence) {
        if (startSequence != 0ULL && startSequence < oldestSequence) {
            lost = (ULONG)(oldestSequence - startSequence);
        }
        startSequence = oldestSequence;
    }
    if (nextSequence > oldestSequence) {
        total = (ULONG)(nextSequence - oldestSequence);
    }
    for (sequence = startSequence; sequence < nextSequence && returned < maxEntries; sequence += 1ULL) {
        ULONG auditIndex = (ULONG)(sequence % KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
        const KSWORD_ARK_MUTATION_AUDIT_ENTRY* source = &gKswordArkMutationState.audit[auditIndex];
        KSWORD_ARK_MUTATION_AUDIT_ENTRY* destination = &response->entries[returned];
        if (source->sequence != sequence) {
            continue;
        }
        RtlCopyMemory(destination, source, sizeof(*destination));
        if (!includeBytes) {
            RtlZeroMemory(destination->byteData, sizeof(destination->byteData));
        }
        returned += 1UL;
    }
    kswordArkReleasePushLockExclusive(&gKswordArkMutationState.lock);
    response->totalCount = total;
    response->returnedCount = returned;
    response->lostCount = lost;
    response->oldestSequence = oldestSequence;
    response->nextSequence = nextSequence;
    *bytesWrittenOut = KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE + ((size_t)returned * sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
