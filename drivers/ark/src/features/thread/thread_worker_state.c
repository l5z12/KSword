/*++

Module Name:

    thread_worker_state.c

Abstract:

    DynData v4-backed _ETHREAD.ActiveExWorker classification.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "thread_worker_state.h"
#include "../../platform/runtime_signature_scan.h"

VOID
kswordArkThreadMarkFailure(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Mark a thread response row when an attempted optional-field read fails.

Return Value:

    None.

--*/
{
    if (entry == NULL || NT_SUCCESS(status)) {
        return;
    }
    entry->r0Status = KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED;
}

static NTSTATUS
kswordArkThreadReadBitField(
    _In_ PETHREAD threadObject,
    _In_ const KswDynV4BitFieldLayout* field,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Read one bounded PDB-described ETHREAD bit field without assuming a fixed
    Windows structure layout.

Arguments:

    ThreadObject - Referenced ETHREAD object.
    Field - Validated v4 offset, bit range, and storage width.
    ValueOut - Receives the normalized field value.

Return Value:

    STATUS_SUCCESS or a validation/read exception status.

--*/
{
    ULONG64 storageValue = 0ULL;
    ULONG64 valueMask = 0ULL;

    if (threadObject == NULL || field == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!(field->storageBytes == 1UL ||
          field->storageBytes == 2UL ||
          field->storageBytes == 4UL ||
          field->storageBytes == 8UL) ||
        field->bitCount == 0UL ||
        field->bitCount > 64UL ||
        field->bitOffset + field->bitCount > field->storageBytes * 8UL) {
        return STATUS_DATA_ERROR;
    }

    /*
     * A safe read must be used here. The field offset may be inferred at runtime; adding it to ETHREAD
     * can exceed the object's end. Touching unmapped addresses in kernel mode triggers a bugcheck
     * 0x50, not a catchable exception. Thus, __try/__except on this path is only superficially safe.
     */
    if (!kswordArkRuntimeReadMemory(
            (const UCHAR*)threadObject + field->offset,
            &storageValue,
            field->storageBytes)) {
        return STATUS_PARTIAL_COPY;
    }

    valueMask = field->bitCount == 64UL
        ? MAXULONGLONG
        : ((1ULL << field->bitCount) - 1ULL);
    *valueOut = (storageValue >> field->bitOffset) & valueMask;
    return STATUS_SUCCESS;
}

VOID
kswordArkThreadPopulateWorkerField(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ PETHREAD threadObject,
    _In_ const KswDynV4BitFieldLayout* activeExWorkerField
    )
/*++

Routine Description:

    Classify one ETHREAD with the v4 _ETHREAD.ActiveExWorker bit. A separate
    field-present bit distinguishes false from an unavailable layout/read.

Return Value:

    None.

--*/
{
    ULONG64 activeExWorker = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || threadObject == NULL || activeExWorkerField == NULL) {
        return;
    }

    status = kswordArkThreadReadBitField(
        threadObject,
        activeExWorkerField,
        &activeExWorker);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadMarkFailure(entry, status);
        return;
    }

    entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT;
    if (activeExWorker != 0ULL) {
        entry->flags |= KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER;
    }
}
