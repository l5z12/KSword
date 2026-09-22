/*++

Module Name:

    rxpf_self_test.c

Abstract:

    Explicit VM-only concurrent execution harness for one managed RXPF page.

Environment:

    Kernel mode, PASSIVE_LEVEL control path. Worker threads remain at
    PASSIVE_LEVEL so instruction-fetch faults are eligible for RXPF dispatch.

--*/

#include "rxpf_self_test.h"

#include "rxpf_runtime.h"
#include "src/platform/pool_compat.h"

#define KSW_RXPF_SELF_TEST_TAG 'tPxR'

typedef struct KswRxpfConcurrentTestState
    KswRxpfConcurrentTestState,
  *PkswRxpfConcurrentTestState;

typedef struct KswRxpfConcurrentTestWorker
{
    KswRxpfConcurrentTestState* shared;
    PROCESSOR_NUMBER processor;
    KEVENT readyEvent;
    PETHREAD threadObject;
    ULONGLONG returnedValue;
    NTSTATUS status;
} KswRxpfConcurrentTestWorker,
  *PkswRxpfConcurrentTestWorker;

struct KswRxpfConcurrentTestState
{
    KEVENT startEvent;
    KEVENT doneEvent;
    PVOID pageAddress;
    ULONGLONG expectedValue;
    volatile LONG remainingWorkers;
    volatile LONG failedWorkers;
    ULONG workerCount;
    KswRxpfConcurrentTestWorker workers[ANYSIZE_ARRAY];
};

static VOID
kswRxpfConcurrentTestWorker(
    _In_ PVOID context
    )
{
    PkswRxpfConcurrentTestWorker worker =
        (PkswRxpfConcurrentTestWorker)context;
    PkswRxpfConcurrentTestState shared = worker->shared;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    BOOLEAN affinitySet = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG returnedValue = 0ULL;

    worker->threadObject = PsGetCurrentThread();
    ObReferenceObject(worker->threadObject);
    KeMemoryBarrier();
    KeSetEvent(&worker->readyEvent, IO_NO_INCREMENT, FALSE);

    /* The creator now owns a thread-object reference for final termination. */
    (void)KeWaitForSingleObject(
        &shared->startEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
    if (worker->processor.Number >= sizeof(KAFFINITY) * 8UL) {
        status = STATUS_NOT_SUPPORTED;
    } else {
        targetAffinity.Group = worker->processor.Group;
        targetAffinity.Mask =
            ((KAFFINITY)1) << worker->processor.Number;
        KeSetSystemGroupAffinityThread(
            &targetAffinity,
            &previousAffinity);
        affinitySet = TRUE;
        __try {
            returnedValue = KswRxpfInvokeTestPage(shared->pageAddress);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    worker->returnedValue = returnedValue;
    if (NT_SUCCESS(status) && returnedValue != shared->expectedValue) {
        status = STATUS_DATA_ERROR;
    }
    worker->status = status;
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&shared->failedWorkers);
    }
    KeMemoryBarrier();
    if (InterlockedDecrement(&shared->remainingWorkers) == 0) {
        KeSetEvent(&shared->doneEvent, IO_NO_INCREMENT, FALSE);
    }
    PsTerminateSystemThread(status);
}

NTSTATUS
kswRxpfRunConcurrentExecutionTest(
    _In_ PVOID pageAddress,
    _In_ ULONGLONG expectedValue,
    _Out_ ULONGLONG* returnedValueOut,
    _Out_ ULONG* workerCountOut
    )
{
    PkswRxpfConcurrentTestState state = NULL;
    ULONG activeCount = 0UL;
    ULONG createdCount = 0UL;
    ULONG index = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    if (pageAddress == NULL || returnedValueOut == NULL ||
        workerCountOut == NULL || expectedValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *returnedValueOut = 0ULL;
    *workerCountOut = 0UL;
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL || activeCount >
        (MAXULONG_PTR - FIELD_OFFSET(
            KswRxpfConcurrentTestState,
            workers)) / sizeof(KswRxpfConcurrentTestWorker)) {
        return STATUS_NOT_SUPPORTED;
    }
    allocationBytes = FIELD_OFFSET(
        KswRxpfConcurrentTestState,
        workers) + (SIZE_T)activeCount *
            sizeof(KswRxpfConcurrentTestWorker);
    state = (PkswRxpfConcurrentTestState)
        kswordArkAllocateNonPagedPool(
            allocationBytes,
            KSW_RXPF_SELF_TEST_TAG);
    if (state == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(state, allocationBytes);
    KeInitializeEvent(&state->startEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&state->doneEvent, NotificationEvent, FALSE);
    state->pageAddress = pageAddress;
    state->expectedValue = expectedValue;

    /* Create every waiter before releasing the shared start event. */
    for (index = 0UL; index < activeCount; ++index) {
        PkswRxpfConcurrentTestWorker worker =
            &state->workers[index];
        HANDLE threadHandle = NULL;

        worker->shared = state;
        KeInitializeEvent(&worker->readyEvent, NotificationEvent, FALSE);
        worker->threadObject = NULL;
        status = KeGetProcessorNumberFromIndex(
            index,
            &worker->processor);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            kswRxpfConcurrentTestWorker,
            worker);
        if (!NT_SUCCESS(status)) {
            threadHandle = NULL;
            break;
        }
        (void)KeWaitForSingleObject(
            &worker->readyEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ZwClose(threadHandle);
        threadHandle = NULL;
        createdCount += 1UL;
    }
    if (createdCount == 0UL) {
        ExFreePoolWithTag(state, KSW_RXPF_SELF_TEST_TAG);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    state->workerCount = createdCount;
    InterlockedExchange(
        &state->remainingWorkers,
        (LONG)createdCount);
    KeMemoryBarrier();
    KeSetEvent(&state->startEvent, IO_NO_INCREMENT, FALSE);
    (void)KeWaitForSingleObject(
        &state->doneEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);

    /* Wait for thread objects, not just the pre-termination completion event. */
    for (index = 0UL; index < createdCount; ++index) {
        if (state->workers[index].threadObject != NULL) {
            (void)KeWaitForSingleObject(
                state->workers[index].threadObject,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            ObDereferenceObject(state->workers[index].threadObject);
            state->workers[index].threadObject = NULL;
        }
    }
    *returnedValueOut = state->workers[0].returnedValue;
    *workerCountOut = createdCount;
    if (createdCount != activeCount && NT_SUCCESS(status)) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    if (NT_SUCCESS(status) &&
        InterlockedCompareExchange(
            &state->failedWorkers,
            0,
            0) != 0) {
        status = STATUS_DATA_ERROR;
    }
    ExFreePoolWithTag(state, KSW_RXPF_SELF_TEST_TAG);
    return status;
}
