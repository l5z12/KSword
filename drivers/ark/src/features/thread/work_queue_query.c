/*++

Module Name:

    work_queue_query.c

Abstract:

    Read-only, identity-matched Ex work-queue enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_thread.h"
#include "driver/KswordArkWorkQueueIoctl.h"
#include "../dyndata/dyndata_v4_internal.h"
#include "work_queue_fallback.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntimage.h>

#define KSW_WORK_QUEUE_MAX_PE_SECTIONS 96UL
#define KSW_WORK_QUEUE_MAX_EX_POOL_INDEX 8UL

typedef struct KswWorkQueueBuilder
{
    KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE* response;
    ULONG capacity;
    ULONG maxEntries;
    BOOLEAN stop;
    KswDynV4WorkQueueLayout layout;
    KswHookSystemModuleInformation* modules;
} KswWorkQueueBuilder;

static BOOLEAN
kswordArkWorkQueueIsKernelAddress(
    _In_ ULONG64 address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFULL;
#else
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkWorkQueueAddAddress(
    _In_ ULONG64 base,
    _In_ ULONG64 offset,
    _Out_ ULONG64* addressOut
    )
{
    if (addressOut == NULL || base > MAXULONGLONG - offset) {
        return FALSE;
    }
    *addressOut = base + offset;
    return kswordArkWorkQueueIsKernelAddress(*addressOut);
}

static BOOLEAN
kswordArkWorkQueueRead(
    _In_ ULONG64 address,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
{
    if (destination == NULL || bytesToRead == 0U ||
        !kswordArkWorkQueueIsKernelAddress(address) ||
        address > MAXULONGLONG - (ULONG64)(bytesToRead - 1U) ||
        !kswordArkWorkQueueIsKernelAddress(address + (ULONG64)(bytesToRead - 1U))) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)address,
        destination,
        bytesToRead);
}

static BOOLEAN
kswordArkWorkQueueReadField(
    _In_ ULONG64 base,
    _In_ ULONG offset,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
{
    ULONG64 address = 0ULL;

    return kswordArkWorkQueueAddAddress(base, offset, &address) &&
        kswordArkWorkQueueRead(address, destination, bytesToRead);
}

static BOOLEAN
kswordArkWorkQueueListHeadIsPlausible(
    _In_ ULONG64 listHeadAddress,
    _In_ const LIST_ENTRY* head
    )
{
    ULONG64 forward = 0ULL;
    ULONG64 backward = 0ULL;

    if (head == NULL || !kswordArkWorkQueueIsKernelAddress(listHeadAddress)) {
        return FALSE;
    }
    forward = (ULONG64)(ULONG_PTR)head->Flink;
    backward = (ULONG64)(ULONG_PTR)head->Blink;

    // An empty list is valid only when both links point back to the head.
    if (forward == listHeadAddress || backward == listHeadAddress) {
        return forward == listHeadAddress && backward == listHeadAddress;
    }
    return kswordArkWorkQueueIsKernelAddress(forward) &&
        kswordArkWorkQueueIsKernelAddress(backward);
}

static BOOLEAN
kswordArkWorkQueueFieldFits(
    _In_ ULONG offset,
    _In_ ULONG fieldBytes,
    _In_ ULONG typeSize
    )
{
    return fieldBytes != 0UL &&
        typeSize >= fieldBytes &&
        offset <= typeSize - fieldBytes;
}

static BOOLEAN
kswordArkWorkQueueLayoutValid(
    _In_ const KswDynV4WorkQueueLayout* layout,
    _In_ ULONG requestFlags
    )
{
    const ULONG kListArrayBytes =
        KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY);
    const BOOLEAN kRuntimeLayout = layout != NULL &&
        (layout->runtimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL;

    if (kRuntimeLayout) {
        const BOOLEAN kItemsRequested =
            (requestFlags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORK_ITEMS) != 0UL;
        const BOOLEAN kThreadsRequested =
            (requestFlags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL;
        const BOOLEAN kItemsAvailable =
            (layout->runtimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS) != 0UL;
        const BOOLEAN kThreadsAvailable =
            (layout->runtimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) != 0UL;

        if (!kswordArkWorkQueueIsKernelAddress(layout->moduleBase) ||
            layout->moduleSize < sizeof(PVOID) ||
            layout->pspSystemPartitionRva == 0UL ||
            layout->pspSystemPartitionRva > layout->moduleSize - sizeof(PVOID) ||
            layout->exPoolUntrusted >= KSW_WORK_QUEUE_MAX_EX_POOL_INDEX ||
            !kItemsAvailable ||
            (kThreadsRequested && !kThreadsAvailable && !kItemsRequested) ||
            layout->runtimePriorityIndexes[0] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            layout->runtimePriorityIndexes[1] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            layout->runtimePriorityIndexes[2] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            layout->runtimePriorityIndexes[0] == layout->runtimePriorityIndexes[1] ||
            layout->runtimePriorityIndexes[0] == layout->runtimePriorityIndexes[2] ||
            layout->runtimePriorityIndexes[1] == layout->runtimePriorityIndexes[2] ||
            !kswordArkWorkQueueFieldFits(
                layout->epartitionExPartition,
                sizeof(PVOID),
                layout->epartitionTypeSize) ||
            !kswordArkWorkQueueFieldFits(
                layout->exPartitionWorkQueues,
                sizeof(PVOID),
                layout->exPartitionTypeSize) ||
            !kswordArkWorkQueueFieldFits(
                layout->kpriQueueEntryListHead,
                kListArrayBytes,
                layout->kpriQueueTypeSize) ||
            (layout->exWorkQueueQueueIndex != 0UL &&
             !kswordArkWorkQueueFieldFits(
                 layout->exWorkQueueQueueIndex,
                 sizeof(ULONG),
                 layout->exWorkQueueTypeSize)) ||
            !kswordArkWorkQueueFieldFits(
                layout->workItemList,
                sizeof(LIST_ENTRY),
                layout->workItemTypeSize) ||
            !kswordArkWorkQueueFieldFits(
                layout->workItemRoutine,
                sizeof(PVOID),
                layout->workItemTypeSize) ||
            !kswordArkWorkQueueFieldFits(
                layout->workItemParameter,
                sizeof(PVOID),
                layout->workItemTypeSize)) {
            return FALSE;
        }
        if (kThreadsRequested && kThreadsAvailable) {
            return kswordArkWorkQueueFieldFits(
                    layout->kthreadQueue,
                    sizeof(PVOID),
                    layout->kthreadTypeSize) &&
                kswordArkWorkQueueFieldFits(
                    layout->ethreadStartAddress,
                    sizeof(PVOID),
                    layout->ethreadTypeSize);
        }
        return TRUE;
    }

    if (layout == NULL ||
        !kswordArkWorkQueueIsKernelAddress(layout->moduleBase) ||
        layout->moduleSize < sizeof(PVOID) ||
        layout->pspSystemPartitionRva == 0UL ||
        layout->expBuiltinPrioritiesRva == 0UL ||
        layout->pspSystemPartitionRva > layout->moduleSize - sizeof(PVOID) ||
        layout->moduleSize < 3UL * sizeof(ULONG) ||
        layout->expBuiltinPrioritiesRva >
            layout->moduleSize - (3UL * sizeof(ULONG)) ||
        layout->exPoolUntrusted >= KSW_WORK_QUEUE_MAX_EX_POOL_INDEX ||
        layout->epartitionTypeSize == 0UL ||
        layout->exPartitionTypeSize == 0UL ||
        layout->exWorkQueueTypeSize == 0UL ||
        layout->kpriQueueTypeSize == 0UL ||
        layout->kthreadTypeSize == 0UL ||
        layout->ethreadTypeSize == 0UL ||
        layout->workItemTypeSize == 0UL) {
        return FALSE;
    }

    return
        kswordArkWorkQueueFieldFits(
            layout->epartitionExPartition,
            sizeof(PVOID),
            layout->epartitionTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->exPartitionWorkQueues,
            sizeof(PVOID),
            layout->exPartitionTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->exWorkQueueWorkPriQueue,
            layout->kpriQueueTypeSize,
            layout->exWorkQueueTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->exWorkQueueQueueIndex,
            sizeof(ULONG),
            layout->exWorkQueueTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->kpriQueueEntryListHead,
            kListArrayBytes,
            layout->kpriQueueTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->kpriQueueThreadListHead,
            sizeof(LIST_ENTRY),
            layout->kpriQueueTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->kthreadQueue,
            sizeof(PVOID),
            layout->kthreadTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->kthreadQueueListEntry,
            sizeof(LIST_ENTRY),
            layout->kthreadTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->ethreadTcb,
            layout->kthreadTypeSize,
            layout->ethreadTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->ethreadStartAddress,
            sizeof(PVOID),
            layout->ethreadTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->workItemList,
            sizeof(LIST_ENTRY),
            layout->workItemTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->workItemRoutine,
            sizeof(PVOID),
            layout->workItemTypeSize) &&
        kswordArkWorkQueueFieldFits(
            layout->workItemParameter,
            sizeof(PVOID),
            layout->workItemTypeSize);
}

static VOID
kswordArkWorkQueueCopyBoundedAnsi(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ SIZE_T destinationBytes,
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
{
    SIZE_T index = 0U;

    if (destination == NULL || destinationBytes == 0U) {
        return;
    }
    destination[0] = '\0';
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }
    while (index + 1U < destinationBytes &&
           index < (SIZE_T)sourceBytes &&
           source[index] != 0U) {
        destination[index] = (CHAR)source[index];
        ++index;
    }
    destination[index] = '\0';
}

static BOOLEAN
kswordArkWorkQueueRoutineInExecutableSection(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ ULONG64 routineAddress
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG64 routineRva64 = 0ULL;
    ULONG64 sectionTableRva64 = 0ULL;
    ULONG sectionIndex = 0UL;

    if (module == NULL || module->imageBase == NULL ||
        module->imageSize == 0UL ||
        routineAddress < (ULONG64)(ULONG_PTR)module->imageBase) {
        return FALSE;
    }
    routineRva64 = routineAddress - (ULONG64)(ULONG_PTR)module->imageBase;
    if (routineRva64 >= module->imageSize ||
        !kswordArkHookReadMemorySafe(module->imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !kswordArkHookReadImageNtHeaders(module, &ntHeaders) ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSW_WORK_QUEUE_MAX_PE_SECTIONS) {
        return FALSE;
    }

    sectionTableRva64 =
        (ULONG64)(ULONG)dosHeader.e_lfanew +
        (ULONG64)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        (ULONG64)ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionTableRva64 > MAXULONG) {
        return FALSE;
    }

    for (sectionIndex = 0UL;
         sectionIndex < (ULONG)ntHeaders.FileHeader.NumberOfSections;
         ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG64 sectionHeaderRva64 =
            sectionTableRva64 +
            ((ULONG64)sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG64 sectionStart = 0ULL;
        ULONG64 sectionSpan = 0ULL;
        ULONG64 sectionEnd = 0ULL;

        if (sectionHeaderRva64 > MAXULONG ||
            !kswordArkHookReadImageBytes(
                module,
                (ULONG)sectionHeaderRva64,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }
        sectionStart = sectionHeader.VirtualAddress;
        sectionSpan = sectionHeader.Misc.VirtualSize != 0UL
            ? sectionHeader.Misc.VirtualSize
            : sectionHeader.SizeOfRawData;
        if (sectionSpan == 0ULL ||
            sectionStart > MAXULONGLONG - sectionSpan) {
            continue;
        }
        sectionEnd = sectionStart + sectionSpan;
        if (routineRva64 >= sectionStart && routineRva64 < sectionEnd) {
            return (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        }
    }
    return FALSE;
}

static VOID
kswordArkWorkQueueFillModule(
    _In_ KswWorkQueueBuilder* builder,
    _In_ ULONG64 routineAddress,
    _Inout_ KSWORD_ARK_WORK_QUEUE_ENTRY* entry
    )
{
    const KswHookSystemModuleEntry* module = NULL;
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (builder == NULL || entry == NULL) {
        return;
    }
    if (routineAddress == 0ULL) {
        entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED;
        return;
    }
    entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT;
    module = kswordArkHookFindModuleForAddress(
        builder->modules,
        (ULONG_PTR)routineAddress);
    if (module == NULL) {
        entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED;
        return;
    }

    entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED;
    entry->moduleBase = (ULONG64)(ULONG_PTR)module->imageBase;
    entry->moduleSize = module->imageSize;
    kswordArkHookGetModuleFileName(module, &fileName, &fileNameBytes);
    kswordArkWorkQueueCopyBoundedAnsi(
        entry->moduleName,
        sizeof(entry->moduleName),
        fileName,
        fileNameBytes);
    kswordArkWorkQueueCopyBoundedAnsi(
        entry->modulePath,
        sizeof(entry->modulePath),
        module->fullPathName,
        sizeof(module->fullPathName));

    if (!kswordArkWorkQueueRoutineInExecutableSection(module, routineAddress)) {
        entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_NOT_EXECUTABLE;
        return;
    }
    entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION;
}

static VOID
kswordArkWorkQueueMarkPartial(
    _Inout_ KswWorkQueueBuilder* builder,
    _In_ ULONG statusFlag,
    _In_ NTSTATUS lastStatus
    )
{
    if (builder == NULL || builder->response == NULL) {
        return;
    }
    builder->response->statusFlags |=
        KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL | statusFlag;
    builder->response->lastStatus = lastStatus;
}

static VOID
kswordArkWorkQueueAppendEntry(
    _Inout_ KswWorkQueueBuilder* builder,
    _In_ const KSWORD_ARK_WORK_QUEUE_ENTRY* entry
    )
{
    KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE* response = NULL;

    if (builder == NULL || entry == NULL || builder->response == NULL ||
        builder->stop) {
        return;
    }
    response = builder->response;
    response->totalCount += 1UL;
    if (response->returnedCount < builder->capacity &&
        response->returnedCount < builder->maxEntries) {
        response->entries[response->returnedCount] = *entry;
        response->returnedCount += 1UL;
    }
    else {
        kswordArkWorkQueueMarkPartial(
            builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED,
            STATUS_BUFFER_OVERFLOW);
        builder->stop = TRUE;
        return;
    }

}

static VOID
kswordArkWorkQueueEnumerateItems(
    _Inout_ KswWorkQueueBuilder* builder,
    _In_ ULONG nodeIndex,
    _In_ ULONG queueType,
    _In_ ULONG priorityIndex,
    _In_ ULONG64 workQueueAddress,
    _In_ ULONG64 listHeadAddress
    )
{
    LIST_ENTRY headBefore;
    LIST_ENTRY headAfter;
    ULONG64 currentLink = 0ULL;
    ULONG64 previousLink = listHeadAddress;
    ULONG iteration = 0UL;

    if (builder == NULL || builder->stop) {
        return;
    }
    if (!kswordArkWorkQueueRead(listHeadAddress, &headBefore, sizeof(headBefore))) {
        builder->response->readFailureCount += 1UL;
        kswordArkWorkQueueMarkPartial(
            builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
            STATUS_PARTIAL_COPY);
        return;
    }
    if (!kswordArkWorkQueueListHeadIsPlausible(listHeadAddress, &headBefore)) {
        builder->response->corruptListCount += 1UL;
        kswordArkWorkQueueMarkPartial(
            builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
            STATUS_DATA_ERROR);
        return;
    }

    currentLink = (ULONG64)(ULONG_PTR)headBefore.Flink;
    while (currentLink != listHeadAddress && !builder->stop) {
        LIST_ENTRY currentLinks;
        ULONG64 workItemAddress = 0ULL;
        ULONG64 routineAddress = 0ULL;
        ULONG64 parameterAddress = 0ULL;
        KSWORD_ARK_WORK_QUEUE_ENTRY entry;

        if (iteration >= builder->maxEntries) {
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED,
                STATUS_BUFFER_OVERFLOW);
            builder->stop = TRUE;
            break;
        }
        ++iteration;
        if (!kswordArkWorkQueueIsKernelAddress(currentLink) ||
            currentLink < builder->layout.workItemList ||
            !kswordArkWorkQueueRead(currentLink, &currentLinks, sizeof(currentLinks)) ||
            (ULONG64)(ULONG_PTR)currentLinks.Blink != previousLink) {
            builder->response->corruptListCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
                STATUS_DATA_ERROR);
            break;
        }
        workItemAddress = currentLink - builder->layout.workItemList;
        if (!kswordArkWorkQueueReadField(
                workItemAddress,
                builder->layout.workItemRoutine,
                &routineAddress,
                sizeof(routineAddress)) ||
            !kswordArkWorkQueueReadField(
                workItemAddress,
                builder->layout.workItemParameter,
                &parameterAddress,
                sizeof(parameterAddress))) {
            builder->response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            previousLink = currentLink;
            currentLink = (ULONG64)(ULONG_PTR)currentLinks.Flink;
            continue;
        }

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.rowKind = KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM;
        entry.queueType = queueType;
        entry.priorityIndex = priorityIndex;
        entry.nodeIndex = nodeIndex;
        entry.flags = KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED;
        entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK;
        entry.queueAddress = workQueueAddress;
        entry.workItemAddress = workItemAddress;
        entry.routineAddress = routineAddress;
        entry.parameterAddress = parameterAddress;
        if (parameterAddress != 0ULL) {
            entry.flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT;
        }
        kswordArkWorkQueueFillModule(builder, routineAddress, &entry);
        if (entry.status != KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK) {
            kswordArkWorkQueueMarkPartial(
                builder,
                0UL,
                STATUS_INVALID_IMAGE_FORMAT);
        }
        kswordArkWorkQueueAppendEntry(builder, &entry);

        previousLink = currentLink;
        currentLink = (ULONG64)(ULONG_PTR)currentLinks.Flink;
    }

    if (!builder->stop) {
        if (!kswordArkWorkQueueRead(listHeadAddress, &headAfter, sizeof(headAfter))) {
            builder->response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (previousLink != (ULONG64)(ULONG_PTR)headBefore.Blink ||
                 !kswordArkWorkQueueListHeadIsPlausible(listHeadAddress, &headAfter) ||
                 headAfter.Flink != headBefore.Flink ||
                 headAfter.Blink != headBefore.Blink) {
            builder->response->corruptListCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
                STATUS_RETRY);
        }
    }
}

static VOID
kswordArkWorkQueueEnumerateThreads(
    _Inout_ KswWorkQueueBuilder* builder,
    _In_ ULONG nodeIndex,
    _In_ ULONG64 workQueueAddress,
    _In_ ULONG64 priQueueAddress,
    _In_opt_ const KswWorkQueueSystemThreadSnapshot* systemThreads
    )
{
    KswWorkQueueThreadWalker walker;
    PETHREAD threadCursor = NULL;

    if (builder == NULL || builder->stop) {
        return;
    }

    /*
     * ThreadListHead is a private, lockless queue list and cannot establish
     * that an arbitrary list-derived address is an object. Walk the System
     * process with the shared thread cursor instead; whether it comes from the
     * public walker or from the TID snapshot plus PsLookupThreadByThreadId,
     * every cursor is an Object Manager referenced ETHREAD. DynData is used
     * only to read the referenced ETHREAD's embedded KTHREAD.Queue and
     * reverse-match it to the target KPRIQUEUE.
     */
    RtlZeroMemory(&walker, sizeof(walker));
    kswordArkWorkQueueInitializeThreadWalker(&walker, systemThreads);
    if (!kswordArkWorkQueueThreadWalkerUsable(&walker)) {
        return;
    }

    threadCursor = kswordArkWorkQueueThreadWalkerNext(&walker);
    while (threadCursor != NULL && !builder->stop) {
        ULONG64 ethreadAddress = 0ULL;
        ULONG64 kthreadAddress = 0ULL;
        ULONG64 queuePointer = 0ULL;
        ULONG64 verifiedQueuePointer = 0ULL;
        ULONG64 startAddress = 0ULL;
        ULONG threadProcessId = 0UL;
        KSWORD_ARK_WORK_QUEUE_ENTRY entry;

        ethreadAddress = (ULONG64)(ULONG_PTR)threadCursor;
        if (!kswordArkWorkQueueAddAddress(
                ethreadAddress,
                builder->layout.ethreadTcb,
                &kthreadAddress) ||
            !kswordArkWorkQueueReadField(
                kthreadAddress,
                builder->layout.kthreadQueue,
                &queuePointer,
                sizeof(queuePointer))) {
            builder->response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            goto AdvanceThread;
        }
        if (queuePointer != priQueueAddress) {
            goto AdvanceThread;
        }

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.rowKind = KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD;
        entry.queueType = KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER;
        entry.priorityIndex = MAXULONG;
        entry.nodeIndex = nodeIndex;
        entry.flags =
            KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED |
            KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_REFERENCED;
        entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK;
        entry.queueAddress = workQueueAddress;
        entry.threadObject = ethreadAddress;

        __try {
            entry.threadId = HandleToULong(PsGetThreadId(threadCursor));
            threadProcessId = HandleToULong(PsGetThreadProcessId(threadCursor));
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
            entry.threadCreateTime100ns =
                (ULONG64)PsGetThreadCreateTime(threadCursor);
#endif
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            threadProcessId = 0UL;
        }
        if (entry.threadId == 0UL ||
            entry.threadCreateTime100ns == 0ULL ||
            threadProcessId != 4UL) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            builder->response->referenceFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_OBJECT_NAME_NOT_FOUND);
        }
        else if (!kswordArkWorkQueueReadField(
                ethreadAddress,
                builder->layout.ethreadStartAddress,
                &startAddress,
                sizeof(startAddress))) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED;
            builder->response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (startAddress == 0ULL) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            builder->response->referenceFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_OBJECT_NAME_NOT_FOUND);
        }
        else if (!kswordArkWorkQueueReadField(
                kthreadAddress,
                builder->layout.kthreadQueue,
                &verifiedQueuePointer,
                sizeof(verifiedQueuePointer))) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED;
            builder->response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (verifiedQueuePointer != priQueueAddress) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            builder->response->referenceFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_RETRY);
        }
        else {
            entry.flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID;
            entry.routineAddress = startAddress;
            kswordArkWorkQueueFillModule(builder, startAddress, &entry);
            if (entry.status != KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK) {
                kswordArkWorkQueueMarkPartial(
                    builder,
                    0UL,
                    STATUS_INVALID_IMAGE_FORMAT);
            }
        }

        kswordArkWorkQueueAppendEntry(builder, &entry);

AdvanceThread:
        if (builder->stop) {
            break;
        }
        threadCursor = kswordArkWorkQueueThreadWalkerNext(&walker);
    }
    kswordArkWorkQueueThreadWalkerClose(&walker);
}

static NTSTATUS
kswordArkDriverEnumerateWorkQueues(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ SIZE_T outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST* request,
    _Out_ SIZE_T* bytesWrittenOut
    )
{
    KswWorkQueueBuilder builder;
    ULONG moduleBytes = 0UL;
    ULONG priorityIndexes[3] = { 0UL, 0UL, 0UL };
    ULONG queueTypes[3] = {
        KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL,
        KSWORD_ARK_WORK_QUEUE_TYPE_DELAYED,
        KSWORD_ARK_WORK_QUEUE_TYPE_HYPERCRITICAL
    };
    KswWorkQueueSystemThreadSnapshot systemThreads;
    BOOLEAN workerThreadsUsable = FALSE;
    ULONG64 pspSystemPartitionAddress = 0ULL;
    ULONG64 prioritiesAddress = 0ULL;
    ULONG64 epartitionAddress = 0ULL;
    ULONG64 exPartitionAddress = 0ULL;
    ULONG64 workQueuesAddress = 0ULL;
    ULONG nodeCount = 0UL;
    ULONG nodeIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL ||
        outputBufferLength < KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    builder.response = (KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE*)outputBuffer;
    builder.capacity = (ULONG)(
        (outputBufferLength - KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
    builder.maxEntries = request->maxEntries;

    builder.response->size = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
    builder.response->version = KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION;
    builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK;
    builder.response->entrySize = sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY);

#if !defined(_M_AMD64) && !defined(_M_X64)
    builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
    builder.Response->lastStatus = STATUS_NOT_SUPPORTED;
    *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
    return STATUS_SUCCESS;
#else
    status = kswordArkDynDataV4SnapshotWorkQueueLayout(&builder.layout);
    if (!NT_SUCCESS(status)) {
        status = kswordArkWorkQueueResolveRuntimeLayout(&builder.layout);
        if (!NT_SUCCESS(status)) {
            builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
            builder.response->lastStatus = status;
            *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
            return STATUS_SUCCESS;
        }
    }
    builder.response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED;
    if (!kswordArkWorkQueueLayoutValid(&builder.layout, request->flags)) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT;
        builder.response->lastStatus = STATUS_DATA_ERROR;
        *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    builder.response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED;

    if ((request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL) {
        if ((builder.layout.runtimeFlags &
             KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL &&
            (builder.layout.runtimeFlags &
             KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) == 0UL) {
            // Runtime layout failed to describe thread fields; work items remain enumerable, but thread rows are explicitly downgraded.
            builder.response->referenceFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                &builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_NOT_SUPPORTED);
        }
        else {
            KswWorkQueueThreadWalker probeWalker;

            /*
             * ntoskrnl does not export psGetNextProcessThread, so thread sources rely primarily on System
             * process TID snapshots: each TID retrieves the referenced ETHREAD via
             * PsLookupThreadByThreadId, with identity strength consistent with public traversal routines.
             */
            (VOID)kswordArkWorkQueueCaptureSystemThreads(&systemThreads);
            RtlZeroMemory(&probeWalker, sizeof(probeWalker));
            kswordArkWorkQueueInitializeThreadWalker(&probeWalker, &systemThreads);
            workerThreadsUsable =
                kswordArkWorkQueueThreadWalkerUsable(&probeWalker);
            kswordArkWorkQueueThreadWalkerClose(&probeWalker);
            if (!workerThreadsUsable) {
                builder.response->referenceFailureCount += 1UL;
                kswordArkWorkQueueMarkPartial(
                    &builder,
                    KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                    STATUS_PROCEDURE_NOT_FOUND);
            }
        }
    }

    status = kswordArkHookBuildModuleSnapshot(&builder.modules, &moduleBytes);
    if (!NT_SUCCESS(status)) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    if ((builder.layout.runtimeFlags &
         KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL) {
        RtlCopyMemory(
            priorityIndexes,
            builder.layout.runtimePriorityIndexes,
            sizeof(priorityIndexes));
    }
    else if (!kswordArkWorkQueueAddAddress(
                 builder.layout.moduleBase,
                 builder.layout.expBuiltinPrioritiesRva,
                 &prioritiesAddress) ||
             !kswordArkWorkQueueRead(
                 prioritiesAddress,
                 priorityIndexes,
                 sizeof(priorityIndexes))) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE;
        builder.response->readFailureCount += 1UL;
        builder.response->lastStatus = STATUS_DATA_ERROR;
        *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.modules, KSW_HOOK_SCAN_TAG);
        builder.modules = NULL;
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    if (!kswordArkWorkQueueAddAddress(
            builder.layout.moduleBase,
            builder.layout.pspSystemPartitionRva,
            &pspSystemPartitionAddress) ||
        !kswordArkWorkQueueRead(
            pspSystemPartitionAddress,
            &epartitionAddress,
            sizeof(epartitionAddress)) ||
        !kswordArkWorkQueueIsKernelAddress(epartitionAddress) ||
        !kswordArkWorkQueueReadField(
            epartitionAddress,
            builder.layout.epartitionExPartition,
            &exPartitionAddress,
            sizeof(exPartitionAddress)) ||
        !kswordArkWorkQueueIsKernelAddress(exPartitionAddress) ||
        !kswordArkWorkQueueReadField(
            exPartitionAddress,
            builder.layout.exPartitionWorkQueues,
            &workQueuesAddress,
            sizeof(workQueuesAddress)) ||
        !kswordArkWorkQueueIsKernelAddress(workQueuesAddress) ||
        priorityIndexes[0] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[1] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[2] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[0] == priorityIndexes[1] ||
        priorityIndexes[0] == priorityIndexes[2] ||
        priorityIndexes[1] == priorityIndexes[2]) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE;
        builder.response->readFailureCount += 1UL;
        builder.response->lastStatus = STATUS_DATA_ERROR;
        *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.modules, KSW_HOOK_SCAN_TAG);
        builder.modules = NULL;
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    nodeCount = (ULONG)KeQueryHighestNodeNumber() + 1UL;
    if (nodeCount == 0UL || nodeCount > KSWORD_ARK_WORK_QUEUE_MAX_NODES) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT;
        builder.response->lastStatus = STATUS_DATA_ERROR;
        *bytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.modules, KSW_HOOK_SCAN_TAG);
        builder.modules = NULL;
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }
    builder.response->nodeCount = nodeCount;

    for (nodeIndex = 0UL; nodeIndex < nodeCount && !builder.stop; ++nodeIndex) {
        ULONG64 nodeQueuePointerAddress = 0ULL;
        ULONG64 nodeQueueArrayAddress = 0ULL;
        ULONG64 workQueuePointerAddress = 0ULL;
        ULONG64 workQueueAddress = 0ULL;
        ULONG64 priQueueAddress = 0ULL;
        ULONG liveQueueIndex = MAXULONG;
        ULONG queueTypeIndex = 0UL;

        if (!kswordArkWorkQueueAddAddress(
                workQueuesAddress,
                (ULONG64)nodeIndex * sizeof(PVOID),
                &nodeQueuePointerAddress) ||
            !kswordArkWorkQueueRead(
                nodeQueuePointerAddress,
                &nodeQueueArrayAddress,
                sizeof(nodeQueueArrayAddress)) ||
            !kswordArkWorkQueueIsKernelAddress(nodeQueueArrayAddress) ||
            !kswordArkWorkQueueAddAddress(
                nodeQueueArrayAddress,
                (ULONG64)builder.layout.exPoolUntrusted * sizeof(PVOID),
                &workQueuePointerAddress) ||
            !kswordArkWorkQueueRead(
                workQueuePointerAddress,
                &workQueueAddress,
                sizeof(workQueueAddress)) ||
            !kswordArkWorkQueueIsKernelAddress(workQueueAddress) ||
            /*
             * The queue's self-reported sequence number is the only evidence that can verify 'this is indeed the correct slot' on live memory.
             * Previously, RuntimeFlags were used for judgment, which excluded the most critical fallback signature path from
             * validation; now, if the upstream provides the offset, validation is enforced, while PDB path behavior remains unchanged.
             */
            ((builder.layout.exWorkQueueQueueIndex != 0UL) &&
             (!kswordArkWorkQueueReadField(
                 workQueueAddress,
                 builder.layout.exWorkQueueQueueIndex,
                 &liveQueueIndex,
                 sizeof(liveQueueIndex)) ||
              liveQueueIndex != builder.layout.exPoolUntrusted)) ||
            !kswordArkWorkQueueAddAddress(
                workQueueAddress,
                builder.layout.exWorkQueueWorkPriQueue,
                &priQueueAddress)) {
            builder.response->readFailureCount += 1UL;
            kswordArkWorkQueueMarkPartial(
                &builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            continue;
        }

        builder.response->queuesVisited += 1UL;
        if ((request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORK_ITEMS) != 0UL) {
            for (queueTypeIndex = 0UL;
                 queueTypeIndex < RTL_NUMBER_OF(priorityIndexes) && !builder.stop;
                 ++queueTypeIndex) {
                ULONG64 listHeadOffset =
                    (ULONG64)builder.layout.kpriQueueEntryListHead +
                    ((ULONG64)priorityIndexes[queueTypeIndex] * sizeof(LIST_ENTRY));
                ULONG64 listHeadAddress = 0ULL;

                if (!kswordArkWorkQueueAddAddress(
                        priQueueAddress,
                        listHeadOffset,
                        &listHeadAddress)) {
                    builder.response->readFailureCount += 1UL;
                    kswordArkWorkQueueMarkPartial(
                        &builder,
                        KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                        STATUS_INTEGER_OVERFLOW);
                    continue;
                }
                kswordArkWorkQueueEnumerateItems(
                    &builder,
                    nodeIndex,
                    queueTypes[queueTypeIndex],
                    priorityIndexes[queueTypeIndex],
                    workQueueAddress,
                    listHeadAddress);
            }
        }

        if ((request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL &&
            !builder.stop &&
            workerThreadsUsable) {
            kswordArkWorkQueueEnumerateThreads(
                &builder,
                nodeIndex,
                workQueueAddress,
                priQueueAddress,
                &systemThreads);
        }
    }

    if ((builder.response->statusFlags &
         (KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL |
          KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED |
          KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST |
          KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE |
          KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE)) != 0UL) {
        builder.response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL;
    }
    else {
        builder.response->lastStatus = STATUS_SUCCESS;
    }

    *bytesWrittenOut =
        KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE +
        ((SIZE_T)builder.response->returnedCount *
         sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
    ExFreePoolWithTag(builder.modules, KSW_HOOK_SCAN_TAG);
    builder.modules = NULL;
    kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS
kswordArkWorkQueueIoctlEnum(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST requestCopy;
    const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    SIZE_T actualInputLength = 0U;
    SIZE_T actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (inputBufferLength != sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST) ||
        outputBufferLength < KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualInputLength != sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    requestPacket = (const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST*)inputBuffer;
    requestCopy = *requestPacket;
    if (requestCopy.size != sizeof(requestCopy) ||
        requestCopy.version != KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION ||
        requestCopy.flags == 0UL ||
        (requestCopy.flags & ~KSWORD_ARK_WORK_QUEUE_FLAG_VALID_MASK) != 0UL ||
        requestCopy.maxEntries == 0UL ||
        requestCopy.maxEntries > KSWORD_ARK_WORK_QUEUE_MAX_ENTRIES ||
        requestCopy.reserved0 != 0UL ||
        requestCopy.reserved1 != 0UL ||
        requestCopy.reserved2 != 0UL ||
        requestCopy.reserved3 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualOutputLength != outputBufferLength) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    return kswordArkDriverEnumerateWorkQueues(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
}
