/*++

Module Name:

    callback_extended_nmi.c

Abstract:

    Enumerates KeRegisterNmiCallback registrations from the bounded private list.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_NMI_CODE_SCAN_BYTES 0x200UL
#define KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG 'mNbK'

#if defined(_M_AMD64)

// Windows AMD64 current NMI private node layout; verify the handle and next pointer after each read.
typedef struct KswordArkCallbackNmiRegistration
{
    ULONG64 next;
    ULONG64 callbackRoutine;
    ULONG64 callbackContext;
    ULONG64 handle;
} KswordArkCallbackNmiRegistration;

// Only NMI node scalars are stored within the lock; module parsing, string handling, and response construction are all deferred until after the lock is released.
typedef struct KswordArkCallbackNmiSnapshot
{
    ULONG traversalIndex;
    ULONG64 nodeAddress;
    ULONG64 callbackRoutine;
    ULONG64 callbackContext;
    ULONG64 handle;
    ULONG64 next;
} KswordArkCallbackNmiSnapshot;

static NTSTATUS
kswordArkCallbackExtendedLocateNmiList(
    _Out_ ULONG64* headStorageAddressOut,
    _Out_ ULONG64* lockAddressOut
    )
/*++

Routine Description:

    Locate the NMI private list head storage and its associated spinlock within the limited code window of
    KeRegisterNmiCallback. The location must show both a read and a write to the same list head, and verify kernel
    accessibility and alignment of both global addresses. Node layout is validated only after acquiring the lock.

Arguments:

    HeadStorageAddressOut - Receives the kernel global address where the pointer to the head node is saved.
    LockAddressOut: Receive the address of the adjacent KSPIN_LOCK in the protected list.

Return Value:

    Returns STATUS_SUCCESS on success; returns the corresponding failure status if safe location cannot be determined.

--*/
{
    // Only copy the fixed prefix of the exported routine; prohibit unbounded scanning of executable memory.
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_NMI_CODE_SCAN_BYTES];
    // offset points to the candidate MOV/LEA instruction pair.
    ULONG offset = 0UL;
    // The exported routine address is obtained solely through the MmGetSystemRoutineAddress wrapper.
    ULONG64 routineAddress = 0ULL;

    // Both results are required to avoid returning partial location information.
    if (headStorageAddressOut == NULL ||
        lockAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // The failure path consistently keeps the output zero so callers do not misuse stale values.
    *headStorageAddressOut = 0ULL;
    *lockAddressOut = 0ULL;
    // Use public exports as version-adaptive scan anchors.
    routineAddress = (ULONG64)(ULONG_PTR)
        kswordArkCallbackExtendedGetSystemRoutine(L"KeRegisterNmiCallback");
    // If not exported, the current system does not support this enumeration path.
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Pre-zero the local copy to ensure short reads do not leave uninitialized bytes.
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    // The safe read wrapper is responsible for capturing invalid kernel address accesses.
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Search for adjacent RIP-relative MOV chain heads to read and LEA lock address combinations.
    for (offset = 0UL; offset + 14UL <= sizeof(codeBytes); ++offset) {
        // storeOffset is used to locate the subsequent write-back to the same chain head global variable.
        ULONG storeOffset = 0UL;
        // Each candidate is parsed independently; failures do not leak results from previous candidates.
        ULONG64 headStorageAddress = 0ULL;
        ULONG64 lockAddress = 0ULL;
        ULONG64 addressDistance = 0ULL;
        BOOLEAN foundHeadStore = FALSE;

        // Only accept the pattern where `mov reg,[rip+disp32]` is immediately followed by `lea reg,[rip+disp32]`.
        if (codeBytes[offset] != 0x48U ||
            codeBytes[offset + 1UL] != 0x8BU ||
            (codeBytes[offset + 2UL] & 0xC7U) != 0x05U ||
            codeBytes[offset + 7UL] != 0x48U ||
            codeBytes[offset + 8UL] != 0x8DU ||
            (codeBytes[offset + 9UL] & 0xC7U) != 0x05U) {
            continue;
        }
        // Separately resolve the absolute kernel addresses for the chain head storage and the lock.
        if (!kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &headStorageAddress) ||
            !kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset + 7UL,
                3UL,
                7UL,
                &lockAddress)) {
            continue;
        }

        // In the current implementation, the lock and chain head are adjacent; a large distance indicates a hit on an unrelated global variable.
        addressDistance = (headStorageAddress > lockAddress)
            ? (headStorageAddress - lockAddress)
            : (lockAddress - headStorageAddress);
        if (headStorageAddress == lockAddress || addressDistance > 0x40ULL) {
            continue;
        }
        // The head pointer slot and KSPIN_LOCK must be aligned to pointer width and currently accessible by the kernel.
        if ((headStorageAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL ||
            (lockAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL ||
            !MmIsAddressValid((PVOID)(ULONG_PTR)headStorageAddress) ||
            !MmIsAddressValid((PVOID)(ULONG_PTR)lockAddress)) {
            continue;
        }
        // Require a RIP-relative write back to the same chain head address within a limited subsequent window.
        for (storeOffset = offset + 14UL;
             storeOffset + 7UL <= sizeof(codeBytes) &&
                 storeOffset < offset + 48UL;
             ++storeOffset) {
            // Save the global target parsed from this write instruction.
            ULONG64 storeTarget = 0ULL;

            // Match only `mov [rip+disp32],reg`, ignoring immediate values or writes of different widths.
            if (codeBytes[storeOffset] != 0x48U ||
                codeBytes[storeOffset + 1UL] != 0x89U ||
                (codeBytes[storeOffset + 2UL] & 0xC7U) != 0x05U) {
                continue;
            }
            // The write target must be exactly consistent with the preceding read target.
            if (kswordArkCallbackExtendedResolveRipRelative(
                    routineAddress + storeOffset,
                    3UL,
                    7UL,
                    &storeTarget) &&
                storeTarget == headStorageAddress) {
                foundHeadStore = TRUE;
                break;
            }
        }
        // Reject candidates lacking paired write-back to reduce false identification risks under version drift.
        if (!foundHeadStore) {
            continue;
        }
        // Publish results in one go after all code forms and address checks pass.
        *headStorageAddressOut = headStorageAddress;
        *lockAddressOut = lockAddress;
        return STATUS_SUCCESS;
    }

    // No candidate satisfying the complete evidence chain within the limited window.
    return STATUS_NOT_FOUND;
}

static VOID
kswordArkCallbackExtendedWalkNmiList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 headStorageAddress,
    _In_ ULONG64 lockAddress
    )
/*++

Routine Description:

    Get the KSPIN_LOCK for the NMI private list; read the list head and copy a bounded scalar snapshot within the lock;
    Verify module ownership, format the text, and generate a unified callback enumeration row after releasing the lock.

Arguments:

    Builder: enumeration builder for the current IOCTL.
    ModuleCache - Module ownership cache used for this NMI enumeration.
    HeadStorageAddress: Global address storing the pointer to the first node.
    LockAddress: address of the KSPIN_LOCK protecting the private linked list.

Return Value:

    No return value.

--*/
{
    // index: Used for both the safety upper bound and the user-visible stable sequence number.
    ULONG index = 0UL;
    // snapshotCount: Records the number of stable nodes successfully copied within the lock.
    ULONG snapshotCount = 0UL;
    // snapshotIndex: Used to generate responses one by one outside the lock.
    ULONG snapshotIndex = 0UL;
    // currentAddress always points to the next node to be verified under lock protection.
    ULONG64 currentAddress = 0ULL;
    // failureAddress records the location of corruption or overflow for out-of-lock diagnostics.
    ULONG64 failureAddress = 0ULL;
    // snapshotStatus aggregates the head read, node validation, and safety limit status.
    NTSTATUS snapshotStatus = STATUS_SUCCESS;
    // oldIrql: Saves the caller's IRQL prior to acquiring the NMI private spinlock.
    KIRQL oldIrql = PASSIVE_LEVEL;
    // snapshots: Points to a non-paged scalar array allocated before locking.
    KswordArkCallbackNmiSnapshot* snapshots = NULL;

    // Parameter addresses must come from a strict locator and again satisfy non-zero and pointer alignment.
    if (builder == NULL ||
        moduleCache == NULL ||
        headStorageAddress == 0ULL ||
        lockAddress == 0ULL ||
        (lockAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL) {
        return;
    }

    // Allocate non-paged snapshots before acquiring the private spinlock; memory allocation and string processing are prohibited within the lock.
    snapshots = (KswordArkCallbackNmiSnapshot*)kswordArkAllocateNonPaged(
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT,
        KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG);
    // Output visible diagnostics on out-of-memory instead of silently dropping all NMI callbacks.
    if (snapshots == NULL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_INSUFFICIENT_RESOURCES,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            lockAddress,
            headStorageAddress,
            0UL,
            L"KeRegisterNmiCallback snapshot allocation failed",
            L"无法分配 NMI 注册链非分页快照，未进入私有自旋锁。");
        return;
    }
    // Zero out the fixed-capacity array to ensure uninitialized fields are not exposed after an exception read.
    RtlZeroMemory(
        snapshots,
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT);

    // Use the real KSPIN_LOCK resolved by the locator to prevent concurrent deregistration and node release.
    KeAcquireSpinLock(
        (PKSPIN_LOCK)(ULONG_PTR)lockAddress,
        &oldIrql);
    // The chain head must be read within the same lock protection window; do not reuse volatile values from the positioning phase.
    if (!kswordArkCallbackExtendedReadPointer(
            headStorageAddress,
            &currentAddress)) {
        snapshotStatus = STATUS_ACCESS_VIOLATION;
        failureAddress = headStorageAddress;
    }

    // Dual condition prevents both null-terminated chain and corrupted cycles from causing infinite traversal.
    while (NT_SUCCESS(snapshotStatus) &&
        currentAddress != 0ULL &&
        index < KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT) {
        // Copy each private node to the stack first, then compress it into a stable snapshot containing only scalars.
        KswordArkCallbackNmiRegistration registration;

        // Clear the node before reading; stack residue is not used in exception paths.
        RtlZeroMemory(&registration, sizeof(registration));
        // Validate read, callback address, self-handle, non-self-loop, and next pointer alignment within the lock.
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration)) ||
            registration.callbackRoutine == 0ULL ||
            registration.handle != currentAddress ||
            registration.next == currentAddress ||
            (registration.next != 0ULL &&
             (registration.next & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL)) {
            snapshotStatus = STATUS_DATA_ERROR;
            failureAddress = currentAddress;
            break;
        }

        // Preserve the original traversal index so the name outside the lock still corresponds to the linked list order.
        snapshots[snapshotCount].traversalIndex = index;
        // Save node address for diagnostics; do not dereference it again outside the lock.
        snapshots[snapshotCount].nodeAddress = currentAddress;
        // Save callback function scalar; verify owning kernel module outside the lock.
        snapshots[snapshotCount].callbackRoutine = registration.callbackRoutine;
        // Save the callback context scalar; used only as response metadata outside the lock.
        snapshots[snapshotCount].callbackContext = registration.callbackContext;
        // Save the public handle scalar; details outside the lock do not need to access the original node.
        snapshots[snapshotCount].handle = registration.handle;
        // Save the next node pointer; details outside the lock can display the link within the consistency window.
        snapshots[snapshotCount].next = registration.next;
        // Increment completed snapshot count; capacity and traversal limit must strictly match.
        ++snapshotCount;
        // Only use the already validated local next value to advance the traversal.
        currentAddress = registration.next;
        ++index;
    }

    // A non-null tail address indicates reaching the safety limit, not a normal chain end.
    if (NT_SUCCESS(snapshotStatus) && currentAddress != 0ULL) {
        snapshotStatus = STATUS_BUFFER_OVERFLOW;
        failureAddress = currentAddress;
    }
    // Release the private spinlock and restore the original IRQL immediately after all node copies are completed.
    KeReleaseSpinLock(
        (PKSPIN_LOCK)(ULONG_PTR)lockAddress,
        oldIrql);

    // Empty list is not an error; return a row indicating unregistered status outside the lock.
    if (snapshotCount == 0UL && NT_SUCCESS(snapshotStatus)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            lockAddress,
            headStorageAddress,
            0UL,
            L"KeRegisterNmiCallback list (empty)",
            L"NMI 注册链已在自旋锁保护下确认为空。");
    }

    // Verify module ownership one by one outside the lock and generate user-visible rows.
    for (snapshotIndex = 0UL;
         snapshotIndex < snapshotCount;
         ++snapshotIndex) {
        // snapshot points only to a non-paged local array and does not rely on private chain nodes for continued existence.
        const KswordArkCallbackNmiSnapshot* snapshot =
            &snapshots[snapshotIndex];
        // Write name and details into fixed-size protocol fields.
        WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

        // The module cache may perform complex queries, so it must be executed after releasing the NMI spin lock.
        if (!kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                snapshot->callbackRoutine)) {
            snapshotStatus = STATUS_DATA_ERROR;
            failureAddress = snapshot->nodeAddress;
            break;
        }
        // All output buffers are zeroed before formatting.
        RtlZeroMemory(nameText, sizeof(nameText));
        RtlZeroMemory(detailText, sizeof(detailText));
        // Generate a stable, readable registration name from the sequence number recorded while holding the lock.
        (VOID)RtlStringCbPrintfW(
            nameText,
            sizeof(nameText),
            L"KeRegisterNmiCallback[%lu]",
            (unsigned long)snapshot->traversalIndex);
        // Details are constructed entirely from scalar snapshots and do not dereference nodes that may have been deregistered.
        (VOID)RtlStringCbPrintfW(
            detailText,
            sizeof(detailText),
            L"NMI callback；headStorage=0x%p，lock=0x%p，node=0x%p，handle=0x%p，next=0x%p。",
            (PVOID)(ULONG_PTR)headStorageAddress,
            (PVOID)(ULONG_PTR)lockAddress,
            (PVOID)(ULONG_PTR)snapshot->nodeAddress,
            (PVOID)(ULONG_PTR)snapshot->handle,
            (PVOID)(ULONG_PTR)snapshot->next);
        // The unified row builder completes module ownership, trust, and paging metadata.
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            snapshot->callbackRoutine,
            snapshot->callbackContext,
            snapshot->nodeAddress,
            0UL,
            nameText,
            detailText);
    }

    // Outputs a unified diagnostic message outside the lock for any failure in the chain head, node, module, or upper limit.
    if (!NT_SUCCESS(snapshotStatus)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            snapshotStatus,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            lockAddress,
            failureAddress,
            0UL,
            snapshotStatus == STATUS_BUFFER_OVERFLOW
                ? L"KeRegisterNmiCallback walk limit reached"
                : L"KeRegisterNmiCallback node validation failed",
            snapshotStatus == STATUS_BUFFER_OVERFLOW
                ? L"NMI 私有链超过安全遍历上限，已在释放自旋锁后停止输出。"
                : L"NMI 私有链未通过链头、布局、句柄、模块归属或 next 指针验证。");
    }

    // Free the non-paged snapshot array allocated before acquiring the lock.
    ExFreePoolWithTag(
        snapshots,
        KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG);
}

#endif

VOID
kswordArkCallbackExtendedAddNmiCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    NMI callback enumeration entry point. initialize the module cache, locate the current system's private registration
    chain, and perform bounded traversal; any unsupported or unverifiable case is converted into a visible diagnostic line.

Arguments:

    Builder: The enumeration builder used by the current IOCTL request.

Return Value:

    No return value.

--*/
{
    // Module cache allows each NMI callback address to be resolved to its owning image.
    KswordArkCallbackModuleCache moduleCache;
    // Non-AMD64 architecture explicitly reports unsupported by default.
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    // The result remains zero until successful.
    ULONG64 headStorageAddress = 0ULL;
    ULONG64 lockAddress = 0ULL;

    // The builder is a required output context.
    if (builder == NULL) {
        return;
    }

    // Cache lifetime is strictly limited to this class's callback enumeration period.
    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    // NMI private nodes must resolve callbacks to loaded kernel modules to prevent accepting forged code addresses.
    status = kswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"NMI callback module inventory unavailable",
            L"无法取得已加载内核模块清单，已停止 NMI 私有链枚举以避免接受未验证的函数地址。");
        kswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }
#if defined(_M_AMD64)
    // AMD64 uses the restricted code form of exported routines to locate the private chain.
    status = kswordArkCallbackExtendedLocateNmiList(
        &headStorageAddress,
        &lockAddress);
    // Allow reading and traversing nodes under the private spinlock only upon successful location.
    if (NT_SUCCESS(status)) {
        kswordArkCallbackExtendedWalkNmiList(
            builder,
            &moduleCache,
            headStorageAddress,
            lockAddress);
    }
    else
#else
    // Explicitly mark placeholder variables in non-AMD64 builds to maintain /W4 /WX warning-free status.
    UNREFERENCED_PARAMETER(headStorageAddress);
    UNREFERENCED_PARAMETER(lockAddress);
#endif
    {
        // A failed location must still be recorded as a diagnosable result, not silently suppressed.
        kswordArkCallbackExtendedAddRow(
            builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeRegisterNmiCallback list unavailable",
            L"无法从当前架构的 KeRegisterNmiCallback 导出代码安全定位 NMI 注册链。");
    }
    // Release the system module snapshot cache regardless of success or failure.
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
