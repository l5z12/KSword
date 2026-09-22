/*++

Module Name:

    injection_vad.c

Abstract:

    Read-only VAD tree enumeration for the injection-trace scan backend.

    This is the **second region view** for injection trace detection. It must directly read the EPROCESS.VadRoot
    balanced tree. It cannot call ZwQueryVirtualMemory, as that and R3's VirtualQueryEx share the same source;
    cross-checking them against each other is self-referential, and any consistency provides no evidence.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL only.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"
#include "ark/ark_dyndata.h"
#include "../../platform/kernel_object_probe.h"

/*
 * These routines are declared in ntifs.h, not ntddk.h; this driver does not include ntifs.h.
 * Consistent manual declaration with features/memory/memory_pagetable.c.
 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

// The layout of MmvadShort / MMVAD is kept consistent with features/section/section_support.c.
// We redeclare this here instead of sharing the header file because this module only requires the first half of the
// Core; pulling in the full section structure would introduce its additional assumptions about the ControlArea layout.
typedef struct KswInjMmvadShort
{
    union KswInjNodeUnion
    {
        struct KswInjNodeFields
        {
            struct KswInjMmvadShort* nextVad;
            PVOID extraCreateInfo;
        } nodeFields;
        RTL_BALANCED_NODE vadNode;
    } nodeUnion;
    ULONG startingVpn;
    ULONG endingVpn;
#ifdef _WIN64
    UCHAR startingVpnHigh;
    UCHAR endingVpnHigh;
    UCHAR commitChargeHigh;
    union KswInjHigherUnion
    {
        UCHAR spareNT64VadUChar;
        struct KswInjHigherFields
        {
            UCHAR endingVpnHigher : 4;
            UCHAR commitChargeHigher : 4;
        } higherFields;
    } higherUnion;
#endif
    LONG referenceCount;
    EX_PUSH_LOCK pushLock;
    ULONG longFlags;
    ULONG longFlags1;
#ifdef _WIN64
    union KswInjU5
    {
        ULONG_PTR eventListULongPtr;
        UCHAR startingVpnHigher : 4;
    } u5;
#else
    PVOID EventList;
#endif
} KswInjMmvadShort, *PkswInjMmvadShort;

typedef struct KswInjMmvad
{
    KswInjMmvadShort core;
    ULONG longFlags2;
    PVOID subsection;
    PVOID firstPrototypePte;
    PVOID lastContiguousPte;
    LIST_ENTRY viewLinks;
    PVOID processUnion;
} KswInjMmvad, *PkswInjMmvad;

/*
 * Bit positions for MMVAD_FLAGS (Win10/11 x64). DynData only validates the offset of VadRoot.
 * **No** verification of bit positions is performed, so all decoded values are marked with `FLAGS_LAYOUT_ASSUMED`;
 * upper layers must not use them for contradictory judgments. The original `LongFlags` are always returned as-is.
 */
#define KSW_INJ_VAD_FLAGS_VADTYPE_SHIFT       4U
#define KSW_INJ_VAD_FLAGS_VADTYPE_MASK        0x7U
#define KSW_INJ_VAD_FLAGS_PROTECTION_SHIFT    7U
#define KSW_INJ_VAD_FLAGS_PROTECTION_MASK     0x1FU
#define KSW_INJ_VAD_FLAGS_PRIVATE_MEMORY_BIT  (1UL << 20)

// Upper bound of the user address space. Under LA57 and 4-level paging, these values
// differ, so use the runtime MmHighestUserAddress instead of hard-coding a constant.
ULONG64
kswordArkInjectionUserAddressLimit(VOID)
{
    return (ULONG64)(ULONG_PTR)MmHighestUserAddress;
}

BOOLEAN
kswordArkInjectionReadKernel(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    )
/*++

Routine Description:

    Fault-tolerant kernel read at PASSIVE_LEVEL. Note: VAD node addresses come from kernel structures
    of the scanned process; any pointer may have been freed or overwritten. Therefore, always use the
    virtual address path of MmCopyMemory with exception handling; never dereference directly.

Return Value:

    TRUE indicates the full Size bytes were read.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (address == NULL || buffer == NULL || size == 0U) {
        return FALSE;
    }
    if (!kswordArkKernelProbeRangeIsResident(address, size)) {
        return FALSE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)address;

    __try {
        status = MmCopyMemory(buffer, copyAddress, size, MM_COPY_MEMORY_VIRTUAL, &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }
    return NT_SUCCESS(status) && copied == size;
}

static ULONG64
kswordArkInjectionVadStartVa(
    _In_ const KswInjMmvadShort* core
    )
{
#ifdef _WIN64
    ULONG_PTR higher = core->u5.startingVpnHigher;
    ULONG_PTR high = core->startingVpnHigh;
    ULONG_PTR low = core->startingVpn;
    return (ULONG64)((low | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (ULONG64)((ULONG_PTR)Core->StartingVpn << PAGE_SHIFT);
#endif
}

static ULONG64
kswordArkInjectionVadEndVaExclusive(
    _In_ const KswInjMmvadShort* core
    )
{
#ifdef _WIN64
    ULONG_PTR higher = core->higherUnion.higherFields.endingVpnHigher;
    ULONG_PTR high = core->endingVpnHigh;
    ULONG_PTR low = core->endingVpn;
    return (ULONG64)(((low + 1U) | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (ULONG64)(((ULONG_PTR)Core->EndingVpn + 1U) << PAGE_SHIFT);
#endif
}

static NTSTATUS
kswordArkInjectionReadVadRoot(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _Out_ PVOID* rootOut,
    _Out_ ULONG* rootOffsetOut
    )
/*++

Routine Description:

    Read EPROCESS.VadRoot. Note: VadRoot is an RTL_AVL_TREE where the first field is the
    root node pointer. The offset must come from DynData and be valid for the current build;
    if unavailable, fail immediately without attempting to use offsets from similar builds.

Return Value:

    STATUS_NOT_SUPPORTED indicates no available offset; when
    STATUS_SUCCESS, *RootOut may be NULL (an empty tree is a valid state).

--*/
{
    ULONG offset = 0U;
    PVOID root = NULL;

    if (rootOut == NULL || rootOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *rootOut = NULL;
    *rootOffsetOut = 0U;

    if (processObject == NULL || dynState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    offset = dynState->kernel.epVadRoot;
    if (offset == KSW_DYN_OFFSET_UNAVAILABLE || offset == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkInjectionReadKernel(
            (const UCHAR*)processObject + offset,
            &root,
            sizeof(root))) {
        return STATUS_ACCESS_VIOLATION;
    }
    *rootOut = root;
    *rootOffsetOut = offset;
    return STATUS_SUCCESS;
}

static VOID
kswordArkInjectionReadVadIntegrityInputs(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _Out_ PVOID* vadHintOut,
    _Out_ ULONG* vadCountOut,
    _Inout_ ULONG* fieldFlags
    )
/*++

Routine Description:

    Check the two items needed for read breakpoint chain verification: EPROCESS.VadHint and EPROCESS.VadCount.
    Note: Both are optional. The flag corresponding to the unavailable offset is not set, allowing the upper
    layer to distinguish between "not checked" and "checked and equals 0". Missing one does not affect the other.

--*/
{
    ULONG offset = 0U;

    *vadHintOut = NULL;
    *vadCountOut = 0U;

    if (processObject == NULL || dynState == NULL) {
        return;
    }

    offset = dynState->kernel.epVadHint;
    if (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0U) {
        PVOID hint = NULL;
        if (kswordArkInjectionReadKernel(
                (const UCHAR*)processObject + offset, &hint, sizeof(hint))) {
            *vadHintOut = hint;
            *fieldFlags |= KSWORD_ARK_INJECTION_FIELD_VAD_HINT_PRESENT;
        }
    }

    offset = dynState->kernel.epVadCount;
    if (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0U) {
        ULONG count = 0U;
        if (kswordArkInjectionReadKernel(
                (const UCHAR*)processObject + offset, &count, sizeof(count))) {
            *vadCountOut = count;
            *fieldFlags |= KSWORD_ARK_INJECTION_FIELD_VAD_COUNT_PRESENT;
        }
    }
}

typedef struct KswInjVadWalkState
{
    PVOID stack[KSWORD_ARK_INJECTION_VAD_MAX_DEPTH];
    ULONG depth;
    BOOLEAN depthOverflow;
    ULONG unreadableNodes;
    ULONG visitedNodes;
    // Accounting for unlink checks. ParentMismatch is only incremented when the parent node is readable; if the parent
    // cannot be read, it is recorded in UnreadableNodes instead of being falsely flagged as a structural inconsistency.
    ULONG parentMismatchNodes;
    BOOLEAN vadHintVisited;
    PVOID vadHint;
} KswInjVadWalkState;

/*
 * The low bits of RTL_BALANCED_NODE.ParentValue are balance bits (Red:1 / Balance:2); the parent pointer must
 * be masked first. Masking incorrectly causes a valid node to be calculated as 'parent pointer mismatch'.
 */
#define KSW_INJ_PARENT_VALUE_MASK (~(ULONG_PTR)0x3)

static VOID
kswordArkInjectionCheckParentLink(
    _Inout_ KswInjVadWalkState* state,
    _In_ PVOID node,
    _In_ const KswInjMmvadShort* core,
    _In_ PVOID root
    )
/*++

Routine Description:

    Verify that a node's parent pointer correctly points back to its parent. Common practice for unlinking involves updating
    the parent's child pointer without modifying the unlinked node's ParentValue or the ParentValue of the newly attached
    subtree. This leaves nodes in the tree that 'recognize it as a parent' while the parent 'does not recognize it as a child'.

    If the parent node cannot be read, **record nothing**: this is a read failure, not a structural
    inconsistency. Mixing the two would cause 'memory swapped out' to be reported as 'tree modified'.

--*/
{
    ULONG_PTR parentValue = 0U;
    PVOID parent = NULL;
    KswInjMmvadShort parentCore;

    parentValue = (ULONG_PTR)core->nodeUnion.vadNode.ParentValue & KSW_INJ_PARENT_VALUE_MASK;
    parent = (PVOID)parentValue;

    if (parent == NULL || parent == node) {
        /*
         * Two representations for the root node: ParentValue is 0, or it points to itself. Both are valid.
         * But only the root can do this; doing so for other nodes breaks the chain.
         */
        if (node != root) {
            ++state->parentMismatchNodes;
        }
        return;
    }
    if (!kswordArkInjectionReadKernel(parent, &parentCore, sizeof(parentCore))) {
        return;  // Failed to read the parent node — not a criterion, do not record.
    }
    if (parentCore.nodeUnion.vadNode.Children[0] != node &&
        parentCore.nodeUnion.vadNode.Children[1] != node) {
        ++state->parentMismatchNodes;
    }
}

static BOOLEAN
kswordArkInjectionVadWalkPush(
    _Inout_ KswInjVadWalkState* state,
    _In_ PVOID node
    )
{
    if (state->depth >= KSWORD_ARK_INJECTION_VAD_MAX_DEPTH) {
        // A real AVL tree would never reach this depth. Arriving here indicates the tree was modified or we are traversing
        // non-tree memory as if it were a tree; stop immediately and mark the inconsistency without following further pointers.
        state->depthOverflow = TRUE;
        return FALSE;
    }
    state->stack[state->depth++] = node;
    return TRUE;
}

NTSTATUS
kswordArkDriverEnumerateProcessVad(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate the VAD tree of the target process. Perform an in-order traversal to return entries sorted by
    StartingVpn in ascending order; when the entry limit is reached, continue scanning via nextCursorVpn.

Return Value:

    STATUS_SUCCESS indicates that the IOCTL has produced a readable response (failure details are written in response->status).

--*/
{
    KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE* response = NULL;
    KswDynState dynState;
    KswInjVadWalkState walk;
    PEPROCESS processObject = NULL;
    PVOID root = NULL;
    PVOID current = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    size_t entryCapacity = 0U;
    ULONG maxEntries = 0UL;
    ULONG rootOffset = 0U;
    ULONG64 rangeStart = 0ULL;
    ULONG64 rangeEnd = 0ULL;
    ULONG64 cursorVpn = 0ULL;
    BOOLEAN truncated = FALSE;

    if (bytesWrittenOut == NULL || outputBuffer == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY);
    response->processId = request->processId;
    response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_IRQL_REJECTED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (request->processId == 0UL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    rangeStart = request->startAddress;
    rangeEnd = (request->endAddress == 0ULL)
        ? (kswordArkInjectionUserAddressLimit() + 1ULL)
        : request->endAddress;
    if (rangeEnd <= rangeStart) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    cursorVpn = request->cursorVpn;

    maxEntries = request->maxEntries;
    if (maxEntries == 0UL) {
        maxEntries = KSWORD_ARK_INJECTION_VAD_LIMIT_DEFAULT;
    }
    if (maxEntries > KSWORD_ARK_INJECTION_VAD_LIMIT_MAX) {
        maxEntries = KSWORD_ARK_INJECTION_VAD_LIMIT_MAX;
    }
    entryCapacity =
        (outputBufferLength - KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY);
    if (entryCapacity > (size_t)maxEntries) {
        entryCapacity = (size_t)maxEntries;
    }
    if (entryCapacity == 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    status = kswordArkInjectionReadVadRoot(processObject, &dynState, &root, &rootOffset);
    if (status == STATUS_NOT_SUPPORTED) {
        // Unverified VadRoot offset — explicitly downgrade, do not guess.
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING;
        response->lastStatus = status;
        response->profileVerified = 0UL;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = status;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    response->profileVerified = 1UL;
    response->vadRootOffset = rootOffset;
    response->vadRootAddress = (ULONG64)(ULONG_PTR)root;
    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ROOT_PRESENT;

    RtlZeroMemory(&walk, sizeof(walk));
    {
        PVOID hint = NULL;
        ULONG count = 0U;
        kswordArkInjectionReadVadIntegrityInputs(
            processObject, &dynState, &hint, &count, &response->fieldFlags);
        walk.vadHint = hint;
        response->vadHintAddress = (ULONG64)(ULONG_PTR)hint;
        response->vadCount = count;
    }
    current = root;

    /*
     * Iterative in-order traversal. Recursion is deliberately avoided: the kernel stack is only 12–24 KiB, and a modified "tree" could cause
     * recursion to overflow the stack directly. The explicit stack has a hard limit; if exceeded, iteration stops and marks inconsistency.
     */
    while ((current != NULL || walk.depth > 0U) && !truncated) {
        /*
         * Read only MmvadShort. Private VADs **are** MmvadShort; their subsequent Subsection/ViewLinks do not
         * exist. Reading the full sizeof(MMVAD) would cross allocation boundaries. When a short VAD happens to fall
         * at the end of a page, this causes resident detection to fail, incorrectly flagging a normal private region
         * as 'node read failure'. Subsections are read separately only after confirming the memory is not private.
         */
        KswInjMmvadShort core;
        ULONG64 startVa = 0ULL;
        ULONG64 endVa = 0ULL;
        ULONG64 startVpn = 0ULL;
        KSWORD_ARK_PROCESS_VAD_ENTRY* entry = NULL;

        if (current != NULL) {
            if (!kswordArkInjectionVadWalkPush(&walk, current)) {
                break;
            }
            if (!kswordArkInjectionReadKernel(current, &core, sizeof(core))) {
                ++walk.unreadableNodes;
                --walk.depth;          // Cannot read at this level; backtrack to the previous level and continue.
                current = NULL;
                continue;
            }
            current = core.nodeUnion.vadNode.Children[0];
            continue;
        }

        current = walk.stack[--walk.depth];
        if (!kswordArkInjectionReadKernel(current, &core, sizeof(core))) {
            ++walk.unreadableNodes;
            current = NULL;
            continue;
        }
        ++walk.visitedNodes;
        kswordArkInjectionCheckParentLink(&walk, current, &core, root);
        if (walk.vadHint != NULL && current == walk.vadHint) {
            walk.vadHintVisited = TRUE;
        }

        startVa = kswordArkInjectionVadStartVa(&core);
        endVa = kswordArkInjectionVadEndVaExclusive(&core);
        startVpn = startVa >> PAGE_SHIFT;

        if (endVa > startVa && startVa < rangeEnd && endVa > rangeStart &&
            startVpn >= cursorVpn) {
            if ((size_t)response->returnedCount >= entryCapacity) {
                // Buffer full: return the next VPN as the cursor to allow the caller to resume scanning.
                truncated = TRUE;
                response->nextCursorVpn = startVpn;
                response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT;
                break;
            }
            entry = &response->entries[response->returnedCount];
            entry->startVa = startVa;
            entry->endVaExclusive = endVa;
            entry->vadNodeAddress = (ULONG64)(ULONG_PTR)current;
            entry->vadFlagsRaw = core.longFlags;
            entry->vadType =
                (core.longFlags >> KSW_INJ_VAD_FLAGS_VADTYPE_SHIFT) &
                KSW_INJ_VAD_FLAGS_VADTYPE_MASK;
            entry->protection =
                (core.longFlags >> KSW_INJ_VAD_FLAGS_PROTECTION_SHIFT) &
                KSW_INJ_VAD_FLAGS_PROTECTION_MASK;
            entry->entryFlags = KSWORD_ARK_INJECTION_VAD_FLAG_FLAGS_LAYOUT_ASSUMED;
            if ((core.longFlags & KSW_INJ_VAD_FLAGS_PRIVATE_MEMORY_BIT) != 0UL) {
                entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_PRIVATE_MEMORY;
            } else {
                /*
                 * Only read the long VAD's Subsection/FirstPrototypePte after confirming the memory is not private.
                 * The bit position for PrivateMemory is assumed, so this step still performs a fault-tolerant read:
                 * If the bit guess is wrong, the result is 'read failure -> leave as 0', not an out-of-bounds access.
                 */
                PVOID subsection = NULL;
                PVOID prototypePte = NULL;
                if (kswordArkInjectionReadKernel(
                        (const UCHAR*)current + FIELD_OFFSET(KswInjMmvad, subsection),
                        &subsection,
                        sizeof(subsection)) &&
                    subsection != NULL) {
                    entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_HAS_SUBSECTION;
                    entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_LONG_VAD;
                    entry->subsection = (ULONG64)(ULONG_PTR)subsection;
                }
                if (kswordArkInjectionReadKernel(
                        (const UCHAR*)current + FIELD_OFFSET(KswInjMmvad, firstPrototypePte),
                        &prototypePte,
                        sizeof(prototypePte))) {
                    entry->firstPrototypePte = (ULONG64)(ULONG_PTR)prototypePte;
                }
            }
            ++response->returnedCount;
            response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT;
        } else if (endVa <= startVa) {
            ++walk.unreadableNodes;
        }

        current = core.nodeUnion.vadNode.Children[1];
    }

    response->visitedCount = walk.visitedNodes;
    response->unreadableNodeCount = walk.unreadableNodes;
    response->parentMismatchNodes = walk.parentMismatchNodes;
    response->vadHintVisited = walk.vadHintVisited ? 1UL : 0UL;
    if (walk.depthOverflow) {
        response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_INCONSISTENT_WALK;
    }

    /*
     * The broken-link criterion holds only after **the entire tree has been traversed**. All three conditions are indispensable:
     *   - No truncation occurred (otherwise visitedCount would already be low).
     *   - No starting cursor (the second half of a resumed scan does not re-traverse the first half).
     *   - No unreadable nodes and no depth overflow (skipped subtrees would naturally cause count
     * mismatches). Range filtering does NOT affect visitedCount — traversal still covers the full tree;
     * filtering only applies to returned entries, so rangeStart/rangeEnd are not included in the condition.
     *
     * Omitting any condition would misreport an incomplete traversal as an unlinked node. This feature
     * must never make that mistake, which would produce consistent false positives on normal machines.
     */
    if (!truncated && cursorVpn == 0ULL && walk.unreadableNodes == 0UL && !walk.depthOverflow) {
        response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID;
    }

    if (truncated) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED;
    } else if (walk.unreadableNodes != 0UL || walk.depthOverflow) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL;
    } else {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_OK;
    }

    *bytesWrittenOut =
        KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY));
    response->size = (ULONG)*bytesWrittenOut;

    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}
