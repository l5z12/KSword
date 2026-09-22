/*++

Module Name:

    callback_extended_special.c

Abstract:

    Enumerates power-setting, coalescing, priority, debug-print, EMP, and
    Plug-and-Play callback registrations. Stable exports are used only as
    bounded anchors; every recovered global and record is validated against
    live list topology and executable loaded-module ranges before publication.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL read-only query path.

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"
#include "ark/ark_dyndata.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_SPECIAL_MAX_REFERENCES 96UL
#define KSW_SPECIAL_MAX_RECORDS 128UL
#define KSW_SPECIAL_ROUTINE_SCAN_BYTES 0x600UL
#define KSW_SPECIAL_MAX_CALL_DEPTH 2UL
#define KSW_SPECIAL_RECORD_BACK_BYTES 0x40UL
#define KSW_SPECIAL_RECORD_FORWARD_BYTES 0xA0UL
#define KSW_SPECIAL_INDIRECT_SCAN_BYTES 0x60UL
#define KSW_SPECIAL_PRIORITY_SLOT_COUNT 8UL
#define KSW_SPECIAL_PNP_LIST_COUNT 13UL
#define KSW_SPECIAL_WORKSPACE_POOL_TAG 'wSsK'

typedef struct KswSpecialRecord
{
    ULONG64 callbackAddress;
    ULONG64 contextAddress;
    ULONG64 registrationAddress;
} KswSpecialRecord, *PkswSpecialRecord;

typedef struct KswSpecialCapture
{
    ULONG64 globalAddress;
    ULONG count;
    BOOLEAN valid;
    KswSpecialRecord records[KSW_SPECIAL_MAX_RECORDS];
} KswSpecialCapture, *PkswSpecialCapture;

/*
 * Candidate captures are about 3 KiB each.  Keeping the references, strongest
 * candidate, and scratch candidate in one reusable pool block prevents the
 * nested signature-scan call chain from exhausting the small kernel stack.
 * The same non-paged workspace also stores DynData, PE views, and traversal records to ensure
 * nested validation functions no longer push these large objects onto the limited kernel stack.
 */
typedef struct KswSpecialWorkspace
{
    KswDynState dynState;
    KswRuntimeImageView ntosView;
    KswRuntimeImageView moduleView;
    KswRuntimeDataReference references[KSW_SPECIAL_MAX_REFERENCES];
    KswSpecialCapture best;
    KswSpecialCapture candidate;
    KswSpecialCapture listScratch;
    ULONG_PTR visited[KSW_SPECIAL_MAX_RECORDS];
} KswSpecialWorkspace, *PkswSpecialWorkspace;

typedef enum KswSpecialCaptureKind
{
    kKswSpecialCaptureDoubleList = 1,
    kKswSpecialCaptureDoubleListIndirect = 2,
    kKswSpecialCaptureSingleList = 3,
    kKswSpecialCapturePriorityArray = 4,
    kKswSpecialCapturePnpLists = 5
} KswSpecialCaptureKind;

static BOOLEAN
kswordArkSpecialIsKernelPointer(
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Rejects user addresses, non-canonical x64 values, and unaligned objects.

Return Value:

    TRUE only for an aligned system-range pointer.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFU &&
        (address & (sizeof(PVOID) - 1U)) == 0U;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#endif
}

static BOOLEAN
kswordArkSpecialInitializeNtosView(
    _Out_ KswRuntimeImageView* viewOut,
    _Inout_ KswSpecialWorkspace* workspace
    )
/*++

Routine Description:

    Builds a bounded PE view from the active ntoskrnl identity already captured
    by the central DynData loader.

Return Value:

    TRUE when the loaded image identity and PE headers are usable.

--*/
{
    KswDynState* state = NULL;

    if (viewOut == NULL || workspace == NULL) {
        return FALSE;
    }
    state = &workspace->dynState;
    RtlZeroMemory(state, sizeof(*state));
    kswordArkDynDataSnapshot(state);
    if (state->ntoskrnl.present == 0UL ||
        state->ntoskrnl.imageBase == 0ULL ||
        state->ntoskrnl.sizeOfImage == 0UL) {
        return FALSE;
    }
    return kswordArkRuntimeInitializeImageView(
        (PVOID)(ULONG_PTR)state->ntoskrnl.imageBase,
        state->ntoskrnl.sizeOfImage,
        viewOut);
}

static BOOLEAN
kswordArkSpecialAddressIsExecutable(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG64 address
    )
/*++

Routine Description:

    Requires a callback candidate to fall inside an executable PE section of
    one currently loaded kernel module.

Return Value:

    TRUE only when the complete pointer resolves to executable image memory.

--*/
{
    ULONG index = 0UL;

    if (moduleCache == NULL || moduleCache->moduleInfo == NULL ||
        workspace == NULL || address == 0ULL) {
        return FALSE;
    }
    for (index = 0UL; index < moduleCache->moduleInfo->numberOfModules; ++index) {
        const KswordArkCallbackModuleEntry* module =
            &moduleCache->moduleInfo->modules[index];
        const ULONG64 kModuleBase = (ULONG64)(ULONG_PTR)module->imageBase;
        KswRuntimeImageView* view = &workspace->moduleView;

        if (kModuleBase == 0ULL || module->imageSize == 0UL ||
            address < kModuleBase || address - kModuleBase >= module->imageSize) {
            continue;
        }
        RtlZeroMemory(view, sizeof(*view));
        if (!kswordArkRuntimeInitializeImageView(
                module->imageBase,
                module->imageSize,
                view)) {
            return FALSE;
        }
        return kswordArkRuntimeAddressIsExecutable(
            view,
            (ULONG_PTR)address,
            1U);
    }
    return FALSE;
}

static BOOLEAN
kswordArkSpecialAddUniqueExecutable(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG64 candidate,
    _Inout_ ULONG64* uniqueAddress,
    _Inout_ ULONG* uniqueCount
    )
/*++

Routine Description:

    Adds one executable candidate to a per-record uniqueness test.

Return Value:

    TRUE when the candidate is absent or does not introduce ambiguity.

--*/
{
    if (uniqueAddress == NULL || uniqueCount == NULL ||
        !kswordArkSpecialAddressIsExecutable(moduleCache, workspace, candidate)) {
        return TRUE;
    }
    if (*uniqueCount == 0UL) {
        *uniqueAddress = candidate;
        *uniqueCount = 1UL;
        return TRUE;
    }
    if (*uniqueAddress == candidate) {
        return TRUE;
    }
    *uniqueCount += 1UL;
    return FALSE;
}

static BOOLEAN
kswordArkSpecialFindExecutableAround(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR centerAddress,
    _In_ BOOLEAN decodeShiftedValues,
    _Out_ ULONG64* callbackAddressOut
    )
/*++

Routine Description:

    Infers a callback member without a build-specific record offset. Pointer-
    aligned fields around the validated registration node are sampled, and the
    record is accepted only when exactly one executable address survives.

Return Value:

    TRUE when one unique executable callback was recovered.

--*/
{
    LONG offset = 0L;
    ULONG uniqueCount = 0UL;
    ULONG64 uniqueAddress = 0ULL;

    if (moduleCache == NULL || workspace == NULL || callbackAddressOut == NULL ||
        !kswordArkSpecialIsKernelPointer(centerAddress)) {
        return FALSE;
    }
    *callbackAddressOut = 0ULL;
    for (offset = -(LONG)KSW_SPECIAL_RECORD_BACK_BYTES;
         offset <= (LONG)KSW_SPECIAL_RECORD_FORWARD_BYTES;
         offset += (LONG)sizeof(PVOID)) {
        ULONG_PTR fieldAddress = 0U;
        ULONG_PTR rawValue = 0U;
        ULONG64 decodedValue = 0ULL;

        if (offset < 0) {
            const ULONG_PTR kMagnitude = (ULONG_PTR)(-(LONGLONG)offset);
            if (centerAddress < kMagnitude) {
                continue;
            }
            fieldAddress = centerAddress - kMagnitude;
        }
        else {
            if (centerAddress > MAXULONG_PTR - (ULONG_PTR)offset) {
                continue;
            }
            fieldAddress = centerAddress + (ULONG_PTR)offset;
        }
        if (!kswordArkRuntimeReadMemory(
                (const VOID*)fieldAddress,
                &rawValue,
                sizeof(rawValue))) {
            continue;
        }
        if (!kswordArkSpecialAddUniqueExecutable(
                moduleCache,
                workspace,
                (ULONG64)rawValue,
                &uniqueAddress,
                &uniqueCount)) {
            return FALSE;
        }
#if defined(_M_AMD64) || defined(_M_X64)
        if (decodeShiftedValues && rawValue != 0U) {
            decodedValue = ((ULONG64)rawValue >> 8U) | 0xFFFF000000000000ULL;
            if (!kswordArkSpecialAddUniqueExecutable(
                    moduleCache,
                    workspace,
                    decodedValue,
                    &uniqueAddress,
                    &uniqueCount)) {
                return FALSE;
            }
        }
#else
        UNREFERENCED_PARAMETER(DecodeShiftedValues);
#endif
    }
    if (uniqueCount != 1UL) {
        return FALSE;
    }
    *callbackAddressOut = uniqueAddress;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialFindExecutableIndirect(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR nodeAddress,
    _Out_ ULONG64* callbackAddressOut,
    _Out_ ULONG64* contextAddressOut
    )
/*++

Routine Description:

    Handles registrations whose list node references a separate owner record.
    Direct record fields are preferred; otherwise each nearby kernel pointer is
    tested as a second bounded record, again requiring one unique callback.

Return Value:

    TRUE when direct or single-indirection structural inference is unique.

--*/
{
    ULONG offset = 0UL;
    ULONG64 callbackAddress = 0ULL;
    ULONG64 uniqueCallback = 0ULL;
    ULONG64 uniqueContext = 0ULL;
    ULONG uniqueCount = 0UL;

    if (workspace == NULL || callbackAddressOut == NULL || contextAddressOut == NULL) {
        return FALSE;
    }
    *callbackAddressOut = 0ULL;
    *contextAddressOut = 0ULL;
    if (kswordArkSpecialFindExecutableAround(
            moduleCache,
            workspace,
            nodeAddress,
            FALSE,
            &callbackAddress)) {
        *callbackAddressOut = callbackAddress;
        return TRUE;
    }
    for (offset = 0UL; offset <= KSW_SPECIAL_INDIRECT_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR ownerAddress = 0U;

        if (nodeAddress > MAXULONG_PTR - offset ||
            !kswordArkRuntimeReadMemory(
                (const VOID*)(nodeAddress + offset),
                &ownerAddress,
                sizeof(ownerAddress))) {
            continue;
        }
        ownerAddress &= ~((ULONG_PTR)0x0FU);
        if (!kswordArkSpecialIsKernelPointer(ownerAddress) ||
            !kswordArkSpecialFindExecutableAround(
                moduleCache,
                workspace,
                ownerAddress,
                FALSE,
                &callbackAddress)) {
            continue;
        }
        if (uniqueCount == 0UL) {
            uniqueCallback = callbackAddress;
            uniqueContext = (ULONG64)ownerAddress;
            uniqueCount = 1UL;
        }
        else if (uniqueCallback != callbackAddress ||
            uniqueContext != (ULONG64)ownerAddress) {
            return FALSE;
        }
    }
    if (uniqueCount != 1UL) {
        return FALSE;
    }
    *callbackAddressOut = uniqueCallback;
    *contextAddressOut = uniqueContext;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialReadValidatedListHead(
    _In_ ULONG_PTR headAddress,
    _Out_ LIST_ENTRY* headOut
    )
/*++

Routine Description:

    Reads a circular list head and validates reciprocal first/last links.

Return Value:

    TRUE for a structurally valid empty or non-empty list.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;

    if (headOut == NULL || !kswordArkSpecialIsKernelPointer(headAddress) ||
        !kswordArkRuntimeReadMemory((const VOID*)headAddress, &head, sizeof(head))) {
        return FALSE;
    }
    if ((ULONG_PTR)head.Flink == headAddress &&
        (ULONG_PTR)head.Blink == headAddress) {
        *headOut = head;
        return TRUE;
    }
    if (!kswordArkSpecialIsKernelPointer((ULONG_PTR)head.Flink) ||
        !kswordArkSpecialIsKernelPointer((ULONG_PTR)head.Blink) ||
        !kswordArkRuntimeReadMemory(head.Flink, &first, sizeof(first)) ||
        !kswordArkRuntimeReadMemory(head.Blink, &last, sizeof(last)) ||
        (ULONG_PTR)first.Blink != headAddress ||
        (ULONG_PTR)last.Flink != headAddress) {
        return FALSE;
    }
    *headOut = head;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialCaptureDoubleList(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR headAddress,
    _In_ BOOLEAN allowIndirect,
    _Inout_ KswSpecialCapture* capture
    )
/*++

Routine Description:

    Traverses one validated circular registration list with loop, reciprocal-
    link, record-count, and executable-callback bounds.

Return Value:

    TRUE when the complete observed topology is self-consistent.

--*/
{
    LIST_ENTRY head;
    ULONG_PTR currentAddress = 0U;
    ULONG_PTR previousAddress = headAddress;
    ULONG visitCount = 0UL;

    if (capture == NULL || workspace == NULL ||
        !kswordArkSpecialReadValidatedListHead(headAddress, &head)) {
        return FALSE;
    }
    currentAddress = (ULONG_PTR)head.Flink;
    while (currentAddress != headAddress) {
        LIST_ENTRY current;
        ULONG64 callbackAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (visitCount >= KSW_SPECIAL_MAX_RECORDS ||
            !kswordArkSpecialIsKernelPointer(currentAddress) ||
            !kswordArkRuntimeReadMemory(
                (const VOID*)currentAddress,
                &current,
                sizeof(current)) ||
            (ULONG_PTR)current.Blink != previousAddress) {
            return FALSE;
        }
        if (allowIndirect) {
            if (!kswordArkSpecialFindExecutableIndirect(
                    moduleCache,
                    workspace,
                    currentAddress,
                    &callbackAddress,
                    &contextAddress)) {
                return FALSE;
            }
        }
        else if (!kswordArkSpecialFindExecutableAround(
                moduleCache,
                workspace,
                currentAddress,
                FALSE,
                &callbackAddress)) {
            return FALSE;
        }
        capture->records[capture->count].callbackAddress = callbackAddress;
        capture->records[capture->count].contextAddress = contextAddress;
        capture->records[capture->count].registrationAddress =
            (ULONG64)currentAddress;
        capture->count += 1UL;
        visitCount += 1UL;
        previousAddress = currentAddress;
        currentAddress = (ULONG_PTR)current.Flink;
    }
    if (previousAddress != (ULONG_PTR)head.Blink) {
        return FALSE;
    }
    capture->globalAddress = (ULONG64)headAddress;
    capture->valid = TRUE;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialCaptureSingleList(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR headAddress,
    _Inout_ KswSpecialCapture* capture
    )
/*++

Routine Description:

    Traverses an EMP-style singly linked registration list with cycle and
    executable-owner validation.

Return Value:

    TRUE for a complete bounded list, including an empty list.

--*/
{
    SINGLE_LIST_ENTRY head;
    ULONG_PTR currentAddress = 0U;
    ULONG_PTR* visited = NULL;
    ULONG visitCount = 0UL;

    if (capture == NULL || workspace == NULL ||
        !kswordArkSpecialIsKernelPointer(headAddress) ||
        !kswordArkRuntimeReadMemory((const VOID*)headAddress, &head, sizeof(head))) {
        return FALSE;
    }
    visited = workspace->visited;
    RtlZeroMemory(visited, sizeof(workspace->visited));
    currentAddress = (ULONG_PTR)head.Next;
    while (currentAddress != 0U) {
        SINGLE_LIST_ENTRY current;
        ULONG index = 0UL;
        ULONG64 callbackAddress = 0ULL;

        if (visitCount >= KSW_SPECIAL_MAX_RECORDS ||
            !kswordArkSpecialIsKernelPointer(currentAddress)) {
            return FALSE;
        }
        for (index = 0UL; index < visitCount; ++index) {
            if (visited[index] == currentAddress) {
                return FALSE;
            }
        }
        if (!kswordArkRuntimeReadMemory(
                (const VOID*)currentAddress,
                &current,
                sizeof(current)) ||
            !kswordArkSpecialFindExecutableAround(
                moduleCache,
                workspace,
                currentAddress,
                FALSE,
                &callbackAddress)) {
            return FALSE;
        }
        visited[visitCount] = currentAddress;
        capture->records[capture->count].callbackAddress = callbackAddress;
        capture->records[capture->count].registrationAddress =
            (ULONG64)currentAddress;
        capture->count += 1UL;
        visitCount += 1UL;
        currentAddress = (ULONG_PTR)current.Next;
    }
    capture->globalAddress = (ULONG64)headAddress;
    capture->valid = TRUE;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialCapturePriorityArray(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR arrayAddress,
    _Inout_ KswSpecialCapture* capture
    )
/*++

Routine Description:

    Validates the fixed public API priority-slot count and decodes the tagged
    record representation by executable-address shape rather than member offset.

Return Value:

    TRUE when every populated slot yields one callback.

--*/
{
    ULONG slot = 0UL;

    if (capture == NULL || workspace == NULL ||
        !kswordArkSpecialIsKernelPointer(arrayAddress)) {
        return FALSE;
    }
    for (slot = 0UL; slot < KSW_SPECIAL_PRIORITY_SLOT_COUNT; ++slot) {
        ULONG_PTR recordAddress = 0U;
        ULONG64 callbackAddress = 0ULL;

        if (!kswordArkRuntimeReadMemory(
                (const VOID*)(arrayAddress + ((ULONG_PTR)slot * sizeof(PVOID))),
                &recordAddress,
                sizeof(recordAddress))) {
            return FALSE;
        }
        if (recordAddress == 0U) {
            continue;
        }
        if (!kswordArkSpecialIsKernelPointer(recordAddress) ||
            !kswordArkSpecialFindExecutableAround(
                moduleCache,
                workspace,
                recordAddress,
                TRUE,
                &callbackAddress)) {
            return FALSE;
        }
        capture->records[capture->count].callbackAddress = callbackAddress;
        capture->records[capture->count].contextAddress = slot;
        capture->records[capture->count].registrationAddress =
            (ULONG64)recordAddress;
        capture->count += 1UL;
    }
    capture->globalAddress = (ULONG64)arrayAddress;
    capture->valid = TRUE;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialCapturePnpLists(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ ULONG_PTR arrayAddress,
    _Inout_ KswSpecialCapture* capture,
    _Inout_ KswSpecialCapture* listScratch
    )
/*++

Routine Description:

    Validates the thirteen Plug-and-Play notification class heads and combines
    their bounded registration rows into one snapshot.

Return Value:

    TRUE only when all list heads are structurally valid.

--*/
{
    ULONG listIndex = 0UL;

    if (workspace == NULL || capture == NULL || listScratch == NULL ||
        capture == listScratch || !kswordArkSpecialIsKernelPointer(arrayAddress)) {
        return FALSE;
    }
    for (listIndex = 0UL; listIndex < KSW_SPECIAL_PNP_LIST_COUNT; ++listIndex) {
        const ULONG_PTR kHeadAddress = arrayAddress +
            ((ULONG_PTR)listIndex * sizeof(LIST_ENTRY));
        ULONG rowIndex = 0UL;

        // Reuse the pool-backed list scratch for every PnP class; keeping this
        // 3 KiB capture off the stack is required even though lists are serial.
        RtlZeroMemory(listScratch, sizeof(*listScratch));
        if (!kswordArkSpecialCaptureDoubleList(
                moduleCache,
                workspace,
                kHeadAddress,
                FALSE,
                listScratch) ||
            capture->count > KSW_SPECIAL_MAX_RECORDS - listScratch->count) {
            return FALSE;
        }
        for (rowIndex = 0UL; rowIndex < listScratch->count; ++rowIndex) {
            capture->records[capture->count] = listScratch->records[rowIndex];
            capture->records[capture->count].contextAddress = listIndex;
            capture->count += 1UL;
        }
    }
    capture->globalAddress = (ULONG64)arrayAddress;
    capture->valid = TRUE;
    return TRUE;
}

static BOOLEAN
kswordArkSpecialTryCapture(
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_ KswSpecialCaptureKind kind,
    _In_ ULONG_PTR candidateAddress,
    _Out_ KswSpecialCapture* captureOut,
    _Inout_ KswSpecialCapture* listScratch
    )
/*++

Routine Description:

    Dispatches one feature-specific structural validator.

Return Value:

    TRUE when the candidate is a complete registration container.

--*/
{
    if (captureOut == NULL || workspace == NULL) {
        return FALSE;
    }
    RtlZeroMemory(captureOut, sizeof(*captureOut));
    switch (kind) {
    case kKswSpecialCaptureDoubleList:
        return kswordArkSpecialCaptureDoubleList(
            moduleCache,
            workspace,
            candidateAddress,
            FALSE,
            captureOut);
    case kKswSpecialCaptureDoubleListIndirect:
        return kswordArkSpecialCaptureDoubleList(
            moduleCache,
            workspace,
            candidateAddress,
            TRUE,
            captureOut);
    case kKswSpecialCaptureSingleList:
        return kswordArkSpecialCaptureSingleList(
            moduleCache,
            workspace,
            candidateAddress,
            captureOut);
    case kKswSpecialCapturePriorityArray:
        return kswordArkSpecialCapturePriorityArray(
            moduleCache,
            workspace,
            candidateAddress,
            captureOut);
    case kKswSpecialCapturePnpLists:
        return kswordArkSpecialCapturePnpLists(
            moduleCache,
            workspace,
            candidateAddress,
            captureOut,
            listScratch);
    default:
        return FALSE;
    }
}

static BOOLEAN
kswordArkSpecialCaptureBetter(
    _In_ const KswSpecialCapture* candidate,
    _In_ const KswSpecialCapture* current
    )
/*++

Routine Description:

    Orders validated candidates by live registration evidence.

Return Value:

    TRUE when Candidate has a strictly stronger record count.

--*/
{
    return candidate != NULL && candidate->valid &&
        (current == NULL || !current->valid || candidate->count > current->count);
}

static BOOLEAN
kswordArkSpecialFindBestCapture(
    _In_ const KswRuntimeImageView* ntosView,
    _In_ const KswordArkCallbackModuleCache* moduleCache,
    _In_reads_(anchorCount) PCSTR const* anchorNames,
    _In_ ULONG anchorCount,
    _In_ KswSpecialCaptureKind kind,
    _Inout_ KswSpecialWorkspace* workspace,
    _Out_ BOOLEAN* ambiguousOut
    )
/*++

Routine Description:

    Collects writable data references reachable from stable exports, validates
    both direct globals and pointer globals, and rejects tied best candidates.

Return Value:

    TRUE when one strongest structural candidate exists.

--*/
{
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    BOOLEAN ambiguous = FALSE;

    if (workspace == NULL || ambiguousOut == NULL) {
        return FALSE;
    }
    // Preserve NtosView and DynState while resetting only reusable search data.
    RtlZeroMemory(workspace->references, sizeof(workspace->references));
    RtlZeroMemory(&workspace->best, sizeof(workspace->best));
    RtlZeroMemory(&workspace->candidate, sizeof(workspace->candidate));
    RtlZeroMemory(&workspace->listScratch, sizeof(workspace->listScratch));
    RtlZeroMemory(workspace->visited, sizeof(workspace->visited));
    *ambiguousOut = FALSE;
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        ntosView,
        anchorNames,
        anchorCount,
        KSW_SPECIAL_MAX_CALL_DEPTH,
        KSW_SPECIAL_ROUTINE_SCAN_BYTES,
        workspace->references,
        RTL_NUMBER_OF(workspace->references));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        ULONG_PTR candidates[2];
        ULONG candidateIndex = 0UL;

        RtlZeroMemory(candidates, sizeof(candidates));
        candidates[0] = workspace->references[referenceIndex].address;
        (VOID)kswordArkRuntimeReadMemory(
            (const VOID*)workspace->references[referenceIndex].address,
            &candidates[1],
            sizeof(candidates[1]));
        for (candidateIndex = 0UL; candidateIndex < RTL_NUMBER_OF(candidates);
             ++candidateIndex) {
            KswSpecialCapture* candidate = &workspace->candidate;

            if (!kswordArkSpecialIsKernelPointer(candidates[candidateIndex]) ||
                (candidateIndex != 0UL && candidates[1] == candidates[0])) {
                continue;
            }
            RtlZeroMemory(candidate, sizeof(*candidate));
            if (!kswordArkSpecialTryCapture(
                    moduleCache,
                    workspace,
                    kind,
                    candidates[candidateIndex],
                    candidate,
                    &workspace->listScratch)) {
                continue;
            }
            if (kswordArkSpecialCaptureBetter(candidate, &workspace->best)) {
                workspace->best = *candidate;
                ambiguous = FALSE;
            }
            else if (workspace->best.valid &&
                candidate->count == workspace->best.count &&
                candidate->globalAddress != workspace->best.globalAddress) {
                ambiguous = TRUE;
            }
        }
    }
    if (!workspace->best.valid || ambiguous) {
        *ambiguousOut = ambiguous;
        return FALSE;
    }
    return TRUE;
}

static VOID
kswordArkSpecialPublishCapture(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ const KswSpecialCapture* capture,
    _In_ ULONG callbackClass,
    _In_ ULONG registrationType,
    _In_z_ PCWSTR nameText
    )
/*++

Routine Description:

    Publishes validated callback rows without enabling removal semantics.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (capture == NULL || !capture->valid) {
        return;
    }
    if (capture->count == 0UL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            NULL,
            callbackClass,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_SUCCESS,
            registrationType,
            0UL,
            0UL,
            0ULL,
            capture->globalAddress,
            capture->globalAddress,
            0UL,
            nameText,
            L"已唯一定位并验证注册容器；当前快照为空。");
        return;
    }
    for (index = 0UL; index < capture->count; ++index) {
        const KswSpecialRecord* record = &capture->records[index];

        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            callbackClass,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            registrationType,
            0UL,
            0UL,
            record->callbackAddress,
            record->contextAddress,
            record->registrationAddress,
            KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE,
            nameText,
            L"稳定导出锚点、有界数据引用、实时拓扑和可执行模块归属均已验证；只读展示。");
    }
}

static VOID
kswordArkSpecialEnumerateOne(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ const KswRuntimeImageView* ntosView,
    _Inout_ KswSpecialWorkspace* workspace,
    _In_reads_(anchorCount) PCSTR const* anchorNames,
    _In_ ULONG anchorCount,
    _In_ KswSpecialCaptureKind kind,
    _In_ ULONG callbackClass,
    _In_ ULONG registrationType,
    _In_z_ PCWSTR nameText
    )
/*++

Routine Description:

    Resolves and publishes one special callback family with an explicit
    unsupported row when validation cannot establish a unique container.

Return Value:

    None.

--*/
{
    BOOLEAN ambiguous = FALSE;

    if (!kswordArkSpecialFindBestCapture(
            ntosView,
            moduleCache,
            anchorNames,
            anchorCount,
            kind,
            workspace,
            &ambiguous)) {
        kswordArkCallbackEnumAddUnsupportedRow(
            builder,
            callbackClass,
            nameText,
            ambiguous
                ? L"锚点产生多个同强度候选，已按 fail-closed 策略拒绝猜测。"
                : L"未从稳定导出锚点恢复出唯一且结构完整的注册容器。");
        return;
    }
    kswordArkSpecialPublishCapture(
        builder,
        moduleCache,
        &workspace->best,
        callbackClass,
        registrationType,
        nameText);
}

VOID
kswordArkCallbackExtendedAddSpecialCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Adds the six callback families missing from the original KSword inventory.

Return Value:

    None. Every family contributes validated rows or one explicit diagnostic.

--*/
{
    static PCSTR const kPowerAnchors[] = {
        "PoRegisterPowerSettingCallback",
        "PoUnregisterPowerSettingCallback"
    };
    static PCSTR const kCoalescingAnchors[] = {
        "PoRegisterCoalescingCallback",
        "PoUnregisterCoalescingCallback"
    };
    static PCSTR const kPriorityAnchors[] = {
        "IoRegisterPriorityCallback"
    };
    static PCSTR const kDebugPrintAnchors[] = {
        "DbgSetDebugPrintCallback"
    };
    static PCSTR const kEmpAnchors[] = {
        "EmpProviderRegister",
        "EmpProviderDeregister"
    };
    static PCSTR const kPlugPlayAnchors[] = {
        "IoRegisterPlugPlayNotification",
        "IoUnregisterPlugPlayNotification"
    };
    KswordArkCallbackModuleCache moduleCache;
    KswSpecialWorkspace* workspace = NULL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;

    if (builder == NULL) {
        return;
    }
    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    moduleStatus = kswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    // One bounded nonpaged block is reused serially by all family searches;
    // no callback data escapes after it is published into the response builder.
    workspace = (KswSpecialWorkspace*)kswordArkAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_SPECIAL_WORKSPACE_POOL_TAG);
    if (workspace != NULL) {
        RtlZeroMemory(workspace, sizeof(*workspace));
    }
    if (!NT_SUCCESS(moduleStatus) ||
        workspace == NULL ||
        !kswordArkSpecialInitializeNtosView(&workspace->ntosView, workspace)) {
        const ULONG kClasses[] = {
            KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY
        };
        static PCWSTR const kNames[] = {
            L"Power Setting Callback",
            L"Coalescing Callback",
            L"Priority Callback",
            L"Debug Print Callback",
            L"EMP Callback",
            L"Plug and Play Notification"
        };
        ULONG index = 0UL;

        for (index = 0UL; index < RTL_NUMBER_OF(kClasses); ++index) {
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                kClasses[index],
                kNames[index],
                L"ntoskrnl 映像视图或已加载模块快照不可用。");
        }
        if (workspace != NULL) {
            ExFreePoolWithTag(workspace, KSW_SPECIAL_WORKSPACE_POOL_TAG);
            workspace = NULL;
        }
        kswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }

    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kPowerAnchors,
        RTL_NUMBER_OF(kPowerAnchors),
        kKswSpecialCaptureDoubleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_POWER_SETTING,
        L"Power Setting Callback");
    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kCoalescingAnchors,
        RTL_NUMBER_OF(kCoalescingAnchors),
        kKswSpecialCaptureDoubleListIndirect,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_COALESCING,
        L"Coalescing Callback");
    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kPriorityAnchors,
        RTL_NUMBER_OF(kPriorityAnchors),
        kKswSpecialCapturePriorityArray,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PRIORITY,
        L"Priority Callback");
    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kDebugPrintAnchors,
        RTL_NUMBER_OF(kDebugPrintAnchors),
        kKswSpecialCaptureDoubleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DEBUG_PRINT,
        L"Debug Print Callback");
    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kEmpAnchors,
        RTL_NUMBER_OF(kEmpAnchors),
        kKswSpecialCaptureSingleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_EMP,
        L"EMP Callback");
    kswordArkSpecialEnumerateOne(
        builder,
        &moduleCache,
        &workspace->ntosView,
        workspace,
        kPlugPlayAnchors,
        RTL_NUMBER_OF(kPlugPlayAnchors),
        kKswSpecialCapturePnpLists,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PLUG_PLAY,
        L"Plug and Play Notification");
    ExFreePoolWithTag(workspace, KSW_SPECIAL_WORKSPACE_POOL_TAG);
    workspace = NULL;
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
