/*++

Module Name:

    driver_image_editor_list.c

Abstract:

    Resolves the exact ntoskrnl module-list exports, holds the real loader
    resource, validates reciprocal LIST_ENTRY links, and performs reversible
    PsLoadedModuleList unlink/reinsert operations.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL transaction path.

--*/

#include "driver_image_editor_internal.h"
#include "../../platform/runtime_signature_scan.h"

// Note: The repository's existing fallback already uses this ntoskrnl export parser; here, only parse the exact data export name.
NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_ PCCH routineName
    );

// Note: Ensure the exported variable fully resides within the ntoskrnl image range matching the identity.
static BOOLEAN
kswordArkDriverImageAddressInNtos(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    )
{
    ULONG_PTR imageBase = 0U;
    ULONG_PTR imageEnd = 0U;

    // Note: Without the current kernel identity, do not treat arbitrary addresses as loader synchronization objects.
    if (identity == NULL || identity->present == 0UL ||
        identity->imageBase == 0ULL || identity->sizeOfImage == 0UL) {
        return FALSE;
    }
    // Note: Check the image range addition first to prevent address wraparound from causing false range hits.
    imageBase = (ULONG_PTR)identity->imageBase;
    if (imageBase > MAXULONG_PTR - identity->sizeOfImage) {
        return FALSE;
    }
    imageEnd = imageBase + identity->sizeOfImage;
    // Note: The entire object range must reside within the image; verifying only the start address is insufficient.
    if (address < imageBase || address >= imageEnd ||
        requiredBytes > imageEnd - address) {
        return FALSE;
    }
    return TRUE;
}

// Note: All linked list and KLDR small field reads use safe MmCopyMemory reads; corrupted addresses return only a status.
static BOOLEAN
kswordArkDriverImageReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    )
{
    // Note: List nodes may be corrupted or unmapped; use MmCopyMemory uniformly to convert invalid accesses to read failures.
    return kswordArkRuntimeReadMemory(address, buffer, size);
}

// Note: Runtime resolution simultaneously verifies that the DynData layout, chain-head exports, and resource lock exports belong to the same ntoskrnl.
NTSTATUS
kswordArkDriverImageResolveRuntime(
    _Out_ KswDriverImageRuntime* runtime
    )
{
    PVOID imageBase = NULL;
    PLIST_ENTRY exportedListHead = NULL;
    PERESOURCE exportedResource = NULL;
    ULONGLONG dynDataListHead = 0ULL;

    // Note: Output is zeroed first; failure responses will not carry kernel addresses from the previous query.
    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(runtime, sizeof(*runtime));
    // Note: Snapshot copying is internally synchronized by the DynData module; do not hold its global lock for cross-module operations.
    kswordArkDynDataSnapshot(&runtime->dynState);
    if (!runtime->dynState.initialized || !runtime->dynState.ntosActive ||
        runtime->dynState.ntoskrnl.imageBase == 0ULL ||
        runtime->dynState.ntoskrnl.sizeOfImage == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }
    // Note: KLDR private fields must originate from the PDB or be validated field-by-field in real-time fallback.
    if ((runtime->dynState.capabilityMask &
        KSW_CAP_KERNEL_MODULE_LIST_FIELDS) == 0ULL ||
        !kswordArkDriverIntegrityOffsetPresent(
            runtime->dynState.kernel.kldrInLoadOrderLinks) ||
        !kswordArkDriverIntegrityOffsetPresent(
            runtime->dynState.kernel.kldrDllBase) ||
        !kswordArkDriverIntegrityOffsetPresent(
            runtime->dynState.kernel.kldrSizeOfImage)) {
        return STATUS_NOT_SUPPORTED;
    }

    // Note: Parse exported data directly from the matched active image, without using user-supplied addresses.
    imageBase = (PVOID)(ULONG_PTR)runtime->dynState.ntoskrnl.imageBase;
    exportedListHead = (PLIST_ENTRY)RtlFindExportedRoutineByName(
        imageBase,
        "PsLoadedModuleList");
    exportedResource = (PERESOURCE)RtlFindExportedRoutineByName(
        imageBase,
        "PsLoadedModuleResource");
    if (exportedListHead == NULL || exportedResource == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    // Note: Both variables must be fully contained within the current ntoskrnl image data region.
    if (!kswordArkDriverImageAddressInNtos(
            &runtime->dynState.ntoskrnl,
            (ULONG_PTR)exportedListHead,
            sizeof(*exportedListHead)) ||
        !kswordArkDriverImageAddressInNtos(
            &runtime->dynState.ntoskrnl,
            (ULONG_PTR)exportedResource,
            sizeof(*exportedResource))) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // Note: The PsLoadedModuleList RVA in DynData must precisely point to the same address as the PE export.
    dynDataListHead = kswordArkDriverIntegrityNtosAddressFromRva(
        &runtime->dynState,
        runtime->dynState.kernelGlobals.psLoadedModuleList,
        sizeof(LIST_ENTRY));
    if (dynDataListHead == 0ULL ||
        dynDataListHead != (ULONGLONG)(ULONG_PTR)exportedListHead) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    // Note: After publishing the runtime object, the caller must explicitly call AcquireRuntime to read or write the list.
    runtime->listHead = exportedListHead;
    runtime->listResource = exportedResource;
    runtime->layoutFlags =
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_DYNDATA_VALIDATED |
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_LIST_EXPORT |
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_RESOURCE_EXPORT;
    return STATUS_SUCCESS;
}

// Note: Resource lock calls follow the Microsoft ERESOURCE convention, keeping normal kernel APCs disabled during the wait.
NTSTATUS
kswordArkDriverImageAcquireRuntime(
    _Inout_ KswDriverImageRuntime* runtime,
    _In_ BOOLEAN exclusive
    )
{
    BOOLEAN acquired = FALSE;

    // Note: Repeated acquisition and calls at high IRQL would break resource pairing, so the request is rejected directly.
    if (runtime == NULL || runtime->listResource == NULL ||
        runtime->resourceAcquired != FALSE ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    // Note: ERESOURCE wait operations require disabling normal kernel APCs; they must be symmetrically restored upon release.
    KeEnterCriticalRegion();
    if (exclusive != FALSE) {
        acquired = ExAcquireResourceExclusiveLite(
            runtime->listResource,
            TRUE);
    }
    else {
        acquired = ExAcquireResourceSharedLite(
            runtime->listResource,
            TRUE);
    }
    if (acquired == FALSE) {
        // Note: Wait=TRUE should theoretically succeed; still retains a definite exception exit path.
        KeLeaveCriticalRegion();
        return STATUS_DEVICE_BUSY;
    }
    runtime->resourceAcquired = TRUE;
    runtime->resourceExclusive = exclusive;
    return STATUS_SUCCESS;
}

// Note: Unified release to avoid missing ExReleaseResourceLite/KeLeaveCriticalRegion in any error path.
VOID
kswordArkDriverImageReleaseRuntime(
    _Inout_ KswDriverImageRuntime* runtime
    )
{
    // Note: Do not touch system resources not belonging to the current thread if acquisition fails.
    if (runtime == NULL || runtime->resourceAcquired == FALSE ||
        runtime->listResource == NULL) {
        return;
    }
    ExReleaseResourceLite(runtime->listResource);
    runtime->resourceAcquired = FALSE;
    runtime->resourceExclusive = FALSE;
    KeLeaveCriticalRegion();
}

// Note: When the module resource is already held, fully traverse the list once and return the member status of the target link.
static NTSTATUS
kswordArkDriverImageInspectLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ PLIST_ENTRY targetLink,
    _Inout_ KswDriverImageLinkView* view
    )
{
    LIST_ENTRY headSnapshot;
    LIST_ENTRY targetSnapshot;
    PLIST_ENTRY current = NULL;
    PLIST_ENTRY previous = NULL;
    ULONG visited = 0UL;

    // Note: Chain read must occur during the shared or exclusive hold of the real PsLoadedModuleResource.
    if (runtime == NULL || view == NULL || targetLink == NULL ||
        runtime->listHead == NULL || runtime->resourceAcquired == FALSE ||
        targetLink == runtime->listHead) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    RtlZeroMemory(&targetSnapshot, sizeof(targetSnapshot));
    if (!kswordArkDriverImageReadMemory(
            runtime->listHead,
            &headSnapshot,
            sizeof(headSnapshot)) ||
        !kswordArkDriverImageReadMemory(
            targetLink,
            &targetSnapshot,
            sizeof(targetSnapshot))) {
        view->malformed = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    // Note: Self-loop and absence from the main chain is the hidden representation defined by this transaction.
    if (targetSnapshot.Flink == targetLink &&
        targetSnapshot.Blink == targetLink) {
        view->selfLinked = TRUE;
    }
    if (headSnapshot.Flink == NULL || headSnapshot.Blink == NULL) {
        view->malformed = TRUE;
        return STATUS_DATA_ERROR;
    }

    // Note: Verify that each item's Blink is the reverse of the previous item, starting from the list head.
    current = headSnapshot.Flink;
    previous = runtime->listHead;
    while (current != runtime->listHead && visited < KSW_DRIVER_IMAGE_LIST_WALK_LIMIT) {
        LIST_ENTRY currentSnapshot;

        if (current == NULL) {
            view->malformed = TRUE;
            return STATUS_DATA_ERROR;
        }
        RtlZeroMemory(&currentSnapshot, sizeof(currentSnapshot));
        if (!kswordArkDriverImageReadMemory(
                current,
                &currentSnapshot,
                sizeof(currentSnapshot)) ||
            currentSnapshot.Flink == NULL ||
            currentSnapshot.Blink != previous) {
            view->malformed = TRUE;
            return STATUS_DATA_ERROR;
        }
        // Note: Save the locked current neighbor when the target is hit; do not directly trust R3 addresses.
        if (current == targetLink) {
            view->inList = TRUE;
            view->flink = currentSnapshot.Flink;
            view->blink = currentSnapshot.Blink;
        }
        previous = current;
        current = currentSnapshot.Flink;
        ++visited;
    }
    // Note: Exceeding the budget or not returning to the list head indicates a cycle or broken link; no write operations are allowed.
    if (current != runtime->listHead ||
        visited >= KSW_DRIVER_IMAGE_LIST_WALK_LIMIT ||
        headSnapshot.Blink != previous) {
        view->malformed = TRUE;
        return STATUS_DATA_ERROR;
    }
    // Note: If the target is not in the main chain, only accept an explicit self-loop; dangling to other nodes is treated as an external conflict.
    if (view->inList == FALSE && view->selfLinked == FALSE) {
        view->malformed = TRUE;
        view->flink = targetSnapshot.Flink;
        view->blink = targetSnapshot.Blink;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (view->inList == FALSE) {
        view->flink = targetSnapshot.Flink;
        view->blink = targetSnapshot.Blink;
    }
    return STATUS_SUCCESS;
}

// Note: Locate the initial loader item by exact DriverStart/DllBase; fuzzy hits that merely fall within the module range are not accepted.
NTSTATUS
kswordArkDriverImageLocateLoaderLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ ULONGLONG driverStart,
    _Out_ KswDriverImageLinkView* view
    )
{
    KswDriverIntegrityLdrTarget target;
    NTSTATUS status = STATUS_SUCCESS;

    // Note: A DriverStart value of zero means there is no provable KLDR image identity.
    if (runtime == NULL || view == NULL || driverStart == 0ULL ||
        runtime->resourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(view, sizeof(*view));
    RtlZeroMemory(&target, sizeof(target));
    status = kswordArkDriverIntegrityFindLoadedModule(
        &runtime->dynState,
        driverStart,
        &target);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Note: Full equality is stronger than 'address within image range'; prevents selecting incorrect loader record.
    if (!target.found || target.dllBase != driverStart ||
        target.entryAddress == 0ULL || target.linkAddress == 0ULL ||
        target.listHeadAddress != (ULONGLONG)(ULONG_PTR)runtime->listHead) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    view->loaderAvailable = TRUE;
    view->entryAddress = target.entryAddress;
    view->linkAddress = target.linkAddress;
    view->dllBase = target.dllBase;
    view->sizeOfImage = target.sizeOfImage;
    status = kswordArkDriverImageInspectLinkLocked(
        runtime,
        (PLIST_ENTRY)(ULONG_PTR)target.linkAddress,
        view);
    return status;
}

// Note: Read fields from the saved loader item for existing records and re-verify that the link matches the active layout.
NTSTATUS
kswordArkDriverImageInspectRecordLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _Out_ KswDriverImageLinkView* view
    )
{
    ULONGLONG dllBase = 0ULL;
    ULONG sizeOfImage = 0UL;
    ULONGLONG expectedLink = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || record == NULL || view == NULL ||
        record->loaderEntry == NULL || record->loaderLink == NULL ||
        runtime->resourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(view, sizeof(*view));
    // Note: The saved link must still equal the loader base address plus the runtime validation offset.
    expectedLink = (ULONGLONG)(ULONG_PTR)record->loaderEntry +
        (ULONGLONG)runtime->dynState.kernel.kldrInLoadOrderLinks;
    if (expectedLink != (ULONGLONG)(ULONG_PTR)record->loaderLink) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // Note: KLDR field addresses come from active DynData; chain writing is skipped if read fails.
    if (!kswordArkDriverImageReadMemory(
            (const UCHAR*)record->loaderEntry +
                runtime->dynState.kernel.kldrDllBase,
            &dllBase,
            sizeof(dllBase)) ||
        !kswordArkDriverImageReadMemory(
            (const UCHAR*)record->loaderEntry +
                runtime->dynState.kernel.kldrSizeOfImage,
            &sizeOfImage,
            sizeof(sizeOfImage))) {
        return STATUS_ACCESS_VIOLATION;
    }
    view->loaderAvailable = TRUE;
    view->entryAddress = (ULONGLONG)(ULONG_PTR)record->loaderEntry;
    view->linkAddress = (ULONGLONG)(ULONG_PTR)record->loaderLink;
    view->dllBase = dllBase;
    view->sizeOfImage = sizeOfImage;
    status = kswordArkDriverImageInspectLinkLocked(
        runtime,
        record->loaderLink,
        view);
    return status;
}

// Note: Unlinking is performed while holding exclusive system resources, and the target is verified to be self-looped before returning.
NTSTATUS
kswordArkDriverImageHideLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ PLIST_ENTRY expectedFlink,
    _In_ PLIST_ENTRY expectedBlink,
    _Out_ BOOLEAN* changed
    )
{
    KswDriverImageLinkView beforeView;
    KswDriverImageLinkView afterView;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || record == NULL || changed == NULL ||
        runtime->resourceAcquired == FALSE ||
        runtime->resourceExclusive == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *changed = FALSE;
    RtlZeroMemory(&beforeView, sizeof(beforeView));
    RtlZeroMemory(&afterView, sizeof(afterView));
    status = kswordArkDriverImageInspectRecordLinkLocked(
        runtime,
        record,
        &beforeView);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Note: When the transaction already owns the self-loop, HIDE is idempotent and succeeds without rewriting neighbors.
    if (beforeView.selfLinked != FALSE && record->linkOwned != FALSE) {
        return STATUS_SUCCESS;
    }
    if (beforeView.inList == FALSE || beforeView.malformed != FALSE ||
        beforeView.flink != expectedFlink ||
        beforeView.blink != expectedBlink) {
        return STATUS_RETRY;
    }

    // Note: On the first unlink, save the exact original neighbors; subsequent restoration prioritizes using this location.
    record->originalLinkFlink = beforeView.flink;
    record->originalLinkBlink = beforeView.blink;
    __try {
        // Note: RemoveEntryList modifies only adjacent nodes; InitializeListHead explicitly marks hidden ownership.
        (VOID)RemoveEntryList(record->loaderLink);
        InitializeListHead(record->loaderLink);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        record->linkConflict = TRUE;
        return GetExceptionCode();
    }
    status = kswordArkDriverImageInspectRecordLinkLocked(
        runtime,
        record,
        &afterView);
    if (!NT_SUCCESS(status) || afterView.selfLinked == FALSE ||
        afterView.inList != FALSE) {
        record->linkConflict = TRUE;
        return NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
    }
    record->linkManaged = TRUE;
    record->linkOwned = TRUE;
    record->linkConflict = FALSE;
    *changed = TRUE;
    return STATUS_SUCCESS;
}

// Note: Check if the candidate neighbor is still in the locked main chain and return its current LIST_ENTRY snapshot.
static BOOLEAN
kswordArkDriverImageFindLiveLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ PLIST_ENTRY candidate,
    _Out_ LIST_ENTRY* snapshot
    )
{
    LIST_ENTRY headSnapshot;
    PLIST_ENTRY current = NULL;
    ULONG visited = 0UL;

    if (runtime == NULL || candidate == NULL || snapshot == NULL ||
        runtime->resourceAcquired == FALSE) {
        return FALSE;
    }
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    if (!kswordArkDriverImageReadMemory(
            runtime->listHead,
            &headSnapshot,
            sizeof(headSnapshot))) {
        return FALSE;
    }
    // Note: The list head itself is a valid recovery neighbor; directly return its locked snapshot.
    if (candidate == runtime->listHead) {
        *snapshot = headSnapshot;
        return TRUE;
    }
    current = headSnapshot.Flink;
    while (current != NULL && current != runtime->listHead &&
        visited < KSW_DRIVER_IMAGE_LIST_WALK_LIMIT) {
        LIST_ENTRY currentSnapshot;

        RtlZeroMemory(&currentSnapshot, sizeof(currentSnapshot));
        if (!kswordArkDriverImageReadMemory(
                current,
                &currentSnapshot,
                sizeof(currentSnapshot))) {
            return FALSE;
        }
        if (current == candidate) {
            *snapshot = currentSnapshot;
            return TRUE;
        }
        current = currentSnapshot.Flink;
        ++visited;
    }
    return FALSE;
}

// Note: The insertion function writes four pointers under exclusive resource ownership and converts exceptions into diagnosable states.
static NTSTATUS
kswordArkDriverImageInsertBetweenLocked(
    _In_ PLIST_ENTRY link,
    _In_ PLIST_ENTRY previous,
    _In_ PLIST_ENTRY next
    )
{
    if (link == NULL || previous == NULL || next == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        // Note: Prepare the target item first, then publish forward and backward neighbors; reader threads under the resource lock will not see a partially constructed state.
        link->Blink = previous;
        link->Flink = next;
        previous->Flink = link;
        next->Blink = link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// Note: Restore chain membership; use the current chain tail if the original neighbor no longer exists, never writing to an invalid old neighbor.
NTSTATUS
kswordArkDriverImageRestoreLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* changed,
    _Out_ BOOLEAN* originalPosition
    )
{
    KswDriverImageLinkView beforeView;
    KswDriverImageLinkView afterView;
    LIST_ENTRY previousSnapshot;
    LIST_ENTRY nextSnapshot;
    LIST_ENTRY headSnapshot;
    LIST_ENTRY tailSnapshot;
    PLIST_ENTRY previous = NULL;
    PLIST_ENTRY next = NULL;
    PLIST_ENTRY tail = NULL;
    BOOLEAN useOriginalPosition = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || record == NULL || changed == NULL ||
        originalPosition == NULL || runtime->resourceAcquired == FALSE ||
        runtime->resourceExclusive == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *changed = FALSE;
    *originalPosition = FALSE;
    RtlZeroMemory(&beforeView, sizeof(beforeView));
    RtlZeroMemory(&afterView, sizeof(afterView));
    RtlZeroMemory(&previousSnapshot, sizeof(previousSnapshot));
    RtlZeroMemory(&nextSnapshot, sizeof(nextSnapshot));
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    RtlZeroMemory(&tailSnapshot, sizeof(tailSnapshot));

    status = kswordArkDriverImageInspectRecordLinkLocked(
        runtime,
        record,
        &beforeView);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Note: Do not re-insert if already in the main chain; the caller determines external recovery or conflict based on the current position.
    if (beforeView.inList != FALSE) {
        return STATUS_SUCCESS;
    }
    if (beforeView.selfLinked == FALSE || record->linkOwned == FALSE ||
        record->originalLinkFlink == NULL ||
        record->originalLinkBlink == NULL) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    // Note: Only write back to the original position if both the original previous and next neighbors remain in the main chain and are adjacent to each other.
    previous = record->originalLinkBlink;
    next = record->originalLinkFlink;
    if (kswordArkDriverImageFindLiveLinkLocked(
            runtime,
            previous,
            &previousSnapshot) &&
        kswordArkDriverImageFindLiveLinkLocked(
            runtime,
            next,
            &nextSnapshot) &&
        previousSnapshot.Flink == next &&
        nextSnapshot.Blink == previous) {
        useOriginalPosition = TRUE;
    }
    if (useOriginalPosition == FALSE) {
        // Note: Old neighbors may have unloaded; only obtain the protected valid tail node from the current chain head.
        if (!kswordArkDriverImageReadMemory(
                runtime->listHead,
                &headSnapshot,
                sizeof(headSnapshot)) ||
            headSnapshot.Blink == NULL) {
            return STATUS_DATA_ERROR;
        }
        tail = headSnapshot.Blink;
        if (!kswordArkDriverImageFindLiveLinkLocked(
                runtime,
                tail,
                &tailSnapshot) ||
            tailSnapshot.Flink != runtime->listHead) {
            return STATUS_DATA_ERROR;
        }
        previous = tail;
        next = runtime->listHead;
    }

    status = kswordArkDriverImageInsertBetweenLocked(
        record->loaderLink,
        previous,
        next);
    if (!NT_SUCCESS(status)) {
        record->linkConflict = TRUE;
        return status;
    }
    status = kswordArkDriverImageInspectRecordLinkLocked(
        runtime,
        record,
        &afterView);
    if (!NT_SUCCESS(status) || afterView.inList == FALSE ||
        afterView.selfLinked != FALSE) {
        record->linkConflict = TRUE;
        return NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
    }
    record->linkManaged = FALSE;
    record->linkOwned = FALSE;
    record->linkConflict = FALSE;
    *changed = TRUE;
    *originalPosition = useOriginalPosition;
    return STATUS_SUCCESS;
}
