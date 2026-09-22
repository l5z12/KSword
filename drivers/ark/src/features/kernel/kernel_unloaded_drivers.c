/*++

Module Name:

    kernel_unloaded_drivers.c

Abstract:

    Read-only MmUnloadedDrivers, PiDDBCacheTable, and CI kernel-hash cache
    enumeration backed by identity-matched DynData/PDB layouts.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include "kernel_unloaded_drivers.h"
#include "ci_hash_fallback.h"
#include "ark/ark_dyndata.h"
#include "../dyndata/dyndata_v4_internal.h"
#include "../../platform/kernel_object_probe.h"

#define KSW_MM_UNLOADED_DRIVER_SLOTS 50UL
#define KSW_UNLOADED_DRIVER_MAX_ENTRY_BYTES 4096UL
#define KSW_UNLOADED_DRIVER_HARD_WALK_LIMIT 4096UL

typedef struct KswUnloadedQueryContext
{
    KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* response;
    ULONG maxRows;
} KswUnloadedQueryContext;

static BOOLEAN
kswordArkUnloadedDynDataSourceIsTrusted(
    _In_ ULONG source
    )
{
    return source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
        source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN;
}

typedef struct KswMmUnloadedLayout
{
    PVOID records;
    ULONG recordSize;
    ULONG nameOffset;
    ULONG startAddressOffset;
    ULONG endAddressOffset;
    ULONG currentTimeOffset;
} KswMmUnloadedLayout;

typedef struct KswPiddbQueryLayout
{
    PRTL_AVL_TABLE table;
    PERESOURCE lock;
    ULONG driverNameOffset;
    ULONG timeDateStampOffset;
    ULONG loadStatusOffset;
    ULONG entrySize;
} KswPiddbQueryLayout;

static BOOLEAN
kswordArkUnloadedRvaToAddress(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _In_ ULONG rva,
    _In_ SIZE_T requiredBytes,
    _Out_ ULONGLONG* addressOut
    )
/*++

Routine Description:

    Convert one identity-matched module RVA into a bounded live kernel address.

Return Value:

    TRUE when the complete requested range lies inside the current image.

--*/
{
    if (identity == NULL || addressOut == NULL ||
        identity->present == 0UL || identity->imageBase == 0ULL ||
        identity->sizeOfImage == 0UL || rva == 0UL ||
        rva == KSW_DYN_OFFSET_UNAVAILABLE || rva >= identity->sizeOfImage ||
        requiredBytes > (SIZE_T)(identity->sizeOfImage - rva) ||
        identity->imageBase > (~0ULL - rva)) {
        return FALSE;
    }

    *addressOut = identity->imageBase + rva;
    return TRUE;
}

static BOOLEAN
kswordArkUnloadedCopyName(
    _In_ const UNICODE_STRING* source,
    _Inout_ KSWORD_ARK_UNLOADED_DRIVER_ROW* row
    )
/*++

Routine Description:

    Copy one separately allocated kernel UNICODE_STRING into the fixed protocol
    row under guarded reads. Note: Names that are too long are
    safely truncated; no bytes beyond MaximumLength are read.

Return Value:

    TRUE when a non-empty, even-length name was copied.

--*/
{
    ULONG copyBytes = 0UL;

    if (source == NULL || row == NULL || source->Buffer == NULL ||
        source->Length == 0U || source->Length > source->MaximumLength ||
        (source->Length & (sizeof(WCHAR) - 1U)) != 0U) {
        return FALSE;
    }

    copyBytes = min(
        (ULONG)source->Length,
        (ULONG)((KSWORD_ARK_UNLOADED_DRIVER_NAME_CHARS - 1U) * sizeof(WCHAR)));
    __try {
        RtlCopyMemory(row->driverName, source->Buffer, copyBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(row->driverName, sizeof(row->driverName));
        return FALSE;
    }

    row->driverName[copyBytes / sizeof(WCHAR)] = L'\0';
    row->nameLengthBytes = copyBytes;
    row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME;
    return TRUE;
}

static VOID
kswordArkUnloadedAppendRow(
    _Inout_ KswUnloadedQueryContext* context,
    _In_ const KSWORD_ARK_UNLOADED_DRIVER_ROW* row
    )
/*++

Routine Description:

    Count one valid source row and copy it only while the caller's bounded
    output budget still has capacity.

Return Value:

    None.

--*/
{
    KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* response = NULL;

    if (context == NULL || context->response == NULL || row == NULL) {
        return;
    }
    response = context->response;
    response->totalRows += 1UL;
    if (response->returnedRows >= context->maxRows) {
        response->responseFlags |=
            KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED;
        return;
    }

    response->rows[response->returnedRows] = *row;
    response->returnedRows += 1UL;
}

static VOID
kswordArkUnloadedSkipInvalidRow(
    _Inout_ KswUnloadedQueryContext* context,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Record one unreadable source entry without aborting the remainder of the
    bounded snapshot.

Return Value:

    None.

--*/
{
    if (context == NULL || context->response == NULL) {
        return;
    }
    context->response->skippedRows += 1UL;
    context->response->responseFlags |=
        KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SKIPPED_INVALID_ROW;
    context->response->queryStatus =
        KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL;
    context->response->lastStatus = status;
}

static NTSTATUS
kswordArkUnloadedResolveMmLayout(
    _Out_ KswMmUnloadedLayout* layout
    )
/*++

Routine Description:

    Resolve the MmUnloadedDrivers pointer and exact _UNLOADED_DRIVERS member
    layout from the active ntoskrnl PDB profile.

Return Value:

    STATUS_SUCCESS, STATUS_DEVICE_NOT_READY for no active profile, or
    STATUS_NOT_SUPPORTED for an incomplete/invalid layout.

--*/
{
    KswDynState state;
    ULONGLONG recordsPointerAddress = 0ULL;
    PVOID records = NULL;

    if (layout == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layout, sizeof(*layout));
    RtlZeroMemory(&state, sizeof(state));
    kswordArkDynDataSnapshot(&state);

    if (!state.ntosActive) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.uldName) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.uldStartAddress) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.uldEndAddress) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.uldCurrentTime) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.uldTypeSize) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelGlobalSources.mmUnloadedDrivers) ||
        state.kernel.uldName == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.uldStartAddress == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.uldEndAddress == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.uldCurrentTime == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.uldTypeSize == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.uldTypeSize < sizeof(UNICODE_STRING) ||
        state.kernel.uldTypeSize > KSW_UNLOADED_DRIVER_MAX_ENTRY_BYTES ||
        state.kernel.uldName > state.kernel.uldTypeSize - sizeof(UNICODE_STRING) ||
        state.kernel.uldStartAddress > state.kernel.uldTypeSize - sizeof(PVOID) ||
        state.kernel.uldEndAddress > state.kernel.uldTypeSize - sizeof(PVOID) ||
        state.kernel.uldCurrentTime > state.kernel.uldTypeSize - sizeof(LARGE_INTEGER)) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkUnloadedRvaToAddress(
            &state.ntoskrnl,
            state.kernelGlobals.mmUnloadedDrivers,
            sizeof(PVOID),
            &recordsPointerAddress)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        records = *(PVOID*)(ULONG_PTR)recordsPointerAddress;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (records == NULL) {
        return STATUS_NOT_FOUND;
    }
    layout->records = records;
    layout->recordSize = state.kernel.uldTypeSize;
    layout->nameOffset = state.kernel.uldName;
    layout->startAddressOffset = state.kernel.uldStartAddress;
    layout->endAddressOffset = state.kernel.uldEndAddress;
    layout->currentTimeOffset = state.kernel.uldCurrentTime;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkUnloadedReadMmRow(
    _In_ const KswMmUnloadedLayout* layout,
    _In_ ULONG index,
    _Out_ KSWORD_ARK_UNLOADED_DRIVER_ROW* row
    )
/*++

Routine Description:

    Read one fixed MmUnloadedDrivers slot using only PDB-bounded offsets.

Return Value:

    TRUE for a populated row; FALSE for empty or unreadable slots.

--*/
{
    const UCHAR* record = NULL;
    UNICODE_STRING name;
    PVOID startAddress = NULL;
    PVOID endAddress = NULL;
    LARGE_INTEGER currentTime;

    if (layout == NULL || row == NULL ||
        index >= KSW_MM_UNLOADED_DRIVER_SLOTS) {
        return FALSE;
    }
    RtlZeroMemory(row, sizeof(*row));
    RtlZeroMemory(&name, sizeof(name));
    RtlZeroMemory(&currentTime, sizeof(currentTime));
    record = (const UCHAR*)layout->records +
        ((SIZE_T)index * layout->recordSize);

    __try {
        RtlCopyMemory(&name, record + layout->nameOffset, sizeof(name));
        RtlCopyMemory(
            &startAddress,
            record + layout->startAddressOffset,
            sizeof(startAddress));
        RtlCopyMemory(
            &endAddress,
            record + layout->endAddressOffset,
            sizeof(endAddress));
        RtlCopyMemory(
            &currentTime,
            record + layout->currentTimeOffset,
            sizeof(currentTime));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (!kswordArkUnloadedCopyName(&name, row)) {
        return FALSE;
    }

    row->source = KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS;
    row->entryAddress = (ULONGLONG)(ULONG_PTR)record;
    if (startAddress != NULL) {
        row->baseAddress = (ULONGLONG)(ULONG_PTR)startAddress;
        row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE;
    }
    if ((ULONG_PTR)endAddress > (ULONG_PTR)startAddress) {
        row->imageSize =
            (ULONGLONG)((ULONG_PTR)endAddress - (ULONG_PTR)startAddress);
        row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE;
    }
    if (currentTime.QuadPart != 0LL) {
        row->unloadTime = (ULONGLONG)currentTime.QuadPart;
        row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME;
    }
    return TRUE;
}

static NTSTATUS
kswordArkUnloadedEnumerateMm(
    _Inout_ KswUnloadedQueryContext* context
    )
/*++

Routine Description:

    enumerate all 50 bounded MmUnloadedDrivers slots. The undocumented writer
    lock is intentionally not guessed; guarded reads report a racy partial
    snapshot when a slot changes concurrently.

Return Value:

    Semantic enumeration status.

--*/
{
    KswMmUnloadedLayout layout;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;

    RtlZeroMemory(&layout, sizeof(layout));
    status = kswordArkUnloadedResolveMmLayout(&layout);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context->response->responseFlags |=
        KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SNAPSHOT_RACY;
    for (index = 0UL; index < KSW_MM_UNLOADED_DRIVER_SLOTS; ++index) {
        KSWORD_ARK_UNLOADED_DRIVER_ROW row;

        RtlZeroMemory(&row, sizeof(row));
        if (kswordArkUnloadedReadMmRow(&layout, index, &row)) {
            kswordArkUnloadedAppendRow(context, &row);
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkUnloadedResolvePiDdbLayout(
    _Out_ KswPiddbQueryLayout* layout
    )
/*++

Routine Description:

    Resolve the PiDDB AVL table, its ERESOURCE, and exact entry field offsets
    from the identity-matched ntoskrnl profile.

Return Value:

    STATUS_SUCCESS or a readable profile/layout status.

--*/
{
    KswDynState state;
    ULONGLONG tableAddress = 0ULL;
    ULONGLONG lockAddress = 0ULL;

    if (layout == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layout, sizeof(*layout));
    RtlZeroMemory(&state, sizeof(state));
    kswordArkDynDataSnapshot(&state);

    if (!state.ntosActive) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.piDdbDriverName) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.piDdbTimeDateStamp) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.piDdbLoadStatus) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelSources.piDdbTypeSize) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelGlobalSources.piDdbCacheTable) ||
        !kswordArkUnloadedDynDataSourceIsTrusted(
            state.kernelGlobalSources.piDdbLock) ||
        state.kernel.piDdbDriverName == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTimeDateStamp == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbLoadStatus == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTypeSize == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTypeSize < sizeof(UNICODE_STRING) ||
        state.kernel.piDdbTypeSize > KSW_UNLOADED_DRIVER_MAX_ENTRY_BYTES ||
        state.kernel.piDdbDriverName >
            state.kernel.piDdbTypeSize - sizeof(UNICODE_STRING) ||
        state.kernel.piDdbTimeDateStamp >
            state.kernel.piDdbTypeSize - sizeof(ULONG) ||
        state.kernel.piDdbLoadStatus >
            state.kernel.piDdbTypeSize - sizeof(NTSTATUS)) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkUnloadedRvaToAddress(
            &state.ntoskrnl,
            state.kernelGlobals.piDdbCacheTable,
            sizeof(RTL_AVL_TABLE),
            &tableAddress) ||
        !kswordArkUnloadedRvaToAddress(
            &state.ntoskrnl,
            state.kernelGlobals.piDdbLock,
            sizeof(ERESOURCE),
            &lockAddress)) {
        return STATUS_NOT_SUPPORTED;
    }

    layout->table = (PRTL_AVL_TABLE)(ULONG_PTR)tableAddress;
    layout->lock = (PERESOURCE)(ULONG_PTR)lockAddress;
    layout->driverNameOffset = state.kernel.piDdbDriverName;
    layout->timeDateStampOffset = state.kernel.piDdbTimeDateStamp;
    layout->loadStatusOffset = state.kernel.piDdbLoadStatus;
    layout->entrySize = state.kernel.piDdbTypeSize;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkUnloadedReadPiDdbRow(
    _In_ const KswPiddbQueryLayout* layout,
    _In_ PVOID entry,
    _Out_ KSWORD_ARK_UNLOADED_DRIVER_ROW* row
    )
/*++

Routine Description:

    Project one AVL element into the unified read-only row.

Return Value:

    TRUE when every required PiDDB field was readable.

--*/
{
    UNICODE_STRING name;

    if (layout == NULL || entry == NULL || row == NULL) {
        return FALSE;
    }
    RtlZeroMemory(row, sizeof(*row));
    RtlZeroMemory(&name, sizeof(name));

    __try {
        RtlCopyMemory(
            &name,
            (const UCHAR*)entry + layout->driverNameOffset,
            sizeof(name));
        RtlCopyMemory(
            &row->timeDateStamp,
            (const UCHAR*)entry + layout->timeDateStampOffset,
            sizeof(row->timeDateStamp));
        RtlCopyMemory(
            &row->loadStatus,
            (const UCHAR*)entry + layout->loadStatusOffset,
            sizeof(row->loadStatus));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    if (!kswordArkUnloadedCopyName(&name, row)) {
        return FALSE;
    }

    row->source = KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE;
    row->entryAddress = (ULONGLONG)(ULONG_PTR)entry;
    row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP |
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS;
    return TRUE;
}

static NTSTATUS
kswordArkUnloadedEnumeratePiDdb(
    _Inout_ KswUnloadedQueryContext* context
    )
/*++

Routine Description:

    Traverse PiDDB with RtlEnumerateGenericTableWithoutSplayingAvl while holding
    the exact PDB-resolved resource shared. No table field is changed.

Return Value:

    Semantic enumeration status.

--*/
{
    KswPiddbQueryLayout layout;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID restartKey = NULL;
    PVOID entry = NULL;
    ULONG walkedRows = 0UL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    status = kswordArkUnloadedResolvePiDdbLayout(&layout);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Note: The RVA may originate from runtime heuristic resolution; the lock must be confirmed to be a resource before acquiring it.
    if (!kswordArkKernelProbeResourceIsSystemResource((ULONG_PTR)layout.lock)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(layout.lock, TRUE)) {
        KeLeaveCriticalRegion();
        return STATUS_LOCK_NOT_GRANTED;
    }

    __try {
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.table,
                    &restartKey)) != NULL) {
            KSWORD_ARK_UNLOADED_DRIVER_ROW row;

            // Do not let corrupted AVL metadata cause unbounded enumeration in a read-only query. At the hard
            // limit, retain the rows already retrieved and explicitly notify R3 through truncated/partial.
            if (walkedRows >= KSW_UNLOADED_DRIVER_HARD_WALK_LIMIT) {
                context->response->responseFlags |=
                    KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED;
                status = STATUS_BUFFER_OVERFLOW;
                break;
            }
            RtlZeroMemory(&row, sizeof(row));
            if (kswordArkUnloadedReadPiDdbRow(&layout, entry, &row)) {
                kswordArkUnloadedAppendRow(context, &row);
            }
            else {
                kswordArkUnloadedSkipInvalidRow(context, STATUS_DATA_ERROR);
            }
            walkedRows += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ExReleaseResourceLite(layout.lock);
    KeLeaveCriticalRegion();
    return status;
}

static BOOLEAN
kswordArkUnloadedReadCiHashRow(
    _In_ const KswDynV4CiKernelHashLayout* layout,
    _In_ PVOID entry,
    _Out_ PVOID* nextEntryOut,
    _Out_ KSWORD_ARK_UNLOADED_DRIVER_ROW* row
    )
/*++

Routine Description:

    Read one CI hash entry using the PDB-reported singly linked Next and
    DriverName offsets. Optional diagnostic fields are sampled only when present.

Return Value:

    TRUE for a readable named entry.

--*/
{
    const UCHAR* entryBytes = NULL;
    UNICODE_STRING name;
    PVOID nextEntry = NULL;
    PVOID imageBase = NULL;
    ULONG imageSize = 0UL;

    if (layout == NULL || entry == NULL || nextEntryOut == NULL || row == NULL) {
        return FALSE;
    }
    RtlZeroMemory(row, sizeof(*row));
    RtlZeroMemory(&name, sizeof(name));
    *nextEntryOut = NULL;
    entryBytes = (const UCHAR*)entry;

    __try {
        RtlCopyMemory(
            &nextEntry,
            entryBytes + layout->entryNext,
            sizeof(nextEntry));
        RtlCopyMemory(
            &name,
            entryBytes + layout->entryDriverName,
            sizeof(name));
        if (layout->entryTimeDateStamp != KSW_DYN_OFFSET_UNAVAILABLE) {
            RtlCopyMemory(
                &row->timeDateStamp,
                entryBytes + layout->entryTimeDateStamp,
                sizeof(row->timeDateStamp));
            row->flags |=
                KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP;
        }
        if (layout->entryLoadStatus != KSW_DYN_OFFSET_UNAVAILABLE) {
            RtlCopyMemory(
                &row->loadStatus,
                entryBytes + layout->entryLoadStatus,
                sizeof(row->loadStatus));
            row->flags |=
                KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS;
        }
        if (layout->entryImageBase != KSW_DYN_OFFSET_UNAVAILABLE) {
            RtlCopyMemory(
                &imageBase,
                entryBytes + layout->entryImageBase,
                sizeof(imageBase));
        }
        if (layout->entryImageSize != KSW_DYN_OFFSET_UNAVAILABLE) {
            RtlCopyMemory(
                &imageSize,
                entryBytes + layout->entryImageSize,
                sizeof(imageSize));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    if (!kswordArkUnloadedCopyName(&name, row)) {
        return FALSE;
    }

    row->source =
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST;
    row->entryAddress = (ULONGLONG)(ULONG_PTR)entry;
    if (imageBase != NULL) {
        row->baseAddress = (ULONGLONG)(ULONG_PTR)imageBase;
        row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE;
    }
    if (imageSize != 0UL) {
        row->imageSize = imageSize;
        row->flags |= KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE;
    }
    *nextEntryOut = nextEntry;
    return TRUE;
}

static NTSTATUS
kswordArkUnloadedEnumerateCiHash(
    _Inout_ KswUnloadedQueryContext* context
    )
/*++

Routine Description:

    Traverse the singly linked g_KernelHashBucketList under its CI resource. Both
    globals and every entry offset come from an identity-checked v4 profile, or
    from the runtime resolver when no profile matches.  Either way the lock is
    proven to be a live ERESOURCE before it is acquired: this path blocks with
    Wait=TRUE and is reachable from an IOCTL, so a misidentified object would
    fault inside the kernel's lock path on every call.

Return Value:

    Semantic enumeration status.

--*/
{
    KswDynV4CiKernelHashLayout layout;
    PVOID listGlobal = NULL;
    PERESOURCE hashLock = NULL;
    PVOID current = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG walkedRows = 0UL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    status = kswordArkDynDataV4SnapshotCiKernelHashLayout(&layout);
    if (!NT_SUCCESS(status)) {
        status = kswordArkCiHashResolveRuntimeLayout(&layout);
        if (!NT_SUCCESS(status)) {
            return STATUS_REVISION_MISMATCH;
        }
    }
    listGlobal = (PVOID)(ULONG_PTR)(
        layout.moduleBase + layout.kernelHashBucketListRva);
    hashLock = (PERESOURCE)(ULONG_PTR)(
        layout.moduleBase + layout.hashCacheLockRva);
    if (!kswordArkKernelProbeResourceIsSystemResource((ULONG_PTR)hashLock)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(hashLock, TRUE)) {
        KeLeaveCriticalRegion();
        return STATUS_LOCK_NOT_GRANTED;
    }
    __try {
        current = *(PVOID*)listGlobal;
        while (current != NULL) {
            PVOID nextEntry = NULL;
            KSWORD_ARK_UNLOADED_DRIVER_ROW row;

            if (walkedRows >= KSW_UNLOADED_DRIVER_HARD_WALK_LIMIT) {
                context->response->responseFlags |=
                    KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED;
                status = STATUS_BUFFER_OVERFLOW;
                break;
            }
            RtlZeroMemory(&row, sizeof(row));
            if (kswordArkUnloadedReadCiHashRow(
                    &layout,
                    current,
                    &nextEntry,
                    &row)) {
                kswordArkUnloadedAppendRow(context, &row);
            }
            else {
                kswordArkUnloadedSkipInvalidRow(context, STATUS_DATA_ERROR);
                status = STATUS_DATA_ERROR;
                break;
            }
            if (nextEntry == current) {
                status = STATUS_DATA_ERROR;
                break;
            }
            current = nextEntry;
            walkedRows += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    ExReleaseResourceLite(hashLock);
    KeLeaveCriticalRegion();
    return status;
}

static VOID
kswordArkUnloadedFinalizeResponse(
    _Inout_ KswUnloadedQueryContext* context,
    _In_ NTSTATUS enumerationStatus
    )
/*++

Routine Description:

    Convert one backend NTSTATUS into the stable semantic response while
    preserving an already-recorded partial-row diagnostic.

Return Value:

    None.

--*/
{
    KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* response = NULL;

    if (context == NULL || context->response == NULL) {
        return;
    }
    response = context->response;

    // When output capacity is 0 or the backend hits the hard traversal limit, a clear partial/truncated
    // semantics must be returned even if no rows were copied; do not misreport this as a standard read failure.
    if ((response->responseFlags &
            KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL;
        response->lastStatus = NT_SUCCESS(enumerationStatus)
            ? STATUS_BUFFER_OVERFLOW
            : enumerationStatus;
        return;
    }

    if (NT_SUCCESS(enumerationStatus)) {
        if (response->queryStatus !=
            KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL) {
            response->queryStatus =
                (response->responseFlags &
                    KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED) != 0UL
                ? KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL
                : KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK;
            response->lastStatus = STATUS_SUCCESS;
        }
        return;
    }

    response->lastStatus = enumerationStatus;
    if (enumerationStatus == STATUS_DEVICE_NOT_READY) {
        response->queryStatus =
            KSWORD_ARK_UNLOADED_DRIVER_STATUS_DYNDATA_UNAVAILABLE;
    }
    else if (enumerationStatus == STATUS_REVISION_MISMATCH) {
        response->queryStatus =
            KSWORD_ARK_UNLOADED_DRIVER_STATUS_MODULE_PROFILE_UNAVAILABLE;
    }
    else if (enumerationStatus == STATUS_NOT_SUPPORTED) {
        response->queryStatus =
            KSWORD_ARK_UNLOADED_DRIVER_STATUS_LAYOUT_UNAVAILABLE;
    }
    else if (response->returnedRows != 0UL) {
        response->queryStatus = KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL;
    }
    else {
        response->queryStatus =
            KSWORD_ARK_UNLOADED_DRIVER_STATUS_READ_FAILED;
    }
}

NTSTATUS
kswordArkQueryUnloadedDrivers(
    _In_ const KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWritten)
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* response,
    _In_ SIZE_T outputBufferLength,
    _Out_ SIZE_T* bytesWritten
    )
/*++

Routine Description:

    Validate the variable-row protocol, dispatch one of the three read-only
    sources, and always return a bounded semantic response.

Return Value:

    STATUS_SUCCESS after writing a semantic response; invalid output buffers
    return transport errors.

--*/
{
    KswUnloadedQueryContext context;
    ULONG rowCapacity = 0UL;
    ULONG requestedRows = 0UL;
    SIZE_T rowCapacitySize = 0U;
    NTSTATUS enumerationStatus = STATUS_SUCCESS;

    if (request == NULL || response == NULL || bytesWritten == NULL ||
        outputBufferLength <
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWritten = 0U;
    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_UNLOADED_DRIVER_PROTOCOL_VERSION;
    response->size =
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE;
    response->rowSize = sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW);
    response->source = request->source;
    response->queryStatus =
        KSWORD_ARK_UNLOADED_DRIVER_STATUS_INVALID_REQUEST;
    response->lastStatus = STATUS_INVALID_PARAMETER;

    if (request->version != KSWORD_ARK_UNLOADED_DRIVER_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->flags != 0UL ||
        request->reserved != 0UL ||
        (request->source !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS &&
         request->source !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE &&
         request->source !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST)) {
        *bytesWritten =
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    rowCapacitySize =
        (outputBufferLength -
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW);
    rowCapacity = rowCapacitySize > KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS
        ? KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS
        : (ULONG)rowCapacitySize;
    requestedRows = request->maxRows == 0UL
        ? KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS
        : min(request->maxRows, KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS);
    RtlZeroMemory(&context, sizeof(context));
    context.response = response;
    context.maxRows = min(rowCapacity, requestedRows);

    switch (request->source) {
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS:
        enumerationStatus = kswordArkUnloadedEnumerateMm(&context);
        break;
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE:
        enumerationStatus = kswordArkUnloadedEnumeratePiDdb(&context);
        break;
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST:
        enumerationStatus = kswordArkUnloadedEnumerateCiHash(&context);
        break;
    default:
        enumerationStatus = STATUS_INVALID_PARAMETER;
        break;
    }

    kswordArkUnloadedFinalizeResponse(&context, enumerationStatus);
    *bytesWritten =
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE +
        ((SIZE_T)response->returnedRows *
            sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW));
    response->size = (ULONG)*bytesWritten;
    return STATUS_SUCCESS;
}
