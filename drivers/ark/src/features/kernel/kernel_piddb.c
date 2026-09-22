/*++

Module Name:

    kernel_piddb.c

Abstract:

    Exact PDB-layout-gated PiDDB cache enumeration and identity-bound removal.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include "kernel_piddb.h"
#include "ark/ark_dyndata.h"
#include "../../platform/kernel_object_probe.h"
#include "../../platform/pool_compat.h"

#define KSW_PIDDB_POOL_TAG 'bDiP'
#define KSW_PIDDB_MAX_ENTRY_BYTES 4096UL
#define KSW_PIDDB_HARD_WALK_LIMIT 4096UL

typedef struct KswPiddbLayout
{
    PRTL_AVL_TABLE table;
    PERESOURCE lock;
    ULONG driverNameOffset;
    ULONG timeDateStampOffset;
    ULONG loadStatusOffset;
    ULONG entrySize;
} KswPiddbLayout, *PkswPiddbLayout;

static BOOLEAN
kswordArkPiDdbSourceIsTrusted(
    _In_ ULONG source
    )
{
    return source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
        source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN;
}

static SIZE_T
kswordArkPiDdbBoundedWideLength(
    _In_reads_(capacity) const WCHAR* text,
    _In_ SIZE_T capacity
    )
{
    SIZE_T index = 0U;

    /* Walk only the fixed protocol array and never depend on kernel CRT helpers. */
    if (text == NULL) {
        return capacity;
    }
    for (index = 0U; index < capacity; ++index) {
        if (text[index] == L'\0') {
            return index;
        }
    }
    return capacity;
}

static BOOLEAN
kswordArkPiDdbRvaToAddress(
    _In_ const KswDynState* state,
    _In_ ULONG rva,
    _In_ SIZE_T requiredBytes,
    _Out_ ULONGLONG* addressOut
    )
{
    ULONGLONG imageBase = 0ULL;
    ULONG imageSize = 0UL;

    /* Reject absent state, unavailable sentinels, and missing image identity. */
    if (state == NULL || addressOut == NULL ||
        rva == 0UL || rva == KSW_DYN_OFFSET_UNAVAILABLE) {
        return FALSE;
    }
    imageBase = state->ntoskrnl.imageBase;
    imageSize = state->ntoskrnl.sizeOfImage;
    if (imageBase == 0ULL || imageSize == 0UL ||
        rva >= imageSize || requiredBytes > imageSize - rva) {
        return FALSE;
    }

    /* Derive the live address only from the identity-matched ntoskrnl base. */
    *addressOut = imageBase + rva;
    return TRUE;
}

static BOOLEAN
kswordArkPiDdbResolveLayout(
    _Out_ KswPiddbLayout* layout
    )
{
    KswDynState state;
    ULONGLONG tableAddress = 0ULL;
    ULONGLONG lockAddress = 0ULL;

    /* Snapshot DynData so no consumer retains pointers into mutable state. */
    if (layout == NULL) {
        return FALSE;
    }
    RtlZeroMemory(layout, sizeof(*layout));
    RtlZeroMemory(&state, sizeof(state));
    kswordArkDynDataSnapshot(&state);

    /*
     * Prefer the exact PDB profile, but also accept the runtime resolver only
     * after its unique export-anchored candidate and live AVL/resource checks.
     */
    if (!state.ntosActive ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelSources.piDdbDriverName) ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelSources.piDdbTimeDateStamp) ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelSources.piDdbLoadStatus) ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelSources.piDdbTypeSize) ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelGlobalSources.piDdbCacheTable) ||
        !kswordArkPiDdbSourceIsTrusted(
            state.kernelGlobalSources.piDdbLock) ||
        state.kernel.piDdbDriverName == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTimeDateStamp == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbLoadStatus == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTypeSize == KSW_DYN_OFFSET_UNAVAILABLE ||
        state.kernel.piDdbTypeSize < sizeof(UNICODE_STRING) ||
        state.kernel.piDdbTypeSize > KSW_PIDDB_MAX_ENTRY_BYTES) {
        return FALSE;
    }

    /* Bound every member inside the exact or runtime-validated entry size. */
    if (state.kernel.piDdbDriverName >
            state.kernel.piDdbTypeSize - sizeof(UNICODE_STRING) ||
        state.kernel.piDdbTimeDateStamp >
            state.kernel.piDdbTypeSize - sizeof(ULONG) ||
        state.kernel.piDdbLoadStatus >
            state.kernel.piDdbTypeSize - sizeof(NTSTATUS)) {
        return FALSE;
    }

    /* Both the AVL table and its ERESOURCE must come from validated RVAs. */
    if (!kswordArkPiDdbRvaToAddress(
            &state,
            state.kernelGlobals.piDdbCacheTable,
            sizeof(RTL_AVL_TABLE),
            &tableAddress) ||
        !kswordArkPiDdbRvaToAddress(
            &state,
            state.kernelGlobals.piDdbLock,
            sizeof(ERESOURCE),
            &lockAddress)) {
        return FALSE;
    }

    /*
     * PiDdb sources include the runtime resolver, whose lock RVA comes from a
     * heuristic scan.  Both callers acquire this resource and block, so prove
     * the object is on the global resource list before publishing it.
     */
    if (!kswordArkKernelProbeResourceIsSystemResource((ULONG_PTR)lockAddress)) {
        return FALSE;
    }

    /* Publish only a fully validated scalar layout. */
    layout->table = (PRTL_AVL_TABLE)(ULONG_PTR)tableAddress;
    layout->lock = (PERESOURCE)(ULONG_PTR)lockAddress;
    layout->driverNameOffset = state.kernel.piDdbDriverName;
    layout->timeDateStampOffset = state.kernel.piDdbTimeDateStamp;
    layout->loadStatusOffset = state.kernel.piDdbLoadStatus;
    layout->entrySize = state.kernel.piDdbTypeSize;
    return TRUE;
}

static BOOLEAN
kswordArkPiDdbReadEntry(
    _In_ const KswPiddbLayout* layout,
    _In_ PVOID entry,
    _Out_ KSWORD_ARK_PIDDB_ROW* row
    )
{
    UNICODE_STRING driverName;
    ULONG copyBytes = 0UL;

    /* Reject null pointers before guarded reads from the AVL element. */
    if (layout == NULL || entry == NULL || row == NULL) {
        return FALSE;
    }
    RtlZeroMemory(row, sizeof(*row));
    RtlZeroMemory(&driverName, sizeof(driverName));

    /* Read only PDB-bounded fields and the separately allocated name buffer. */
    __try {
        RtlCopyMemory(
            &driverName,
            (const UCHAR*)entry + layout->driverNameOffset,
            sizeof(driverName));
        RtlCopyMemory(
            &row->timeDateStamp,
            (const UCHAR*)entry + layout->timeDateStampOffset,
            sizeof(row->timeDateStamp));
        RtlCopyMemory(
            &row->loadStatus,
            (const UCHAR*)entry + layout->loadStatusOffset,
            sizeof(row->loadStatus));
        if (driverName.Length == 0U ||
            driverName.Buffer == NULL ||
            driverName.Length > driverName.MaximumLength ||
            (driverName.Length & (sizeof(WCHAR) - 1U)) != 0U) {
            return FALSE;
        }
        copyBytes = min(
            (ULONG)driverName.Length,
            (ULONG)((KSWORD_ARK_PIDDB_NAME_CHARS - 1U) * sizeof(WCHAR)));
        RtlCopyMemory(row->driverName, driverName.Buffer, copyBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(row, sizeof(*row));
        return FALSE;
    }

    /* Record the exact element identity and explicit copied name length. */
    row->entryAddress = (ULONGLONG)(ULONG_PTR)entry;
    row->nameLengthBytes = copyBytes;
    row->driverName[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN
kswordArkPiDdbRowMatchesRequest(
    _In_ const KSWORD_ARK_PIDDB_ROW* row,
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* request
    )
{
    UNICODE_STRING rowName;
    UNICODE_STRING requestedName;
    SIZE_T requestedChars = 0U;

    /* Bind removal to the exact address, timestamp, load status, and name. */
    if (row == NULL || request == NULL ||
        row->entryAddress != request->expectedEntryAddress ||
        row->timeDateStamp != request->expectedTimeDateStamp ||
        row->loadStatus != request->expectedLoadStatus) {
        return FALSE;
    }
    requestedChars = kswordArkPiDdbBoundedWideLength(
        request->driverName,
        KSWORD_ARK_PIDDB_NAME_CHARS);
    if (requestedChars == 0U ||
        requestedChars >= KSWORD_ARK_PIDDB_NAME_CHARS) {
        return FALSE;
    }
    RtlInitUnicodeString(&rowName, row->driverName);
    RtlInitUnicodeString(&requestedName, request->driverName);
    return RtlEqualUnicodeString(&rowName, &requestedName, TRUE);
}

NTSTATUS
kswordArkPiDdbQuery(
    _In_ const KSWORD_ARK_QUERY_PIDDB_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWritten)
        KSWORD_ARK_QUERY_PIDDB_RESPONSE* response,
    _In_ SIZE_T outputBufferLength,
    _Out_ SIZE_T* bytesWritten
    )
{
    KswPiddbLayout layout;
    ULONG maxRows = 0UL;
    ULONG rowCapacity = 0UL;
    PVOID entry = NULL;
    PVOID restartKey = NULL;
    ULONG walkedRows = 0UL;

    /* Validate the fixed header contract before writing variable rows. */
    if (request == NULL || response == NULL || bytesWritten == NULL ||
        outputBufferLength < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWritten = 0U;
    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
    response->size = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
    response->rowSize = sizeof(KSWORD_ARK_PIDDB_ROW);
    response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT;
    if (request->version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
        request->size != sizeof(*request)) {
        response->lastStatus = STATUS_INVALID_PARAMETER;
        *bytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    /* Bound output rows by both the request and the actual WDF buffer. */
    maxRows = request->maxRows == 0UL
        ? KSWORD_ARK_PIDDB_DEFAULT_ROWS
        : min(request->maxRows, KSWORD_ARK_PIDDB_MAX_ROWS);
    rowCapacity = (ULONG)(
        (outputBufferLength - KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PIDDB_ROW));
    maxRows = min(maxRows, rowCapacity);
    if (!kswordArkPiDdbResolveLayout(&layout)) {
        response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        *bytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    /*
     * Hold the exact internal resource while traversing the AVL table.  The
     * walk must not mutate it: RtlEnumerateGenericTableAvl writes RestartKey
     * and WhichOrderedElement into the table, and this resource is held only
     * shared, so concurrent readers would corrupt each other's traversal.  The
     * WithoutSplaying variant keeps its cursor in the caller's restartKey.
     */
    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(layout.lock, TRUE)) {
        KeLeaveCriticalRegion();
        response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_READ_FAILED;
        response->lastStatus = STATUS_LOCK_NOT_GRANTED;
        *bytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    __try {
        response->totalRows = RtlNumberGenericTableElementsAvl(layout.table);
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.table,
                    &restartKey)) != NULL) {
            KSWORD_ARK_PIDDB_ROW row;

            /* Damaged AVL metadata must not turn a read-only query endless. */
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                response->responseFlags |=
                    KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED;
                break;
            }
            walkedRows += 1UL;
            if (!kswordArkPiDdbReadEntry(&layout, entry, &row)) {
                response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL;
                response->lastStatus = STATUS_DATA_ERROR;
                continue;
            }
            if (response->returnedRows >= maxRows) {
                response->responseFlags |=
                    KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED;
                break;
            }
            response->rows[response->returnedRows] = row;
            response->returnedRows += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL;
        response->lastStatus = GetExceptionCode();
    }
    ExReleaseResourceLite(layout.lock);
    KeLeaveCriticalRegion();

    /* Preserve a partial status; otherwise report a complete bounded snapshot. */
    if (response->queryStatus != KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL) {
        response->queryStatus =
            (response->responseFlags &
                KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED) != 0UL
            ? KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL
            : KSWORD_ARK_PIDDB_QUERY_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }
    *bytesWritten = KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE +
        ((SIZE_T)response->returnedRows *
            sizeof(KSWORD_ARK_PIDDB_ROW));
    response->size = (ULONG)*bytesWritten;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkPiDdbDelete(
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* request,
    _Out_ KSWORD_ARK_DELETE_PIDDB_RESPONSE* response
    )
{
    KswPiddbLayout layout;
    PVOID entry = NULL;
    PVOID matchedEntry = NULL;
    PVOID entryCopy = NULL;
    PVOID restartKey = NULL;
    ULONG walkedRows = 0UL;
    KSWORD_ARK_PIDDB_ROW row = { 0 };
    BOOLEAN deleted = FALSE;
    BOOLEAN stillPresent = FALSE;

    /* initialize a semantic response before validating the mutation identity. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->status = KSWORD_ARK_PIDDB_DELETE_STATUS_INVALID_REQUEST;
    if (request->version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->confirmationToken !=
            KSWORD_ARK_PIDDB_DELETE_CONFIRMATION_TOKEN ||
        request->expectedEntryAddress == 0ULL ||
        kswordArkPiDdbBoundedWideLength(
            request->driverName,
            KSWORD_ARK_PIDDB_NAME_CHARS) >=
            KSWORD_ARK_PIDDB_NAME_CHARS) {
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!kswordArkPiDdbResolveLayout(&layout)) {
        response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DYNDATA_MISSING;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        return STATUS_SUCCESS;
    }

    /* Serialize identity lookup and deletion under the real PiDDB resource. */
    KeEnterCriticalRegion();
    if (!ExAcquireResourceExclusiveLite(layout.lock, TRUE)) {
        KeLeaveCriticalRegion();
        response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        response->lastStatus = STATUS_LOCK_NOT_GRANTED;
        return STATUS_SUCCESS;
    }
    __try {
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.table,
                    &restartKey)) != NULL) {
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                break;
            }
            walkedRows += 1UL;
            if (!kswordArkPiDdbReadEntry(&layout, entry, &row)) {
                continue;
            }
            if (kswordArkPiDdbRowMatchesRequest(&row, request)) {
                matchedEntry = entry;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->lastStatus = GetExceptionCode();
    }
    if (matchedEntry == NULL) {
        response->status = KSWORD_ARK_PIDDB_DELETE_STATUS_NOT_FOUND;
        if (response->lastStatus == STATUS_SUCCESS) {
            response->lastStatus = STATUS_NOT_FOUND;
        }
        ExReleaseResourceLite(layout.lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Copy matched identity into the response before any table-owned memory frees. */
    response->matchedEntryAddress = row.entryAddress;
    response->matchedTimeDateStamp = row.timeDateStamp;
    response->matchedLoadStatus = row.loadStatus;
    RtlCopyMemory(
        response->matchedDriverName,
        row.driverName,
        sizeof(response->matchedDriverName));

    /* A non-force call is a read-only preflight against the current AVL state. */
    if ((request->flags & KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE) == 0UL) {
        response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED;
        response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->remainingRows =
            RtlNumberGenericTableElementsAvl(layout.table);
        ExReleaseResourceLite(layout.lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Delete using a byte-for-byte key copy while the source entry is locked. */
    entryCopy = kswordArkAllocateNonPagedPool(
        layout.entrySize,
        KSW_PIDDB_POOL_TAG);
    if (entryCopy == NULL) {
        response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ExReleaseResourceLite(layout.lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }
    __try {
        RtlCopyMemory(entryCopy, matchedEntry, layout.entrySize);
        deleted = RtlDeleteElementGenericTableAvl(
            layout.table,
            entryCopy);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->lastStatus = GetExceptionCode();
        deleted = FALSE;
    }
    ExFreePoolWithTag(entryCopy, KSW_PIDDB_POOL_TAG);
    entryCopy = NULL;
    if (!deleted) {
        response->status =
            KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
        if (response->lastStatus == STATUS_SUCCESS) {
            response->lastStatus = STATUS_UNSUCCESSFUL;
        }
        ExReleaseResourceLite(layout.lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Re-enumerate and require the exact identity to be absent before success. */
    restartKey = NULL;
    walkedRows = 0UL;
    __try {
        while ((entry = RtlEnumerateGenericTableWithoutSplayingAvl(
                    layout.table,
                    &restartKey)) != NULL) {
            /* A truncated re-scan cannot prove absence, so it must not pass. */
            if (walkedRows >= KSW_PIDDB_HARD_WALK_LIMIT) {
                stillPresent = TRUE;
                break;
            }
            walkedRows += 1UL;
            if (kswordArkPiDdbReadEntry(&layout, entry, &row) &&
                kswordArkPiDdbRowMatchesRequest(&row, request)) {
                stillPresent = TRUE;
                break;
            }
        }
        response->remainingRows =
            RtlNumberGenericTableElementsAvl(layout.table);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->lastStatus = GetExceptionCode();
        stillPresent = TRUE;
    }
    response->status = stillPresent
        ? KSWORD_ARK_PIDDB_DELETE_STATUS_VERIFY_FAILED
        : KSWORD_ARK_PIDDB_DELETE_STATUS_OK;
    if (!stillPresent) {
        response->lastStatus = STATUS_SUCCESS;
    }
    ExReleaseResourceLite(layout.lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}
