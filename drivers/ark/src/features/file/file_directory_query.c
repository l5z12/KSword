/*++

Module Name:

    file_directory_query.c

Abstract:

    enumerate mounted directories in R0 via the file system driver and return fixed rows that have passed boundary checks to R3.
    This module calls only public Zw file interfaces and does not parse or dereference NTFS/FAT/exFAT private kernel structures.

Environment:

    Kernel-mode Driver Framework: the calling thread must be at PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

// The query buffer is kept at 64 KiB to support batch reception of directory entries without growing indefinitely with user directory size.
#define KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES (64UL * 1024UL)
#define KSWORD_ARK_DIRECTORY_POOL_TAG 'dFsK'
#define KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG 'sFsK'

/*
 * Directory rescan cache.
 *
 * Fetching a directory in R3 spans many pages. Originally, each page required reopening the directory, calling
 * restartScan, and skipping the first startIndex entries. While skipping itself involves no translation,
 * ZwQueryDirectoryFile forces the file system to traverse the directory index again, causing the total cost to
 * grow quadratically with the number of pages—a directory with thousands of files can noticeably freeze the UI.
 *
 * Preserve the previous directory handle and scan progress: R3 paging loops issue continuous requests on the
 * same driver handle. The next page's startIndex must equal the previous page's nextIndex, so we can directly
 * continue with ZwQueryDirectoryFile on the original handle; each directory only needs to be enumerated once.
 *
 * Only one slot is needed: the paging loop has no user interaction and cannot be interrupted. When the left and right panels alternate enumeration,
 * they invalidate each other's caches, causing a fallback to the old 'reopen per page' behavior; the result remains correct, though slower.
 *
 * Use InterlockedExchangePointer for get/put to avoid introducing a lock object that requires initialization:
 * Exclusive ownership upon retrieval; ZwCreateFile/ZwClose must always execute at PASSIVE_LEVEL during the exclusive period.
 */
typedef struct KswordArkDirectoryScanState
{
    HANDLE directoryHandle;   // Keep the open directory handle.
    ULONG nextVisibleIndex;   // Index of the next visible entry to continue from.
    HANDLE ownerProcessId;    // Process that created this handle; never reuse across processes.
    USHORT pathLengthChars;   // Directory path character count.
    WCHAR path[KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS]; // Directory path.

    /*
     * Native data batch retrieved by the previous ZwQueryDirectoryFile call but not yet consumed.
     * Page-full occurs in the middle of the native buffer: the file system returns hundreds of entries at once, but the protocol page can
     * only hold a subset. At this point, the file system's scan position is already past the entire batch, making the remaining entries
     * unreadable. Therefore, the buffer itself must be retained for the next page's parsing; otherwise, entries will be silently dropped.
     */
    PVOID pendingBuffer;      // Unconsumed native buffer; ownership belongs to this structure.
    ULONG pendingBytes;       // Number of valid bytes in this buffer.
    ULONG pendingOffset;      // Offset from which to continue parsing next.
} KswordArkDirectoryScanState, *PkswordArkDirectoryScanState;

static PVOID volatile gKswordArkDirectoryScanState = NULL;

static PVOID
kswordArkDirectoryAllocate(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate a fixed-size non-paged temporary buffer for a single ZwQueryDirectoryFile call.

Arguments:

    BufferBytes - The requested number of bytes.

Return Value:

    Returns the buffer address on success, NULL on failure; caller must free using kswordArkDirectoryFree.

--*/
{
    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(
        NonPagedPoolNx,
        bufferBytes,
        KSWORD_ARK_DIRECTORY_POOL_TAG);
#pragma warning(pop)
}

static VOID
kswordArkDirectoryFree(
    _In_opt_ PVOID buffer
    )
/*++

Routine Description:

    Free temporary buffer for directory enumeration; allow direct return for NULL input.

Arguments:

    Buffer - the address returned by kswordArkDirectoryAllocate.

Return Value:

    None.

--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, KSWORD_ARK_DIRECTORY_POOL_TAG);
    }
}

static PkswordArkDirectoryScanState
kswordArkDirectoryScanStateAcquire(
    VOID
    )
/*++

Routine Description:

    Atomically retrieve the resume scan cache and nullify the slot. Retrieval grants exclusive ownership: the caller is the sole
    holder of this handle until it is returned, so subsequent ZwClose/ZwQueryDirectoryFile calls require no additional locking.

Arguments:

    None.

Return Value:

    Cached pointer; returns NULL when the slot is empty.

--*/
{
    return (PkswordArkDirectoryScanState)InterlockedExchangePointer(
        (PVOID volatile*)&gKswordArkDirectoryScanState,
        NULL);
}

static VOID
kswordArkDirectoryScanStateFree(
    _In_opt_ PkswordArkDirectoryScanState scanState
    )
/*++

Routine Description:

    Close the directory handle held by the resume scan cache and free the cache itself. Requires PASSIVE_LEVEL.

Arguments:

    ScanState: cache to be released; NULL allows an immediate return.

Return Value:

    None.

--*/
{
    if (scanState == NULL) {
        return;
    }
    if (scanState->directoryHandle != NULL) {
        ZwClose(scanState->directoryHandle);
    }
    if (scanState->pendingBuffer != NULL) {
        kswordArkDirectoryFree(scanState->pendingBuffer);
    }
    ExFreePoolWithTag(scanState, KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG);
}

static VOID
kswordArkDirectoryScanStatePublish(
    _In_ PkswordArkDirectoryScanState scanState
    )
/*++

Routine Description:

    Return the resume scan buffer to the slot. If another request has already returned its buffer
    during this period, discard the later one to ensure at most one handle is cached at any time.

Arguments:

    ScanState - The cache to be published.

Return Value:

    None.

--*/
{
    PkswordArkDirectoryScanState previous =
        (PkswordArkDirectoryScanState)InterlockedExchangePointer(
            (PVOID volatile*)&gKswordArkDirectoryScanState,
            scanState);
    if (previous != NULL) {
        kswordArkDirectoryScanStateFree(previous);
    }
}

VOID
kswordArkDriverResetDirectoryScanCache(
    VOID
    )
/*++

Routine Description:

    Release the continuation-scan cache. The driver unload path must call this function to avoid leaving a directory handle open.

Arguments:

    None.

Return Value:

    None.

--*/
{
    kswordArkDirectoryScanStateFree(kswordArkDirectoryScanStateAcquire());
}

static BOOLEAN
kswordArkDirectoryIsDotEntry(
    _In_ const FILE_ID_BOTH_DIR_INFORMATION* nativeEntry
    )
/*++

Routine Description:

    Check if the native directory entry is '.' or '..'; these entries do not enter the R3-visible index.

Arguments:

    NativeEntry - Native directory entry with length validation completed.

Return Value:

    TRUE indicates a dot directory entry; FALSE indicates a normal visible entry.

--*/
{
    if (nativeEntry == NULL) {
        return FALSE;
    }

    if (nativeEntry->FileNameLength == sizeof(WCHAR) &&
        nativeEntry->FileName[0] == L'.') {
        return TRUE;
    }

    return nativeEntry->FileNameLength == (2U * sizeof(WCHAR)) &&
        nativeEntry->FileName[0] == L'.' &&
        nativeEntry->FileName[1] == L'.';
}

static NTSTATUS
kswordArkDirectoryOpenForEnumeration(
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* request,
    _Out_ HANDLE* directoryHandleOut
    )
/*++

Routine Description:

    Open the requested directory with read-only, full-share, and kernel handle modes to avoid contention from enumeration operations.

Arguments:

    Request: An NT path request that has been validated by the IOCTL handler.
    DirectoryHandleOut - Receives the directory handle; caller must call ZwClose on success.

Return Value:

    NTSTATUS returned by ZwCreateFile.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (request == NULL || directoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *directoryHandleOut = NULL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)request->path;
    targetPath.Length = (USHORT)(request->pathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    return ZwCreateFile(
        directoryHandleOut,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_FOR_BACKUP_INTENT,
        NULL,
        0U);
}

static VOID
kswordArkDirectoryQueryFileSystemName(
    _In_ HANDLE directoryHandle,
    _Inout_ KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* response
    )
/*++

Routine Description:

    Query the file system name associated with the current directory handle and set FS_NAME_PRESENT on success.

Arguments:

    DirectoryHandle - Opened directory handle.
    Response - Current protocol response header.

Return Value:

    None; failure to query the file system name does not affect directory enumeration.

--*/
{
    UCHAR informationBuffer[
        sizeof(FILE_FS_ATTRIBUTE_INFORMATION) +
        (KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS * sizeof(WCHAR))];
    FILE_FS_ATTRIBUTE_INFORMATION* attributeInformation = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG availableNameChars = 0UL;
    ULONG sourceNameChars = 0UL;
    ULONG copyNameChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (directoryHandle == NULL || response == NULL) {
        return;
    }

    RtlZeroMemory(informationBuffer, sizeof(informationBuffer));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryVolumeInformationFile(
        directoryHandle,
        &ioStatusBlock,
        informationBuffer,
        (ULONG)sizeof(informationBuffer),
        FileFsAttributeInformation);
    if (!NT_SUCCESS(status) ||
        ioStatusBlock.Information < FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) {
        return;
    }

    attributeInformation = (FILE_FS_ATTRIBUTE_INFORMATION*)informationBuffer;
    availableNameChars = (ULONG)(
        (ioStatusBlock.Information -
            FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) /
        sizeof(WCHAR));
    sourceNameChars = (ULONG)(attributeInformation->FileSystemNameLength / sizeof(WCHAR));
    copyNameChars = sourceNameChars;
    if (copyNameChars > availableNameChars) {
        copyNameChars = availableNameChars;
    }
    if (copyNameChars >= KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS) {
        copyNameChars = KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS - 1UL;
    }

    if (copyNameChars != 0UL) {
        RtlCopyMemory(
            response->fileSystemName,
            attributeInformation->FileSystemName,
            copyNameChars * sizeof(WCHAR));
        response->fileSystemName[copyNameChars] = L'\0';
        response->fileSystemNameLengthChars = copyNameChars;
        response->responseFlags |=
            KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT;
    }
}

static NTSTATUS
kswordArkDirectoryConsumeNativeBuffer(
    _In_reads_bytes_(nativeBytes) const UCHAR* nativeBuffer,
    _In_ ULONG nativeBytes,
    _In_ ULONG startIndex,
    _In_ ULONG maximumRows,
    _Inout_ ULONG* visibleIndex,
    _Inout_ KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* response,
    _Out_ BOOLEAN* pageCompleteOut,
    _Out_ ULONG* nextOffsetOut
    )
/*++

Routine Description:

    Validate and convert a FILE_ID_BOTH_DIR_INFORMATION chain, skipping the first page of entries by visible index.

Arguments:

    NativeBuffer/NativeBytes: Native buffer and valid length returned by ZwQueryDirectoryFile.
    StartIndex: Index of the first visible entry on the current page.
    MaximumRows - Protocol output page capacity.
    VisibleIndex - Cumulative index of visible entries across native buffers.
    Response - Receive fixed protocol line.
    PageCompleteOut: TRUE indicates the next page entry has been found; stop the current scan.
    NextOffsetOut: The starting offset within this buffer that has not yet been consumed. If exiting early due to page full,
        it points to the entry not yet received; if completed normally, it equals NativeBytes. Continuation scans must use it to
        process the remaining data; otherwise, entries discarded during page-full conditions would be permanently lost.

Return Value:

    STATUS_SUCCESS indicates the buffer chain is valid; STATUS_DATA_ERROR indicates the file system returned an out-of-bounds chain.

--*/
{
    ULONG nativeOffset = 0UL;
    const ULONG kNativeHeaderBytes =
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);

    if (nativeBuffer == NULL ||
        visibleIndex == NULL ||
        response == NULL ||
        pageCompleteOut == NULL ||
        nextOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pageCompleteOut = FALSE;
    *nextOffsetOut = nativeBytes;

    while (nativeOffset < nativeBytes) {
        const FILE_ID_BOTH_DIR_INFORMATION* nativeEntry = NULL;
        KSWORD_ARK_DIRECTORY_ENTRY* outputEntry = NULL;
        ULONG remainingBytes = nativeBytes - nativeOffset;
        ULONG nameChars = 0UL;
        ULONG copyNameChars = 0UL;
        ULONG minimumEntryBytes = 0UL;

        if (remainingBytes < kNativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        nativeEntry = (const FILE_ID_BOTH_DIR_INFORMATION*)(
            nativeBuffer + nativeOffset);
        if ((nativeEntry->FileNameLength % sizeof(WCHAR)) != 0U) {
            return STATUS_DATA_ERROR;
        }
        if (nativeEntry->FileNameLength > remainingBytes - kNativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        minimumEntryBytes = kNativeHeaderBytes + nativeEntry->FileNameLength;
        if (nativeEntry->NextEntryOffset != 0UL &&
            (nativeEntry->NextEntryOffset < minimumEntryBytes ||
                nativeEntry->NextEntryOffset > remainingBytes)) {
            return STATUS_DATA_ERROR;
        }

        if (!kswordArkDirectoryIsDotEntry(nativeEntry)) {
            if (*visibleIndex < startIndex) {
                *visibleIndex += 1UL;
            }
            else if (response->rowCount >= maximumRows) {
                response->responseFlags |=
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE;
                // This entry has not yet been accepted; the continuation scan must start from it and cannot skip it.
                *nextOffsetOut = nativeOffset;
                *pageCompleteOut = TRUE;
                return STATUS_SUCCESS;
            }
            else {
                outputEntry = &response->rows[response->rowCount];
                RtlZeroMemory(outputEntry, sizeof(*outputEntry));
                outputEntry->fileAttributes = nativeEntry->FileAttributes;
                outputEntry->fileId = (ULONGLONG)nativeEntry->FileId.QuadPart;
                outputEntry->allocationSize = nativeEntry->AllocationSize.QuadPart;
                outputEntry->endOfFile = nativeEntry->EndOfFile.QuadPart;
                outputEntry->creationTime = nativeEntry->CreationTime.QuadPart;
                outputEntry->lastAccessTime = nativeEntry->LastAccessTime.QuadPart;
                outputEntry->lastWriteTime = nativeEntry->LastWriteTime.QuadPart;
                outputEntry->changeTime = nativeEntry->ChangeTime.QuadPart;

                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY;
                }
                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_REPARSE_POINT;
                }

                nameChars = (ULONG)(nativeEntry->FileNameLength / sizeof(WCHAR));
                copyNameChars = nameChars;
                if (copyNameChars >= KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS) {
                    copyNameChars = KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS - 1UL;
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_NAME_TRUNCATED;
                }
                if (copyNameChars != 0UL) {
                    RtlCopyMemory(
                        outputEntry->name,
                        nativeEntry->FileName,
                        copyNameChars * sizeof(WCHAR));
                }
                outputEntry->name[copyNameChars] = L'\0';
                outputEntry->nameLengthChars = copyNameChars;
                response->rowCount += 1UL;
                *visibleIndex += 1UL;
            }
        }

        if (nativeEntry->NextEntryOffset == 0UL) {
            break;
        }
        nativeOffset += nativeEntry->NextEntryOffset;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnumerateDirectory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Open the directory and scan from the beginning up to startIndex, returning up to maxEntries validated fixed-protocol rows.

Arguments:

    OutputBuffer/OutputBufferLength - METHOD_BUFFERED output view and length.
    Request: Fixed request snapshot copied and validated by the handler.
    BytesWrittenOut - Receives the total byte count of the protocol header and valid lines.

Return Value:

    Return STATUS_SUCCESS when the buffer itself is valid; write queryStatus/lastStatus for directory semantic failures.

--*/
{
    KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* response = NULL;
    HANDLE directoryHandle = NULL;
    PkswordArkDirectoryScanState scanState = NULL;
    BOOLEAN reusedScanState = FALSE;
    ULONG pendingBytes = 0UL;
    ULONG pendingOffset = 0UL;
    PVOID nativeBuffer = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG maximumRowsByBuffer = 0UL;
    ULONG maximumRows = 0UL;
    ULONG visibleIndex = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN pageComplete = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maximumRowsByBuffer = (ULONG)(
        (outputBufferLength - KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    maximumRows = request->maxEntries;
    if (maximumRows > maximumRowsByBuffer) {
        maximumRows = maximumRowsByBuffer;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_DIRECTORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;
    response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE;
    response->rowSize = (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
    response->startIndex = request->startIndex;
    response->nextIndex = request->startIndex;
    response->openStatus = STATUS_UNSUCCESSFUL;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *bytesWrittenOut = KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        maximumRows == 0UL ||
        request->version != KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION ||
        request->size != (ULONG)sizeof(*request)) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST;
        response->lastStatus = KeGetCurrentIrql() != PASSIVE_LEVEL
            ? STATUS_INVALID_DEVICE_STATE
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    /*
     * Prioritize continuing the scan from the previous page. The hit condition requires the same process, the same directory, and a request
     * start index exactly matching the last resume position—this is the form of the R3 paging loop. On a hit, do not reopen the directory
     * or call restartScan; instead, fetch the next batch directly from the original handle, enumerating the entire directory only once.
     */
    scanState = kswordArkDirectoryScanStateAcquire();
    if (scanState != NULL) {
        if (scanState->directoryHandle != NULL &&
            scanState->ownerProcessId == PsGetCurrentProcessId() &&
            scanState->nextVisibleIndex == request->startIndex &&
            scanState->pathLengthChars == request->pathLengthChars &&
            RtlEqualMemory(
                scanState->path,
                request->path,
                (SIZE_T)request->pathLengthChars * sizeof(WCHAR))) {
            directoryHandle = scanState->directoryHandle;
            visibleIndex = scanState->nextVisibleIndex;
            restartScan = FALSE;
            reusedScanState = TRUE;
        }
        else {
            // Not a continuation request: the old handle is invalid, so release it immediately to avoid holding onto the directory.
            kswordArkDirectoryScanStateFree(scanState);
            scanState = NULL;
        }
    }

    if (!reusedScanState) {
        status = kswordArkDirectoryOpenForEnumeration(request, &directoryHandle);
        response->openStatus = status;
        response->lastStatus = status;
        if (!NT_SUCCESS(status)) {
            response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED;
            return STATUS_SUCCESS;
        }
    }
    else {
        // During rescan, no re-open action occurs; the open status retains the success semantics.
        response->openStatus = STATUS_SUCCESS;
        response->lastStatus = STATUS_SUCCESS;
    }

    kswordArkDirectoryQueryFileSystemName(directoryHandle, response);

    // On resume scanning, take over the batch of native data not yet consumed from the previous page, along
    // with its buffer, and continue parsing from the recorded offset; otherwise, allocate a new block.
    if (reusedScanState && scanState->pendingBuffer != NULL) {
        nativeBuffer = scanState->pendingBuffer;
        pendingBytes = scanState->pendingBytes;
        pendingOffset = scanState->pendingOffset;
        scanState->pendingBuffer = NULL;
        scanState->pendingBytes = 0UL;
        scanState->pendingOffset = 0UL;
    }
    else {
        nativeBuffer = kswordArkDirectoryAllocate(
            KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES);
    }
    if (nativeBuffer == NULL) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        if (scanState != NULL) {
            // The handle is owned by scanState and is released along with the cache.
            kswordArkDirectoryScanStateFree(scanState);
        }
        else {
            ZwClose(directoryHandle);
        }
        return STATUS_SUCCESS;
    }

    for (;;) {
        ULONG consumedOffset = 0UL;

        // Only fetch new data after consuming the current batch.
        if (pendingOffset >= pendingBytes) {
            RtlZeroMemory(nativeBuffer, KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES);
            RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
            status = ZwQueryDirectoryFile(
                directoryHandle,
                NULL,
                NULL,
                NULL,
                &ioStatusBlock,
                nativeBuffer,
                KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES,
                FileIdBothDirectoryInformation,
                FALSE,
                NULL,
                restartScan);
            restartScan = FALSE;

            if (status == STATUS_NO_MORE_FILES) {
                response->lastStatus = STATUS_SUCCESS;
                break;
            }
            if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
                response->lastStatus = status;
                response->queryStatus = response->rowCount == 0UL
                    ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                    : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
                break;
            }
            if (ioStatusBlock.Information == 0U ||
                ioStatusBlock.Information > KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES) {
                response->lastStatus = STATUS_DATA_ERROR;
                response->queryStatus = response->rowCount == 0UL
                    ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                    : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
                break;
            }

            pendingBytes = (ULONG)ioStatusBlock.Information;
            pendingOffset = 0UL;
        }

        status = kswordArkDirectoryConsumeNativeBuffer(
            (const UCHAR*)nativeBuffer + pendingOffset,
            pendingBytes - pendingOffset,
            request->startIndex,
            maximumRows,
            &visibleIndex,
            response,
            &pageComplete,
            &consumedOffset);
        // consumedOffset is relative to the current input start; accumulate it back to the global offset.
        pendingOffset += consumedOffset;
        if (!NT_SUCCESS(status)) {
            response->lastStatus = status;
            response->queryStatus = response->rowCount == 0UL
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }
        if (pageComplete) {
            response->lastStatus = STATUS_SUCCESS;
            break;
        }
    }

    if (response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK;
    }
    response->nextIndex = request->startIndex + response->rowCount;
    response->size = (ULONG)(
        KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
        (response->rowCount * sizeof(KSWORD_ARK_DIRECTORY_ENTRY)));
    *bytesWrittenOut = response->size;

    /*
     * If more pages are available, keep the handle and progress to resume scanning on the next page; otherwise, close immediately.
     * Cache only when semantics are valid (failure states other than OK/PARTIAL make the handle status
     * unreliable) and more entries truly exist, to avoid caching a failed scan for the next request to continue.
     */
    {
        const BOOLEAN kMoreAvailable =
            (response->responseFlags &
                KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) != 0UL;
        const BOOLEAN kSemanticOk =
            response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK;

        if (kMoreAvailable && kSemanticOk) {
            if (scanState == NULL) {
#pragma warning(push)
#pragma warning(disable:4996)
                scanState = (PkswordArkDirectoryScanState)ExAllocatePoolWithTag(
                    NonPagedPoolNx,
                    sizeof(KswordArkDirectoryScanState),
                    KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG);
#pragma warning(pop)
            }
            if (scanState != NULL) {
                RtlZeroMemory(scanState, sizeof(*scanState));
                scanState->directoryHandle = directoryHandle;
                scanState->nextVisibleIndex = response->nextIndex;
                scanState->ownerProcessId = PsGetCurrentProcessId();
                scanState->pathLengthChars = request->pathLengthChars;
                RtlCopyMemory(
                    scanState->path,
                    request->path,
                    (SIZE_T)request->pathLengthChars * sizeof(WCHAR));
                // Retain the unconsumed portion of the native buffer: Page full must occur
                // mid-batch; discarding it would lose the remaining directory entries in this batch.
                if (pendingOffset < pendingBytes) {
                    scanState->pendingBuffer = nativeBuffer;
                    scanState->pendingBytes = pendingBytes;
                    scanState->pendingOffset = pendingOffset;
                    nativeBuffer = NULL;
                }
                // Ownership is transferred to the cache; this function will no longer close the handle.
                directoryHandle = NULL;
                kswordArkDirectoryScanStatePublish(scanState);
                scanState = NULL;
            }
        }
    }

    if (scanState != NULL) {
        // Reaching here indicates the cache was not published; the handle is held by it and is released together.
        kswordArkDirectoryScanStateFree(scanState);
    }
    else if (directoryHandle != NULL) {
        ZwClose(directoryHandle);
    }

    // If the buffer was already transferred to the cache, it is NULL; here we only free the portion still owned by this function.
    kswordArkDirectoryFree(nativeBuffer);
    return STATUS_SUCCESS;
}
