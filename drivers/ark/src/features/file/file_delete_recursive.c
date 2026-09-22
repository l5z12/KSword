/*++

Module Name:

    file_delete_recursive.c

Abstract:

    Recursively delete the directory tree in R0. R3 directory traversal requires FILE_LIST_DIRECTORY. If a directory
    DACL denies enumeration, its children cannot be obtained and deleting the parent then fails because it is not empty;
    Kernel-mode Zw* calls do not perform access checks when opening objects in KernelMode, so recursive expansion must remain in
    R0. This module implements post-order deletion via explicit stack iteration to prevent kernel stack recursion depth from going
    out of control, and enforces hard limits on depth and total entry count to ensure predictable blocking time for a single IOCTL.

    The deletion action for a single node still reuses `kswordArkDriverDeletePath`, preserving existing semantics
    such as read-only attribute normalization, `FileDispositionInformationEx` fallback, and image section refresh.

Environment:

    Kernel-mode Driver Framework: the calling thread must be at PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000UL
#endif

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

#define KSWORD_ARK_DELETE_TREE_POOL_TAG 'tDsK'

// Each frame uses a fixed enumeration buffer: 8 KiB is sufficient to hold a batch of directory entries, and total usage remains bounded within the depth limit.
#define KSWORD_ARK_DELETE_TREE_BATCH_BYTES (8UL * 1024UL)

// KswordArkDeleteTreeFrame: Traversal state for a single directory level.
// Retains the batch offset to resume processing the next item in the same batch after entering a
// subdirectory, avoiding O(n^2) caused by re-enumerating every time returning to the parent level.
typedef struct KswordArkDeleteTreeFrame
{
    HANDLE directoryHandle;
    ULONG pathLengthChars;
    ULONG batchOffset;
    ULONG batchBytes;
    BOOLEAN batchValid;
    BOOLEAN restartScan;
    PUCHAR batchBuffer;
} KswordArkDeleteTreeFrame, *PkswordArkDeleteTreeFrame;

// KswordArkDeleteTreeContext: All mutable state for a single recursive deletion.
// PathBuffer is the sole path workspace: append child names when pushing to the stack, and truncate to the parent directory length when popping.
typedef struct KswordArkDeleteTreeContext
{
    PWCHAR pathBuffer;
    ULONG pathCapacityChars;
    PkswordArkDeleteTreeFrame frames;
    ULONG frameCapacity;
    ULONG frameCount;
    PUCHAR batchPool;
    KSWORD_ARK_DELETE_PATH_RESPONSE* response;
    ULONG deleteFlags;
    BOOLEAN continueOnError;
    BOOLEAN aborted;
} KswordArkDeleteTreeContext, *PkswordArkDeleteTreeContext;

static PVOID
kswordArkDeleteTreeAllocate(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate a zeroed non-paged buffer for recursive deletion.

Arguments:

    BufferBytes - The requested number of bytes.

Return Value:

    Returns the buffer address on success; returns NULL on failure.

--*/
{
    PVOID buffer = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    buffer = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        bufferBytes,
        KSWORD_ARK_DELETE_TREE_POOL_TAG);
#pragma warning(pop)

    if (buffer != NULL) {
        RtlZeroMemory(buffer, bufferBytes);
    }
    return buffer;
}

static VOID
kswordArkDeleteTreeFree(
    _In_opt_ PVOID buffer
    )
/*++

Routine Description:

    Free the buffer allocated by kswordArkDeleteTreeAllocate; return immediately if the input is NULL.

Arguments:

    Buffer - Address to be freed.

Return Value:

    None.

--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, KSWORD_ARK_DELETE_TREE_POOL_TAG);
    }
}

static VOID
kswordArkDeleteTreeReleaseContext(
    _Inout_ PkswordArkDeleteTreeContext context
    )
/*++

Routine Description:

    Close directory handles still on the stack and release all working buffers. The interrupt
    exit path must also go through here; otherwise, kernel handles will leak with the driver.

Arguments:

    Context - Recursive context.

Return Value:

    None.

--*/
{
    ULONG frameIndex;

    if (context == NULL) {
        return;
    }

    if (context->frames != NULL) {
        for (frameIndex = 0U; frameIndex < context->frameCount; frameIndex += 1U) {
            if (context->frames[frameIndex].directoryHandle != NULL) {
                ZwClose(context->frames[frameIndex].directoryHandle);
                context->frames[frameIndex].directoryHandle = NULL;
            }
        }
    }
    context->frameCount = 0U;

    kswordArkDeleteTreeFree(context->frames);
    context->frames = NULL;
    kswordArkDeleteTreeFree(context->batchPool);
    context->batchPool = NULL;
    kswordArkDeleteTreeFree(context->pathBuffer);
    context->pathBuffer = NULL;
}

static NTSTATUS
kswordArkDeleteTreePrepareContext(
    _Inout_ PkswordArkDeleteTreeContext context,
    _In_ KSWORD_ARK_DELETE_PATH_RESPONSE* response,
    _In_ ULONG deleteFlags,
    _In_ BOOLEAN continueOnError
    )
/*++

Routine Description:

    Allocate workspace for the path, frame array, and enumeration buffer pool.

Arguments:

    Context: Recursive context to be initialized.
    Response - Statistics acknowledgment, owned by the caller.
    DeleteFlags: BACKEND_* flags to pass to the single-node deleter.
    ContinueOnError: TRUE indicates continuing to process other items at the same level after a single-point failure.

Return Value:

    STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.

--*/
{
    const ULONG kFrameCapacity = (ULONG)KSWORD_ARK_DELETE_PATH_MAX_DEPTH;
    const SIZE_T kPathBytes =
        ((SIZE_T)KSWORD_ARK_DELETE_PATH_TREE_MAX_CHARS + 1U) * sizeof(WCHAR);
    const SIZE_T kFrameBytes = (SIZE_T)kFrameCapacity * sizeof(KswordArkDeleteTreeFrame);
    const SIZE_T kBatchBytes = (SIZE_T)kFrameCapacity * KSWORD_ARK_DELETE_TREE_BATCH_BYTES;
    ULONG frameIndex;

    RtlZeroMemory(context, sizeof(*context));
    context->response = response;
    context->deleteFlags = deleteFlags;
    context->continueOnError = continueOnError;

    context->pathBuffer = (PWCHAR)kswordArkDeleteTreeAllocate(kPathBytes);
    context->frames = (PkswordArkDeleteTreeFrame)kswordArkDeleteTreeAllocate(kFrameBytes);
    context->batchPool = (PUCHAR)kswordArkDeleteTreeAllocate(kBatchBytes);
    if (context->pathBuffer == NULL ||
        context->frames == NULL ||
        context->batchPool == NULL) {
        kswordArkDeleteTreeReleaseContext(context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    context->pathCapacityChars = (ULONG)KSWORD_ARK_DELETE_PATH_TREE_MAX_CHARS;
    context->frameCapacity = kFrameCapacity;
    for (frameIndex = 0U; frameIndex < kFrameCapacity; frameIndex += 1U) {
        context->frames[frameIndex].batchBuffer =
            context->batchPool + ((SIZE_T)frameIndex * KSWORD_ARK_DELETE_TREE_BATCH_BYTES);
    }
    return STATUS_SUCCESS;
}

static VOID
kswordArkDeleteTreeRecordFailure(
    _Inout_ PkswordArkDeleteTreeContext context,
    _In_ ULONG pathLengthChars,
    _In_ NTSTATUS failureStatus
    )
/*++

Routine Description:

    Record a delete/enum failure. Note: Keep only the first failed path to prevent response packet
    growth; R3 can use failedCount and the first failed path to locate the issue and decide on retry.

Arguments:

    Context - Recursive context.
    PathLengthChars - Number of valid characters currently in PathBuffer.
    FailureStatus: Failed NTSTATUS.

Return Value:

    None.

--*/
{
    ULONG copyChars;

    if (context == NULL || context->response == NULL) {
        return;
    }

    context->response->failedCount += 1U;
    context->response->lastStatus = failureStatus;

    if (context->response->failedPathLengthChars == 0U && pathLengthChars > 0U) {
        copyChars = pathLengthChars;
        if (copyChars >= KSWORD_ARK_DELETE_PATH_MAX_CHARS) {
            copyChars = KSWORD_ARK_DELETE_PATH_MAX_CHARS - 1U;
        }
        RtlCopyMemory(
            context->response->failedPath,
            context->pathBuffer,
            (SIZE_T)copyChars * sizeof(WCHAR));
        context->response->failedPath[copyChars] = L'\0';
        context->response->failedPathLengthChars = (unsigned short)copyChars;
    }

    if (!context->continueOnError) {
        context->aborted = TRUE;
    }
}

static BOOLEAN
kswordArkDeleteTreeDeleteNode(
    _Inout_ PkswordArkDeleteTreeContext context,
    _In_ ULONG pathLengthChars,
    _In_ BOOLEAN isDirectory
    )
/*++

Routine Description:

    Delete the single node currently represented by PathBuffer and accumulate statistics.

Arguments:

    Context - Recursive context.
    PathLengthChars - Valid character count in PathBuffer (excluding trailing NUL).
    IsDirectory - TRUE indicates opening with directory semantics.

Return Value:

    TRUE indicates successful deletion.

--*/
{
    NTSTATUS status;

    if (context == NULL || context->response == NULL) {
        return FALSE;
    }

    if (pathLengthChars == 0U || pathLengthChars > MAXUSHORT) {
        kswordArkDeleteTreeRecordFailure(context, pathLengthChars, STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    context->pathBuffer[pathLengthChars] = L'\0';
    status = kswordArkDriverDeletePathWithFlags(
        context->pathBuffer,
        (USHORT)pathLengthChars,
        isDirectory,
        context->deleteFlags);
    if (!NT_SUCCESS(status)) {
        kswordArkDeleteTreeRecordFailure(context, pathLengthChars, status);
        return FALSE;
    }

    if (isDirectory) {
        context->response->deletedDirectoryCount += 1U;
    }
    else {
        context->response->deletedFileCount += 1U;
    }
    return TRUE;
}

static NTSTATUS
kswordArkDeleteTreeQueryAttributes(
    _In_ PCWSTR pathText,
    _In_ ULONG pathLengthChars,
    _Out_ PULONG fileAttributesOut
    )
/*++

Routine Description:

    Read node attributes with FILE_OPEN_REPARSE_POINT semantics to determine if it is a 'directory / reparse point'.
    Note: Do not use queries that follow reparse points, or symbolic links will be treated
    as real directories, causing recursive deletion to penetrate into the link target.

Arguments:

    PathText - NT path, must be NUL-terminated.
    PathLengthChars: character count, excluding the trailing NUL.
    FileAttributesOut - receives FILE_ATTRIBUTE_*.

Return Value:

    NTSTATUS of ZwCreateFile / ZwQueryInformationFile.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_BASIC_INFORMATION basicInformation;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    if (pathText == NULL || pathLengthChars == 0U ||
        pathLengthChars > MAXUSHORT || fileAttributesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileAttributesOut = 0UL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)pathText;
    targetPath.Length = (USHORT)(pathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_FOR_BACKUP_INTENT |
            FILE_OPEN_REPARSE_POINT,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &basicInformation,
        (ULONG)sizeof(basicInformation),
        FileBasicInformation);
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *fileAttributesOut = basicInformation.FileAttributes;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDeleteTreeOpenDirectory(
    _In_ PCWSTR pathText,
    _In_ ULONG pathLengthChars,
    _Out_ PHANDLE directoryHandleOut
    )
/*++

Routine Description:

    Open a directory layer for enumeration; open with full sharing to avoid additional contention caused by the traversal itself.

Arguments:

    PathText - NT directory path, must be NUL-terminated.
    PathLengthChars: character count, excluding the trailing NUL.
    DirectoryHandleOut - Receives the directory handle; caller must call ZwClose on success.

Return Value:

    NTSTATUS of ZwCreateFile.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (pathText == NULL || pathLengthChars == 0U ||
        pathLengthChars > MAXUSHORT || directoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *directoryHandleOut = NULL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)pathText;
    targetPath.Length = (USHORT)(pathLengthChars * sizeof(WCHAR));
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

static BOOLEAN
kswordArkDeleteTreeIsDotEntry(
    _In_ const FILE_BOTH_DIR_INFORMATION* entry
    )
/*++

Routine Description:

    Check if the directory entry is "." or "..".

Arguments:

    Entry - Directory entry with completed length validation.

Return Value:

    TRUE indicates a directory entry.

--*/
{
    if (entry == NULL) {
        return FALSE;
    }

    if (entry->FileNameLength == sizeof(WCHAR) && entry->FileName[0] == L'.') {
        return TRUE;
    }

    return entry->FileNameLength == (2U * sizeof(WCHAR)) &&
        entry->FileName[0] == L'.' &&
        entry->FileName[1] == L'.';
}

static BOOLEAN
kswordArkDeleteTreeAppendChildName(
    _Inout_ PkswordArkDeleteTreeContext context,
    _In_ ULONG parentLengthChars,
    _In_reads_bytes_(nameLengthBytes) PCWCH nameText,
    _In_ ULONG nameLengthBytes,
    _Out_ PULONG childLengthCharsOut
    )
/*++

Routine Description:

    Append child name to parent directory on PathBuffer.

Arguments:

    Context - Recursive context.
    ParentLengthChars - number of characters in the parent directory path.
    NameText - Directory entry name (not NUL-terminated).
    NameLengthBytes - Byte count of the directory entry name.
    ChildLengthCharsOut - Receives the total character count after concatenation.

Return Value:

    TRUE indicates concatenation succeeded; FALSE indicates the name is empty or exceeds the path limit.

--*/
{
    ULONG nameChars;
    ULONG childChars;

    if (context == NULL || nameText == NULL || childLengthCharsOut == NULL) {
        return FALSE;
    }
    *childLengthCharsOut = 0U;

    nameChars = nameLengthBytes / (ULONG)sizeof(WCHAR);
    if (nameChars == 0U) {
        return FALSE;
    }

    childChars = parentLengthChars + 1U + nameChars;
    if (childChars >= context->pathCapacityChars) {
        return FALSE;
    }

    context->pathBuffer[parentLengthChars] = L'\\';
    RtlCopyMemory(
        &context->pathBuffer[parentLengthChars + 1U],
        nameText,
        (SIZE_T)nameChars * sizeof(WCHAR));
    context->pathBuffer[childChars] = L'\0';
    *childLengthCharsOut = childChars;
    return TRUE;
}

static BOOLEAN
kswordArkDeleteTreePushDirectory(
    _Inout_ PkswordArkDeleteTreeContext context,
    _In_ ULONG pathLengthChars
    )
/*++

Routine Description:

    Open the directory pointed to by PathBuffer and push it onto the stack. If the push fails, the caller will delete the leaf node as a fallback.

Arguments:

    Context - Recursive context.
    PathLengthChars - Character count of the directory path.

Return Value:

    TRUE indicates the frame has been pushed; FALSE indicates depth limit exceeded or directory cannot be opened.

--*/
{
    PkswordArkDeleteTreeFrame frame;
    HANDLE directoryHandle = NULL;
    NTSTATUS status;

    if (context == NULL || context->response == NULL) {
        return FALSE;
    }

    if (context->frameCount >= context->frameCapacity) {
        context->response->responseFlags |=
            KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_DEPTH_LIMITED;
        return FALSE;
    }

    context->pathBuffer[pathLengthChars] = L'\0';
    status = kswordArkDeleteTreeOpenDirectory(
        context->pathBuffer,
        pathLengthChars,
        &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    frame = &context->frames[context->frameCount];
    frame->directoryHandle = directoryHandle;
    frame->pathLengthChars = pathLengthChars;
    frame->batchOffset = 0U;
    frame->batchBytes = 0U;
    frame->batchValid = FALSE;
    frame->restartScan = TRUE;
    context->frameCount += 1U;

    if (context->frameCount > context->response->maxDepthReached) {
        context->response->maxDepthReached = context->frameCount;
    }
    return TRUE;
}

static VOID
kswordArkDeleteTreePopDirectory(
    _Inout_ PkswordArkDeleteTreeContext context
    )
/*++

Routine Description:

    Close the stack-top directory handle, delete the directory itself, and truncate the PathBuffer back to the parent directory.
    Note: The handle must be closed before deletion; otherwise, the reference held by itself will cause the directory deletion to hang.

Arguments:

    Context - Recursive context.

Return Value:

    None.

--*/
{
    PkswordArkDeleteTreeFrame frame;
    ULONG directoryLengthChars;

    if (context == NULL || context->frameCount == 0U) {
        return;
    }

    context->frameCount -= 1U;
    frame = &context->frames[context->frameCount];
    directoryLengthChars = frame->pathLengthChars;

    if (frame->directoryHandle != NULL) {
        ZwClose(frame->directoryHandle);
        frame->directoryHandle = NULL;
    }
    frame->batchValid = FALSE;
    frame->batchBytes = 0U;
    frame->batchOffset = 0U;

    (VOID)kswordArkDeleteTreeDeleteNode(context, directoryLengthChars, TRUE);

    if (context->frameCount > 0U) {
        context->pathBuffer[context->frames[context->frameCount - 1U].pathLengthChars] = L'\0';
    }
}

static BOOLEAN
kswordArkDeleteTreeFetchBatch(
    _Inout_ PkswordArkDeleteTreeContext context,
    _Inout_ PkswordArkDeleteTreeFrame frame
    )
/*++

Routine Description:

    Fetch the next batch of directory entries for the stack-top directory.

Arguments:

    Context - Recursive context.
    Frame - Top of stack.

Return Value:

    TRUE indicates a batch of processable directory entries has been retrieved; FALSE indicates traversal at this level has
    ended (either enumeration completed or failed, in which case the caller unwinds the stack and deletes the directory itself).

--*/
{
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryDirectoryFile(
        frame->directoryHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        frame->batchBuffer,
        KSWORD_ARK_DELETE_TREE_BATCH_BYTES,
        FileBothDirectoryInformation,
        FALSE,
        NULL,
        frame->restartScan);
    frame->restartScan = FALSE;

    if (status == STATUS_NO_MORE_FILES) {
        return FALSE;
    }

    if (!NT_SUCCESS(status)) {
        context->response->responseFlags |=
            KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED;
        kswordArkDeleteTreeRecordFailure(context, frame->pathLengthChars, status);
        return FALSE;
    }

    if (ioStatusBlock.Information == 0U ||
        ioStatusBlock.Information > KSWORD_ARK_DELETE_TREE_BATCH_BYTES) {
        return FALSE;
    }

    frame->batchBytes = (ULONG)ioStatusBlock.Information;
    frame->batchOffset = 0U;
    frame->batchValid = TRUE;
    return TRUE;
}

static BOOLEAN
kswordArkDeleteTreeValidateEntry(
    _In_ const KswordArkDeleteTreeFrame* frame,
    _In_ const FILE_BOTH_DIR_INFORMATION* entry
    )
/*++

Routine Description:

    Verify that directory entries fall entirely within the batch buffer. Note: The file system returns variable-length
    records; advancing directly by NextEntryOffset without validation causes out-of-bounds reads into non-paged pool.

Arguments:

    Frame - Current frame, providing batch boundaries.
    Entry - Directory entry to be validated.

Return Value:

    TRUE indicates the record length is valid.

--*/
{
    ULONG headerBytes;
    ULONG requiredBytes;

    headerBytes = (ULONG)FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
    if (frame->batchOffset > frame->batchBytes ||
        (frame->batchBytes - frame->batchOffset) < headerBytes) {
        return FALSE;
    }

    if (entry->FileNameLength > (frame->batchBytes - frame->batchOffset - headerBytes)) {
        return FALSE;
    }
    if ((entry->FileNameLength % sizeof(WCHAR)) != 0U) {
        return FALSE;
    }

    if (entry->NextEntryOffset != 0U) {
        requiredBytes = headerBytes + entry->FileNameLength;
        if (entry->NextEntryOffset < requiredBytes ||
            entry->NextEntryOffset > (frame->batchBytes - frame->batchOffset)) {
            return FALSE;
        }
    }
    return TRUE;
}

static VOID
kswordArkDeleteTreeRun(
    _Inout_ PkswordArkDeleteTreeContext context
    )
/*++

Routine Description:

    Subsequent deletion main loop: enumerate the top-of-stack directory in batches, delete files and reparse points directly, push
    ordinary subdirectories onto the stack; after enumeration at a level completes, pop the stack to delete the directory itself.

Arguments:

    Context - Recursive context with the root frame pushed.

Return Value:

    None; all results are written to Context->Response.

--*/
{
    PkswordArkDeleteTreeFrame frame;
    FILE_BOTH_DIR_INFORMATION* entry;
    ULONG childLengthChars;
    ULONG nextEntryOffset;
    ULONG entryAttributes;
    BOOLEAN entryIsDirectory;
    BOOLEAN entryIsReparsePoint;
    BOOLEAN descended;

    while (context->frameCount > 0U && !context->aborted) {
        frame = &context->frames[context->frameCount - 1U];

        if (!frame->batchValid) {
            if (!kswordArkDeleteTreeFetchBatch(context, frame)) {
                kswordArkDeleteTreePopDirectory(context);
                continue;
            }
        }

        descended = FALSE;
        while (frame->batchOffset < frame->batchBytes) {
            entry = (FILE_BOTH_DIR_INFORMATION*)(frame->batchBuffer + frame->batchOffset);
            if (!kswordArkDeleteTreeValidateEntry(frame, entry)) {
                context->response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED;
                kswordArkDeleteTreeRecordFailure(
                    context,
                    frame->pathLengthChars,
                    STATUS_INVALID_BUFFER_SIZE);
                frame->batchOffset = frame->batchBytes;
                break;
            }

            nextEntryOffset = entry->NextEntryOffset;
            entryAttributes = entry->FileAttributes;
            entryIsDirectory = ((entryAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) ? TRUE : FALSE;
            entryIsReparsePoint = ((entryAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) ? TRUE : FALSE;

            if (nextEntryOffset == 0U) {
                frame->batchOffset = frame->batchBytes;
            }
            else {
                frame->batchOffset += nextEntryOffset;
            }

            if (kswordArkDeleteTreeIsDotEntry(entry)) {
                continue;
            }

            context->response->visitedCount += 1U;
            if (context->response->visitedCount > (ULONG)KSWORD_ARK_DELETE_PATH_MAX_ENTRIES) {
                context->response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENTRY_LIMITED;
                context->aborted = TRUE;
                break;
            }

            if (!kswordArkDeleteTreeAppendChildName(
                    context,
                    frame->pathLengthChars,
                    entry->FileName,
                    entry->FileNameLength,
                    &childLengthChars)) {
                kswordArkDeleteTreeRecordFailure(
                    context,
                    frame->pathLengthChars,
                    STATUS_NAME_TOO_LONG);
                if (context->aborted) {
                    break;
                }
                continue;
            }

            if (entryIsDirectory && entryIsReparsePoint) {
                // For reparse point directories, delete only the link itself; never follow the target, or real data pointed to by the link will be deleted.
                context->response->skippedReparseCount += 1U;
                context->response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_REPARSE_SKIPPED;
                (VOID)kswordArkDeleteTreeDeleteNode(context, childLengthChars, TRUE);
                context->pathBuffer[frame->pathLengthChars] = L'\0';
                if (context->aborted) {
                    break;
                }
                continue;
            }

            if (entryIsDirectory) {
                if (kswordArkDeleteTreePushDirectory(context, childLengthChars)) {
                    descended = TRUE;
                    break;
                }
                // If the file cannot be opened or the depth limit is reached: delete as a leaf node as a fallback; empty directories can still succeed.
                (VOID)kswordArkDeleteTreeDeleteNode(context, childLengthChars, TRUE);
                context->pathBuffer[frame->pathLengthChars] = L'\0';
                if (context->aborted) {
                    break;
                }
                continue;
            }

            (VOID)kswordArkDeleteTreeDeleteNode(context, childLengthChars, FALSE);
            context->pathBuffer[frame->pathLengthChars] = L'\0';
            if (context->aborted) {
                break;
            }
        }

        if (descended) {
            continue;
        }

        if (frame->batchOffset >= frame->batchBytes) {
            frame->batchValid = FALSE;
        }
    }
}

NTSTATUS
kswordArkDriverDeletePathTree(
    _In_ const KSWORD_ARK_DELETE_PATH_REQUEST* request,
    _Inout_ KSWORD_ARK_DELETE_PATH_RESPONSE* response
    )
/*++

Routine Description:

    Recursive deletion request path. Note: Directories are expanded into a post-order sequence within R0 before
    being deleted individually; reparse points only delete the link itself. If depth or total entry count exceeds
    limits, the operation ends with PARTIAL and sets the corresponding flag; silent truncation is never performed.

Arguments:

    Request: A deletion request that has been snapshotted and validated by the IOCTL handler.
    Response: A statistics reply with size/version/requestFlags already initialized.

Return Value:

    STATUS_SUCCESS indicates the traversal process completed (success or failure is determined by Response->deleteStatus);
    Returns corresponding NTSTATUS if parameters are invalid or resources are insufficient.

--*/
{
    KswordArkDeleteTreeContext context;
    ULONG rootAttributes = 0UL;
    ULONG rootLengthChars;
    BOOLEAN continueOnError;
    NTSTATUS status;

    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    rootLengthChars = (ULONG)request->pathLengthChars;
    if (rootLengthChars == 0U || rootLengthChars >= KSWORD_ARK_DELETE_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    // Paths ending with a backslash point to volume roots or similar containers; recursively deleting a volume root is outside the scope of this feature.
    if (request->path[rootLengthChars - 1U] == L'\\') {
        return STATUS_INVALID_PARAMETER;
    }

    continueOnError =
        ((request->flags & KSWORD_ARK_DELETE_PATH_FLAG_CONTINUE_ON_ERROR) != 0UL) ? TRUE : FALSE;

    status = kswordArkDeleteTreePrepareContext(
        &context,
        response,
        request->flags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK,
        continueOnError);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(
        context.pathBuffer,
        request->path,
        (SIZE_T)rootLengthChars * sizeof(WCHAR));
    context.pathBuffer[rootLengthChars] = L'\0';

    status = kswordArkDeleteTreeQueryAttributes(
        context.pathBuffer,
        rootLengthChars,
        &rootAttributes);
    if (!NT_SUCCESS(status)) {
        kswordArkDeleteTreeRecordFailure(&context, rootLengthChars, status);
        response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_FAILED;
        kswordArkDeleteTreeReleaseContext(&context);
        return STATUS_SUCCESS;
    }

    response->visitedCount += 1U;

    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0UL) {
        (VOID)kswordArkDeleteTreeDeleteNode(&context, rootLengthChars, FALSE);
    }
    else if ((rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) {
        response->skippedReparseCount += 1U;
        response->responseFlags |= KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_REPARSE_SKIPPED;
        (VOID)kswordArkDeleteTreeDeleteNode(&context, rootLengthChars, TRUE);
    }
    else if (kswordArkDeleteTreePushDirectory(&context, rootLengthChars)) {
        kswordArkDeleteTreeRun(&context);
    }
    else {
        // Attempt direct deletion even if the root directory cannot be opened; this is correct and sufficient for empty directory scenarios.
        (VOID)kswordArkDeleteTreeDeleteNode(&context, rootLengthChars, TRUE);
    }

    if (response->failedCount == 0U &&
        (response->responseFlags &
            (KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_DEPTH_LIMITED |
             KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENTRY_LIMITED |
             KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED)) == 0UL) {
        response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED;
    }
    else if ((response->deletedFileCount + response->deletedDirectoryCount) > 0U) {
        response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_PARTIAL;
    }
    else {
        response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_FAILED;
    }

    kswordArkDeleteTreeReleaseContext(&context);
    return STATUS_SUCCESS;
}
