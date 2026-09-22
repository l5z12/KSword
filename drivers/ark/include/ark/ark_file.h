#pragma once

#include <ntddk.h>
#include "driver/KswordArkFileIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverDeletePath(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory
    );

/*
 * kswordArkDriverDeletePathWithFlags
 * Inputs:
 * - deleteFlags only accepts KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK; if not set, it indicates the original
 *   underlying Zw* scheme, with BACKEND_IRP/POSIX explicitly selecting the corresponding implementation.
 * Processing:
 * - All three backends share path validation and recursive scheduling boundaries. The low-level/POSIX backends normalize read-only
 *   attributes, while the IRP backend retains the target filesystem's native judgment for traditional FileDispositionInformation.
 * Return behavior:
 * - Returns the NTSTATUS of the selected backend; unsupported file systems or system capabilities fail as-is without cross-backend degradation.
 */
NTSTATUS
kswordArkDriverDeletePathWithFlags(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory,
    _In_ ULONG deleteFlags
    );

/*
 * kswordArkDriverDeletePathTree
 * Inputs:
 * - Request is a snapshot-verified deletion request; Response is a reply with size/version already filled.
 * Processing:
 * - In R0, use an explicit stack for post-order directory traversal and delete each item; for reparse points, delete only the link itself;
 *   The depth and total number of entries are limited by KSWORD_ARK_DELETE_PATH_MAX_*.
 * Return behavior:
 * - Return STATUS_SUCCESS indicates the traversal process is complete; the deletion semantics result is written to Response->deleteStatus;
 *   Returns corresponding NTSTATUS if parameters are invalid or resources are insufficient.
 */
NTSTATUS
kswordArkDriverDeletePathTree(
    _In_ const KSWORD_ARK_DELETE_PATH_REQUEST* request,
    _Inout_ KSWORD_ARK_DELETE_PATH_RESPONSE* response
    );

NTSTATUS
kswordArkDriverQueryFileInfo(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_FILE_INFO_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

// kswordArkDriverEnumerateDirectory: returns R0 filesystem directory rows via paging, without parsing private FS kernel structures.
// Continuous paging (next page startIndex equals previous page nextIndex) reuses the previous directory handle to resume scanning,
// avoiding reopening the directory and skipping the first N items for each page; non-contiguous requests automatically trigger a reopen.
NTSTATUS
kswordArkDriverEnumerateDirectory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

// kswordArkDriverResetDirectoryScanCache: release directory handles held by the directory rescan cache.
// Must be called in the driver unload path; otherwise, the driver exits with an unclosed handle.
VOID
kswordArkDriverResetDirectoryScanCache(
    VOID
    );

/*
 * kswordArkDriverSetFileIntegrity
 * Inputs:
 * - Request contains a kernel/NT-style path and target S-1-16-* RID.
 * Processing:
 * - Opens the file object and calls ZwSetSecurityObject with
 *   LABEL_SECURITY_INFORMATION. It does not patch filesystem/private objects.
 * Return behavior:
 * - Returns the NTSTATUS from path open, security descriptor construction, or
 *   ZwSetSecurityObject.
 */
NTSTATUS
kswordArkDriverSetFileIntegrity(
    _In_ const KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST* request
    );

EXTERN_C_END
