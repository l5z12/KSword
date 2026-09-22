/*++

Module Name:

    hook_scan.c

Abstract:

    Kernel inline hook and IAT/EAT diagnostic helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "hook_scan_support.h"

#include <ntimage.h>

#define KSW_HOOK_SCAN_IMPORT_DESCRIPTOR_LIMIT 1024UL
#define KSW_HOOK_SCAN_IMPORT_THUNK_LIMIT 16384UL

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

static const ULONG kGKswordArkInlineHookResponseHeaderSize =
    (ULONG)(sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY));

static const ULONG kGKswordArkIatEatHookResponseHeaderSize =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY));

static ULONG
kswordArkHookFnv1a32(
    _In_reads_bytes_(byteCount) const UCHAR* bytes,
    _In_ ULONG byteCount
    )
/*++

Routine Description:

    Computes a small FNV-1a hash for the first bytes captured in a hook row.
    The hash is diagnostic evidence only and is not used for authorization.

Arguments:

    Bytes - Input byte buffer.
    ByteCount - Number of bytes to hash.

Return Value:

    32-bit FNV-1a hash, or 0 when the input is empty.

--*/
{
    ULONG hashValue = 2166136261UL;
    ULONG byteIndex = 0UL;

    if (bytes == NULL || byteCount == 0UL) {
        return 0UL;
    }

    for (byteIndex = 0UL; byteIndex < byteCount; ++byteIndex) {
        hashValue ^= (ULONG)bytes[byteIndex];
        hashValue *= 16777619UL;
    }

    return hashValue;
}

static ULONG
kswordArkHookClassifyInlineBytes(
    _In_ ULONG_PTR functionAddress,
    _In_reads_(byteCount) const UCHAR* bytes,
    _In_ ULONG byteCount,
    _Out_ ULONG_PTR* targetAddressOut
    )
/*++

Routine Description:

    Identify common x64/x86 inline hook instruction patterns. Note: Only perform conservative parsing, not full
    disassembly; return the type and target address when obvious patches like JMP, MOV+JMP, RET, or INT3 are detected.

Arguments:

    FunctionAddress - Current function address.
    Bytes - First bytes of the function.
    ByteCount - Available byte count.
    TargetAddressOut: Returns the jump target; 0 if resolution fails.

Return Value:

    KSWORD_ARK_INLINE_HOOK_TYPE_*。

--*/
{
    ULONG_PTR targetAddress = 0U;
    ULONG hookType = KSWORD_ARK_INLINE_HOOK_TYPE_NONE;

    if (targetAddressOut != NULL) {
        *targetAddressOut = 0U;
    }
    if (bytes == NULL || byteCount == 0UL) {
        return KSWORD_ARK_INLINE_HOOK_TYPE_NONE;
    }

    if (byteCount >= 5UL && bytes[0] == 0xE9U) {
        LONG rel32 = 0;
        RtlCopyMemory(&rel32, bytes + 1, sizeof(rel32));
        targetAddress = functionAddress + 5U + (LONG_PTR)rel32;
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32;
    }
    else if (byteCount >= 2UL && bytes[0] == 0xEBU) {
        CHAR rel8 = (CHAR)bytes[1];
        targetAddress = functionAddress + 2U + (LONG_PTR)rel8;
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8;
    }
#if defined(_M_AMD64)
    else if (byteCount >= 14UL &&
        bytes[0] == 0xFFU &&
        bytes[1] == 0x25U) {
        LONG rel32 = 0;
        ULONG_PTR pointerAddress = 0U;
        RtlCopyMemory(&rel32, bytes + 2, sizeof(rel32));
        pointerAddress = functionAddress + 6U + (LONG_PTR)rel32;
        (VOID)kswordArkHookReadMemorySafe((const VOID*)pointerAddress, &targetAddress, sizeof(targetAddress));
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT;
    }
    else if (byteCount >= 12UL &&
        bytes[0] == 0x48U &&
        bytes[1] == 0xB8U &&
        bytes[10] == 0xFFU &&
        bytes[11] == 0xE0U) {
        RtlCopyMemory(&targetAddress, bytes + 2, sizeof(targetAddress));
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX;
    }
    else if (byteCount >= 13UL &&
        bytes[0] == 0x49U &&
        bytes[1] == 0xBBU &&
        bytes[10] == 0x41U &&
        bytes[11] == 0xFFU &&
        bytes[12] == 0xE3U) {
        RtlCopyMemory(&targetAddress, bytes + 2, sizeof(targetAddress));
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11;
    }
#endif
    else if (bytes[0] == 0xC3U || bytes[0] == 0xC2U) {
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH;
    }
    else if (bytes[0] == 0xCCU) {
        hookType = KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH;
    }

    if (targetAddressOut != NULL) {
        *targetAddressOut = targetAddress;
    }
    return hookType;
}

static NTSTATUS
kswordArkHookWriteKernelMemoryUnsafe(
    _In_ PVOID destination,
    _In_reads_bytes_(bytesToWrite) const VOID* source,
    _In_ SIZE_T bytesToWrite
    )
/*++

Routine Description:

    Write to kernel code pages. Note: This function is only called after explicit UI force; use an MDL to create a
    writable system mapping to avoid directly modifying CR0.WP, and release the mapping immediately after writing.

Arguments:

    Destination - Target kernel address.
    Source - Source bytes.
    BytesToWrite - Length to write.

Return Value:

    STATUS_SUCCESS or MDL/exception status.

--*/
{
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN pagesLocked = FALSE;

    if (destination == NULL || source == NULL || bytesToWrite == 0U || bytesToWrite > KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        mdl = IoAllocateMdl(destination, (ULONG)bytesToWrite, FALSE, FALSE, NULL);
        if (mdl == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // Note: This is the code page path for writing. Must use IoModifyAccess and record the locked page
        // state to avoid incorrectly unlocking an unlocked MDL in the Exit branch if Probe throws an exception.
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
        pagesLocked = TRUE;
        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            NULL,
            FALSE,
            NormalPagePriority);
        if (mappedAddress == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
        RtlCopyMemory(mappedAddress, source, bytesToWrite);
        // Note: Insert a memory barrier after writing to ensure a well-defined patch byte commit order on this CPU.
        // Instruction cache consistency is handled by x64 kernel code page mapping and subsequent execution paths; no undeclared routines are called here.
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

Exit:
    if (mappedAddress != NULL) {
        MmUnmapLockedPages(mappedAddress, mdl);
        mappedAddress = NULL;
    }
    if (mdl != NULL && pagesLocked) {
        MmUnlockPages(mdl);
        pagesLocked = FALSE;
    }
    if (mdl != NULL) {
        IoFreeMdl(mdl);
        mdl = NULL;
    }
    return status;
}

static VOID
kswordArkHookFillInlineEntry(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_z_ const CHAR* functionName,
    _In_ PVOID functionAddress,
    _In_reads_(KSWORD_ARK_KERNEL_HOOK_BYTES) const UCHAR* expectedBytes,
    _In_reads_(KSWORD_ARK_KERNEL_HOOK_BYTES) const UCHAR* currentBytes,
    _In_ ULONG hookType,
    _In_ ULONG_PTR targetAddress,
    _Inout_ KSWORD_ARK_INLINE_HOOK_ENTRY* entry
    )
/*++

Routine Description:

    Populate the Inline Hook response row. Note: This function only organizes diagnostic fields and performs no writes.

Arguments:

    ModuleInfo - module snapshot.
    ModuleEntry - Current module.
    FunctionName - Function name.
    FunctionAddress: function address.
    ExpectedBytes is a protocol-compatible field; the current implementation fills it with the runtime observation baseline, not the original disk bytes.
    CurrentBytes - Current number of bytes read.
    HookType: The detected Hook type.
    TargetAddress - Jump target.
    Entry - Output line.

Return Value:

    None. This function has no return value.

--*/
{
    const UCHAR* moduleFileName = NULL;
    ULONG moduleFileNameBytes = 0UL;
    const KswHookSystemModuleEntry* targetModule = NULL;

    RtlZeroMemory(entry, sizeof(*entry));
    entry->hookType = hookType;
    entry->functionAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
    entry->targetAddress = (ULONGLONG)targetAddress;
    entry->currentTargetAddress = (ULONGLONG)targetAddress;
    entry->moduleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
    entry->expectedOwnerBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
    entry->originalByteCount = KSWORD_ARK_KERNEL_HOOK_BYTES;
    entry->currentByteCount = KSWORD_ARK_KERNEL_HOOK_BYTES;
    entry->firstBytesHashStatus = KSWORD_ARK_KERNEL_HOOK_HASH_STATUS_CURRENT_BYTES;
    entry->firstBytesHash = kswordArkHookFnv1a32(currentBytes, KSWORD_ARK_KERNEL_HOOK_BYTES);
    entry->flags = 0UL;
    RtlCopyMemory(entry->expectedBytes, expectedBytes, KSWORD_ARK_KERNEL_HOOK_BYTES);
    RtlCopyMemory(entry->currentBytes, currentBytes, KSWORD_ARK_KERNEL_HOOK_BYTES);
    kswordArkHookCopyAnsi(entry->functionName, sizeof(entry->functionName), functionName);

    kswordArkHookGetModuleFileName(moduleEntry, &moduleFileName, &moduleFileNameBytes);
    kswordArkHookCopyBoundedAnsiToWide(
        moduleFileName,
        moduleFileNameBytes,
        entry->moduleName,
        KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);

    targetModule = kswordArkHookFindModuleForAddress(moduleInfo, targetAddress);
    if (targetModule != NULL) {
        const UCHAR* targetFileName = NULL;
        ULONG targetFileNameBytes = 0UL;

        entry->targetModuleBase = (ULONGLONG)(ULONG_PTR)targetModule->imageBase;
        kswordArkHookGetModuleFileName(targetModule, &targetFileName, &targetFileNameBytes);
        kswordArkHookCopyBoundedAnsiToWide(
            targetFileName,
            targetFileNameBytes,
            entry->targetModuleName,
            KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
    }

    if (hookType == KSWORD_ARK_INLINE_HOOK_TYPE_NONE) {
        entry->status = KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
        entry->moduleRangeState = KSWORD_ARK_KERNEL_HOOK_RANGE_WITHIN_EXPECTED;
    }
    else if (targetModule == moduleEntry) {
        entry->status = KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH;
        entry->moduleRangeState = KSWORD_ARK_KERNEL_HOOK_RANGE_WITHIN_EXPECTED;
    }
    else if (targetModule == NULL) {
        entry->status = KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH;
        entry->moduleRangeState = KSWORD_ARK_KERNEL_HOOK_RANGE_UNRESOLVED;
    }
    else {
        entry->status = KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS;
        entry->moduleRangeState = KSWORD_ARK_KERNEL_HOOK_RANGE_WITHIN_OTHER_MODULE;
    }
}

NTSTATUS
kswordArkDriverScanInlineHooks(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Scan for common Inline Hooks at the start of exported functions in kernel modules. Note: Use the loaded image's own
    export addresses as the scan source to identify obvious jumps/patches and classify them as clean/internal/suspicious.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    Request - Optional scan request.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS or query/parse failure.

--*/
{
    KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG entryCapacity = 0UL;
    ULONG moduleIndex = 0UL;
    ULONG requestFlags = 0UL;
    ULONG maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < kGKswordArkInlineHookResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request != NULL) {
        requestFlags = request->flags;
        if (request->maxEntries != 0UL) {
            maxEntries = request->maxEntries;
        }
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_KERNEL_HOOK_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);
    response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
    entryCapacity = (ULONG)((outputBufferLength - kGKswordArkInlineHookResponseHeaderSize) / sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY));
    if (entryCapacity > maxEntries) {
        entryCapacity = maxEntries;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED;
        *bytesWrittenOut = kGKswordArkInlineHookResponseHeaderSize;
        return STATUS_SUCCESS;
    }
    response->moduleCount = moduleInfo->numberOfModules;

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswHookSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const UCHAR* moduleFileName = NULL;
        ULONG moduleFileNameBytes = 0UL;
        IMAGE_NT_HEADERS ntHeaders;
        IMAGE_DATA_DIRECTORY exportDirectory;
        IMAGE_EXPORT_DIRECTORY exportHeader;
        ULONG nameArrayBytes = 0UL;
        ULONG ordinalArrayBytes = 0UL;
        ULONG functionArrayBytes = 0UL;
        ULONG exportNameIndex = 0UL;

        kswordArkHookGetModuleFileName(moduleEntry, &moduleFileName, &moduleFileNameBytes);
        if ((requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER) != 0UL &&
            request != NULL &&
            !kswordArkHookWideModuleFilterMatches(
                moduleFileName,
                moduleFileNameBytes,
                request->moduleName,
                KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)) {
            continue;
        }

        RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
        RtlZeroMemory(&exportDirectory, sizeof(exportDirectory));
        RtlZeroMemory(&exportHeader, sizeof(exportHeader));
        if (!kswordArkHookReadImageNtHeaders(moduleEntry, &ntHeaders) ||
            !kswordArkHookGetDataDirectory(&ntHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportDirectory) ||
            exportDirectory.VirtualAddress == 0UL ||
            !kswordArkHookReadImageBytes(moduleEntry, exportDirectory.VirtualAddress, &exportHeader, sizeof(exportHeader))) {
            continue;
        }

        if (exportHeader.AddressOfNames == 0UL ||
            exportHeader.AddressOfNameOrdinals == 0UL ||
            exportHeader.AddressOfFunctions == 0UL ||
            !kswordArkHookMultiplyUlong(exportHeader.NumberOfNames, sizeof(ULONG), &nameArrayBytes) ||
            !kswordArkHookMultiplyUlong(exportHeader.NumberOfNames, sizeof(USHORT), &ordinalArrayBytes) ||
            !kswordArkHookMultiplyUlong(exportHeader.NumberOfFunctions, sizeof(ULONG), &functionArrayBytes) ||
            !kswordArkHookValidateRvaRange(exportHeader.AddressOfNames, nameArrayBytes, moduleEntry->imageSize) ||
            !kswordArkHookValidateRvaRange(exportHeader.AddressOfNameOrdinals, ordinalArrayBytes, moduleEntry->imageSize) ||
            !kswordArkHookValidateRvaRange(exportHeader.AddressOfFunctions, functionArrayBytes, moduleEntry->imageSize)) {
            continue;
        }

        for (exportNameIndex = 0UL; exportNameIndex < exportHeader.NumberOfNames; ++exportNameIndex) {
            ULONG nameEntryRva = 0UL;
            ULONG ordinalEntryRva = 0UL;
            ULONG functionEntryRva = 0UL;
            ULONG nameRva = 0UL;
            USHORT ordinalIndex = 0U;
            CHAR exportNameBuffer[KSWORD_ARK_KERNEL_HOOK_NAME_CHARS] = { 0 };
            ULONG functionRva = 0UL;
            ULONG_PTR functionAddressValue = 0U;
            UCHAR currentBytes[KSWORD_ARK_KERNEL_HOOK_BYTES] = { 0 };
            UCHAR expectedBytes[KSWORD_ARK_KERNEL_HOOK_BYTES] = { 0 };
            ULONG_PTR targetAddress = 0U;
            ULONG hookType = KSWORD_ARK_INLINE_HOOK_TYPE_NONE;
            KSWORD_ARK_INLINE_HOOK_ENTRY tempEntry;

            if (!kswordArkHookAddRvaOffset(exportHeader.AddressOfNames, exportNameIndex, sizeof(ULONG), &nameEntryRva) ||
                !kswordArkHookAddRvaOffset(exportHeader.AddressOfNameOrdinals, exportNameIndex, sizeof(USHORT), &ordinalEntryRva) ||
                !kswordArkHookReadImageUlong(moduleEntry, nameEntryRva, &nameRva) ||
                !kswordArkHookReadImageUshort(moduleEntry, ordinalEntryRva, &ordinalIndex) ||
                ordinalIndex >= exportHeader.NumberOfFunctions) {
                continue;
            }

            if (!kswordArkHookAddRvaOffset(exportHeader.AddressOfFunctions, ordinalIndex, sizeof(ULONG), &functionEntryRva) ||
                !kswordArkHookReadImageUlong(moduleEntry, functionEntryRva, &functionRva) ||
                kswordArkHookIsRvaInsideDirectory(functionRva, &exportDirectory) ||
                !kswordArkHookImageAddressFromRva(moduleEntry, functionRva, &functionAddressValue) ||
                !kswordArkHookReadImageBytes(moduleEntry, functionRva, currentBytes, sizeof(currentBytes)) ||
                !kswordArkHookCopyImageAnsi(moduleEntry, nameRva, exportNameBuffer, sizeof(exportNameBuffer))) {
                continue;
            }

            /*
             * Note:
             * expectedBytes is a legacy compatibility field. R0 can currently read only loaded image
             * memory safely, so this is an observed runtime baseline, not a clean disk baseline.
             * The R3 UI supplements baseline bytes from the disk module at the same RVA and explicitly marks the differences in the details.
             */
            RtlCopyMemory(expectedBytes, currentBytes, sizeof(expectedBytes));
            hookType = kswordArkHookClassifyInlineBytes(
                functionAddressValue,
                currentBytes,
                KSWORD_ARK_KERNEL_HOOK_BYTES,
                &targetAddress);

            RtlZeroMemory(&tempEntry, sizeof(tempEntry));
            kswordArkHookFillInlineEntry(
                moduleInfo,
                moduleEntry,
                exportNameBuffer,
                (PVOID)functionAddressValue,
                expectedBytes,
                currentBytes,
                hookType,
                targetAddress,
                &tempEntry);

            if (tempEntry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN &&
                (requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN) == 0UL) {
                continue;
            }
            if (tempEntry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH &&
                (requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL) == 0UL) {
                continue;
            }

            response->totalCount += 1UL;
            if (response->returnedCount >= entryCapacity) {
                continue;
            }
            RtlCopyMemory(
                &response->entries[response->returnedCount],
                &tempEntry,
                sizeof(tempEntry));
            response->returnedCount += 1UL;
        }
    }

    response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
    *bytesWrittenOut = kGKswordArkInlineHookResponseHeaderSize +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY));
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverPatchInlineHook(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Fix Inline Hook instruction patching. Note: Ordinary requests only return force-required; only
    after force is applied does it compare expectedCurrentBytes and write restoreBytes or NOP patches.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Response length.
    Request - fix request.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates a valid response.

--*/
{
    KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE* response = NULL;
    UCHAR currentBytes[KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES] = { 0 };
    UCHAR patchBytes[KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    ULONG patchBytesCount = 0UL;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->functionAddress == 0ULL ||
        request->patchBytes == 0UL ||
        request->patchBytes > KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_KERNEL_HOOK_PROTOCOL_VERSION;
    response->functionAddress = request->functionAddress;
    response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
    response->lastStatus = STATUS_SUCCESS;
    patchBytesCount = request->patchBytes;

    if ((request->flags & KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE) == 0UL) {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED;
        response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    if (!kswordArkHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)request->functionAddress,
        currentBytes,
        patchBytesCount)) {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED;
        response->lastStatus = STATUS_ACCESS_VIOLATION;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    RtlCopyMemory(response->beforeBytes, currentBytes, patchBytesCount);

    if (RtlCompareMemory(currentBytes, request->expectedCurrentBytes, patchBytesCount) != patchBytesCount) {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    if (request->mode == KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES) {
        RtlCopyMemory(patchBytes, request->restoreBytes, patchBytesCount);
    }
    else if (request->mode == KSWORD_ARK_INLINE_PATCH_MODE_NOP_BRANCH) {
        RtlFillMemory(patchBytes, patchBytesCount, 0x90U);
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkHookWriteKernelMemoryUnsafe(
        (PVOID)(ULONG_PTR)request->functionAddress,
        patchBytes,
        patchBytesCount);
    response->lastStatus = status;
    if (NT_SUCCESS(status)) {
        response->bytesPatched = patchBytesCount;
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED;
        (VOID)kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)request->functionAddress,
            response->afterBytes,
            patchBytesCount);
    }
    else {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnumerateIatEatHooks(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate suspicious pointers in kernel module IAT/EAT. Note: IAT detection checks if the current target of an imported thunk falls
    within the declared import module; EAT detection checks if the exported RVA falls within its own image or is a forwarded export.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    Request - Scan request.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS or query status.

--*/
{
    KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG entryCapacity = 0UL;
    ULONG moduleIndex = 0UL;
    ULONG requestFlags = KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < kGKswordArkIatEatHookResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request != NULL && request->flags != 0UL) {
        requestFlags = request->flags;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_KERNEL_HOOK_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY);
    response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
    entryCapacity = (ULONG)((outputBufferLength - kGKswordArkIatEatHookResponseHeaderSize) / sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY));

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED;
        *bytesWrittenOut = kGKswordArkIatEatHookResponseHeaderSize;
        return STATUS_SUCCESS;
    }
    response->moduleCount = moduleInfo->numberOfModules;

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswHookSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const UCHAR* moduleFileName = NULL;
        ULONG moduleFileNameBytes = 0UL;
        IMAGE_NT_HEADERS ntHeaders;
        IMAGE_DATA_DIRECTORY exportDirectory;
        IMAGE_DATA_DIRECTORY importDirectory;

        kswordArkHookGetModuleFileName(moduleEntry, &moduleFileName, &moduleFileNameBytes);
        if ((requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER) != 0UL &&
            request != NULL &&
            !kswordArkHookWideModuleFilterMatches(
                moduleFileName,
                moduleFileNameBytes,
                request->moduleName,
                KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)) {
            continue;
        }

        RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
        RtlZeroMemory(&exportDirectory, sizeof(exportDirectory));
        RtlZeroMemory(&importDirectory, sizeof(importDirectory));
        if (!kswordArkHookReadImageNtHeaders(moduleEntry, &ntHeaders)) {
            continue;
        }
        (VOID)kswordArkHookGetDataDirectory(&ntHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportDirectory);
        (VOID)kswordArkHookGetDataDirectory(&ntHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT, &importDirectory);

        if ((requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS) != 0UL) {
            IMAGE_EXPORT_DIRECTORY exportHeader;
            ULONG functionArrayBytes = 0UL;
            ULONG nameArrayBytes = 0UL;
            ULONG ordinalArrayBytes = 0UL;
            ULONG exportNameIndex = 0UL;

            RtlZeroMemory(&exportHeader, sizeof(exportHeader));
            if (exportDirectory.VirtualAddress != 0UL &&
                kswordArkHookReadImageBytes(moduleEntry, exportDirectory.VirtualAddress, &exportHeader, sizeof(exportHeader)) &&
                exportHeader.AddressOfFunctions != 0UL &&
                exportHeader.AddressOfNames != 0UL &&
                exportHeader.AddressOfNameOrdinals != 0UL &&
                kswordArkHookMultiplyUlong(exportHeader.NumberOfFunctions, sizeof(ULONG), &functionArrayBytes) &&
                kswordArkHookMultiplyUlong(exportHeader.NumberOfNames, sizeof(ULONG), &nameArrayBytes) &&
                kswordArkHookMultiplyUlong(exportHeader.NumberOfNames, sizeof(USHORT), &ordinalArrayBytes) &&
                kswordArkHookValidateRvaRange(exportHeader.AddressOfFunctions, functionArrayBytes, moduleEntry->imageSize) &&
                kswordArkHookValidateRvaRange(exportHeader.AddressOfNames, nameArrayBytes, moduleEntry->imageSize) &&
                kswordArkHookValidateRvaRange(exportHeader.AddressOfNameOrdinals, ordinalArrayBytes, moduleEntry->imageSize)) {
                for (exportNameIndex = 0UL; exportNameIndex < exportHeader.NumberOfNames; ++exportNameIndex) {
                    ULONG nameEntryRva = 0UL;
                    ULONG ordinalEntryRva = 0UL;
                    ULONG functionEntryRva = 0UL;
                    ULONG nameRva = 0UL;
                    USHORT ordinalIndex = 0U;
                    ULONG functionRva = 0UL;
                    BOOLEAN suspicious = FALSE;
                    KSWORD_ARK_IAT_EAT_HOOK_ENTRY row;

                    if (!kswordArkHookAddRvaOffset(exportHeader.AddressOfNames, exportNameIndex, sizeof(ULONG), &nameEntryRva) ||
                        !kswordArkHookAddRvaOffset(exportHeader.AddressOfNameOrdinals, exportNameIndex, sizeof(USHORT), &ordinalEntryRva) ||
                        !kswordArkHookReadImageUlong(moduleEntry, nameEntryRva, &nameRva) ||
                        !kswordArkHookReadImageUshort(moduleEntry, ordinalEntryRva, &ordinalIndex) ||
                        ordinalIndex >= exportHeader.NumberOfFunctions ||
                        !kswordArkHookAddRvaOffset(exportHeader.AddressOfFunctions, ordinalIndex, sizeof(ULONG), &functionEntryRva) ||
                        !kswordArkHookReadImageUlong(moduleEntry, functionEntryRva, &functionRva)) {
                        continue;
                    }

                    if (kswordArkHookIsRvaInsideDirectory(functionRva, &exportDirectory)) {
                        suspicious = FALSE;
                    }
                    else if (!kswordArkHookValidateRvaRange(functionRva, 1UL, moduleEntry->imageSize)) {
                        suspicious = TRUE;
                    }
                    if (!suspicious && (requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN) == 0UL) {
                        continue;
                    }

                    response->totalCount += 1UL;
                    if (response->returnedCount >= entryCapacity) {
                        continue;
                    }
                    RtlZeroMemory(&row, sizeof(row));
                    row.hookClass = KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT;
                    row.status = suspicious ? KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS : KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
                    row.moduleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
                    row.currentTarget = (ULONGLONG)((ULONG_PTR)moduleEntry->imageBase + (ULONG_PTR)functionRva);
                    row.expectedTarget = row.currentTarget;
                    row.ordinal = (ULONG)ordinalIndex + exportHeader.Base;
                    (VOID)kswordArkHookCopyImageAnsi(moduleEntry, nameRva, row.functionName, sizeof(row.functionName));
                    kswordArkHookCopyBoundedAnsiToWide(moduleFileName, moduleFileNameBytes, row.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
                    RtlCopyMemory(&response->entries[response->returnedCount], &row, sizeof(row));
                    response->returnedCount += 1UL;
                }
            }
        }

        if ((requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS) != 0UL) {
            ULONG descriptorIndex = 0UL;
            ULONG importDirectoryEnd = 0UL;

            if (importDirectory.VirtualAddress == 0UL ||
                importDirectory.Size == 0UL ||
                importDirectory.Size > MAXULONG - importDirectory.VirtualAddress) {
                continue;
            }
            importDirectoryEnd = importDirectory.VirtualAddress + importDirectory.Size;

            for (descriptorIndex = 0UL;
                descriptorIndex < KSW_HOOK_SCAN_IMPORT_DESCRIPTOR_LIMIT;
                ++descriptorIndex) {
                ULONG descriptorRva = 0UL;
                IMAGE_IMPORT_DESCRIPTOR importDescriptor;
                CHAR importNameBuffer[KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS] = { 0 };
                const KswHookSystemModuleEntry* importModule = NULL;
                ULONG findIndex = 0UL;
                ULONG thunkIndex = 0UL;
                ULONG thunkRva = 0UL;

                if (!kswordArkHookAddRvaOffset(importDirectory.VirtualAddress, descriptorIndex, sizeof(IMAGE_IMPORT_DESCRIPTOR), &descriptorRva) ||
                    descriptorRva >= importDirectoryEnd ||
                    (importDirectoryEnd - descriptorRva) < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
                    !kswordArkHookReadImageBytes(moduleEntry, descriptorRva, &importDescriptor, sizeof(importDescriptor))) {
                    break;
                }
                if (importDescriptor.Name == 0UL) {
                    break;
                }
                if (importDescriptor.FirstThunk == 0UL ||
                    importDescriptor.FirstThunk > MAXULONG ||
                    !kswordArkHookCopyImageAnsi(moduleEntry, importDescriptor.Name, importNameBuffer, sizeof(importNameBuffer))) {
                    continue;
                }

                for (findIndex = 0UL; findIndex < moduleInfo->numberOfModules; ++findIndex) {
                    const UCHAR* candidateName = NULL;
                    ULONG candidateBytes = 0UL;

                    kswordArkHookGetModuleFileName(&moduleInfo->modules[findIndex], &candidateName, &candidateBytes);
                    if (kswordArkHookBoundedAnsiEqualsInsensitive(candidateName, candidateBytes, importNameBuffer)) {
                        importModule = &moduleInfo->modules[findIndex];
                        break;
                    }
                }

                thunkRva = importDescriptor.FirstThunk;
                if (!kswordArkHookValidateRvaRange(thunkRva, sizeof(ULONG_PTR), moduleEntry->imageSize)) {
                    continue;
                }

                for (thunkIndex = 0UL;
                    thunkIndex < KSW_HOOK_SCAN_IMPORT_THUNK_LIMIT;
                    ++thunkIndex) {
                    ULONG thunkEntryRva = 0UL;
                    ULONG_PTR thunkAddressValue = 0U;
                    ULONG_PTR target = 0U;
                    const KswHookSystemModuleEntry* targetModule = NULL;
                    BOOLEAN suspicious = FALSE;
                    KSWORD_ARK_IAT_EAT_HOOK_ENTRY row;

                    if (!kswordArkHookAddRvaOffset(thunkRva, thunkIndex, sizeof(ULONG_PTR), &thunkEntryRva) ||
                        !kswordArkHookImageAddressFromRva(moduleEntry, thunkEntryRva, &thunkAddressValue) ||
                        !kswordArkHookReadImageBytes(moduleEntry, thunkEntryRva, &target, sizeof(target))) {
                        break;
                    }
                    if (target == 0U) {
                        break;
                    }

                    targetModule = kswordArkHookFindModuleForAddress(moduleInfo, target);
                    if (importModule != NULL && targetModule != importModule) {
                        suspicious = TRUE;
                    }
                    if (!suspicious && (requestFlags & KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN) == 0UL) {
                        continue;
                    }

                    response->totalCount += 1UL;
                    if (response->returnedCount < entryCapacity) {
                        const UCHAR* targetName = NULL;
                        ULONG targetNameBytes = 0UL;

                        RtlZeroMemory(&row, sizeof(row));
                        row.hookClass = KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT;
                        row.status = suspicious ? KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS : KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
                        row.moduleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
                        row.thunkAddress = (ULONGLONG)thunkAddressValue;
                        row.currentTarget = (ULONGLONG)target;
                        row.targetModuleBase = targetModule ? (ULONGLONG)(ULONG_PTR)targetModule->imageBase : 0ULL;
                        row.ordinal = thunkIndex;
                        kswordArkHookCopyAnsi(row.functionName, sizeof(row.functionName), "<import-thunk>");
                        kswordArkHookCopyBoundedAnsiToWide(moduleFileName, moduleFileNameBytes, row.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
                        kswordArkHookCopyBoundedAnsiToWide((const UCHAR*)importNameBuffer, (ULONG)sizeof(importNameBuffer), row.importModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
                        if (targetModule != NULL) {
                            kswordArkHookGetModuleFileName(targetModule, &targetName, &targetNameBytes);
                            kswordArkHookCopyBoundedAnsiToWide(targetName, targetNameBytes, row.targetModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
                        }
                        RtlCopyMemory(&response->entries[response->returnedCount], &row, sizeof(row));
                        response->returnedCount += 1UL;
                    }
                }
            }
        }
    }

    response->status = KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
    *bytesWrittenOut = kGKswordArkIatEatHookResponseHeaderSize +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY));
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    return STATUS_SUCCESS;
}
