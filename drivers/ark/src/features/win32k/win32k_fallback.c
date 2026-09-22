/*++

Module Name:

    win32k_fallback.c

Abstract:

    PDB-independent tagWND and tagQ layout discovery.  Stable win32k exports
    are used only as bounded disassembly anchors.  A decoded layout is not
    trusted until live HWND generation values, object back-pointers, and the
    public PsGetThreadWin32Thread map agree in an attached GUI session.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query paths.

--*/

#include "win32k_fallback.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

#define KSW_WIN32K_HANDLE_SCAN_BYTES       0x0300UL
#define KSW_WIN32K_MAX_SESSION_HANDLES     0x00010000UL
#define KSW_WIN32K_MAX_SILO_OFFSET         0x00010000UL
#define KSW_WIN32K_WINDOW_HEAD_BYTES       0x20UL
#define KSW_WIN32K_OFFSET_UNKNOWN          MAXULONG

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((NTSTATUS)0xC000003EL)
#endif

typedef PVOID(NTAPI* KswUserGetSiloGlobalsFn)(VOID);

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

static BOOLEAN
KswordARKWin32kFallbackIsKernelAddress(
    _In_ ULONG_PTR address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (((ULONG64)address >> 48U) == 0xFFFFULL);
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkWin32kFallbackRead(
    _In_ ULONG_PTR address,
    _Out_writes_bytes_(size) PVOID buffer,
    _In_ SIZE_T size
    )
{
    if (buffer == NULL || size == 0U ||
        !KswordARKWin32kFallbackIsKernelAddress(address) ||
        address > MAXULONG_PTR - (size - 1U) ||
        !KswordARKWin32kFallbackIsKernelAddress(address + size - 1U)) {
        return FALSE;
    }
    return kswordArkRuntimeReadMemory((const VOID*)address, buffer, size);
}

static BOOLEAN
kswordArkWin32kFallbackReadUlong(
    _In_reads_bytes_(byteCount) const UCHAR* bytes,
    _In_ ULONG byteCount,
    _In_ ULONG offset,
    _Out_ ULONG* valueOut
    )
{
    if (bytes == NULL || valueOut == NULL ||
        offset > byteCount || sizeof(*valueOut) > byteCount - offset) {
        return FALSE;
    }
    RtlCopyMemory(valueOut, bytes + offset, sizeof(*valueOut));
    return TRUE;
}

static BOOLEAN
kswordArkWin32kFallbackSetUniqueOffset(
    _Inout_ ULONG* destination,
    _In_ ULONG candidate,
    _In_ ULONG maximum
    )
{
    if (destination == NULL || candidate > maximum) {
        return FALSE;
    }
    if (*destination == KSW_WIN32K_OFFSET_UNKNOWN) {
        *destination = candidate;
        return TRUE;
    }
    return *destination == candidate;
}

static BOOLEAN
kswordArkWin32kFallbackDecodeDirectBranch(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR instruction,
    _Out_ ULONG_PTR* targetOut
    )
{
    UCHAR bytes[5];
    LONG displacement = 0L;
    ULONG_PTR target = 0U;

    if (view == NULL || targetOut == NULL ||
        !kswordArkRuntimeAddressIsExecutable(view, instruction, sizeof(bytes)) ||
        !kswordArkRuntimeReadMemory((const VOID*)instruction, bytes, sizeof(bytes)) ||
        (bytes[0] != 0xE8U && bytes[0] != 0xE9U)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + 1U, sizeof(displacement));
    target = instruction + sizeof(bytes) + (LONG_PTR)displacement;
    if (!kswordArkRuntimeAddressIsExecutable(view, target, 1U)) {
        return FALSE;
    }
    *targetOut = target;
    return TRUE;
}

static BOOLEAN
kswordArkWin32kFallbackDecodeHandleLayoutAt(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR routineAddress,
    _Out_ KswWiN32KFallbackLayout* layoutOut
    )
/*++

Routine Description:

    Decode the private handle-table path used by ValidateHwnd.  The compound
    instruction relationships intentionally match semantics, not an entire
    build-specific byte string.

--*/
{
    UCHAR code[KSW_WIN32K_HANDLE_SCAN_BYTES];
    KswWiN32KFallbackLayout layout;
    ULONG index = 0UL;
    ULONG flagsInstruction = KSW_WIN32K_OFFSET_UNKNOWN;
    BOOLEAN foundTableSequence = FALSE;
    BOOLEAN foundObjectScale = FALSE;
    BOOLEAN foundHandleMetadata = FALSE;

    if (view == NULL || layoutOut == NULL ||
        !kswordArkRuntimeAddressIsExecutable(view, routineAddress, sizeof(code)) ||
        !kswordArkRuntimeReadMemory((const VOID*)routineAddress, code, sizeof(code))) {
        return FALSE;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    layout.siloServerInfo = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.siloHandleEntrySize = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.siloHandleEntries = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.siloObjectSlots = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.serverHandleCount = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.handleEntryShift = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.objectSlotStride = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.handleGeneration = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.handleType = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.handleFlags = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagWndHandle = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagWndThreadInfo = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagThreadInfoQueue = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagQActiveWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagQFocusWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagQCaptureWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.tagQCaretWindow = KSW_WIN32K_OFFSET_UNKNOWN;

    for (index = 0UL; index + 11UL < sizeof(code); ++index) {
        ULONG siloOffset = 0UL;

        if (code[index] == 0x4CU && code[index + 1UL] == 0x8BU &&
            code[index + 2UL] == 0x88U &&
            code[index + 7UL] == 0x49U && code[index + 8UL] == 0x3BU &&
            (code[index + 9UL] & 0xC7U) == 0x41U &&
            kswordArkWin32kFallbackReadUlong(
                code, sizeof(code), index + 3UL, &siloOffset) &&
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.siloServerInfo, siloOffset, KSW_WIN32K_MAX_SILO_OFFSET)) {
            return FALSE;
        }
        if (code[index] == 0x4CU && code[index + 1UL] == 0x8BU &&
            code[index + 2UL] == 0x88U &&
            code[index + 7UL] == 0x49U && code[index + 8UL] == 0x3BU &&
            (code[index + 9UL] & 0xC7U) == 0x41U) {
            if (!kswordArkWin32kFallbackSetUniqueOffset(
                    &layout.serverHandleCount,
                    code[index + 10UL],
                    0x40UL)) {
                return FALSE;
            }
        }
    }

    for (index = 0UL; index + 45UL < sizeof(code); ++index) {
        ULONG sizeOffset = 0UL;
        ULONG entriesOffset = 0UL;
        ULONG objectsOffset = 0UL;
        ULONG entriesIndex = 0UL;
        ULONG objectsIndex = 0UL;
        ULONG search = 0UL;

        if (code[index] != 0x0FU || code[index + 1UL] != 0xAFU ||
            code[index + 2UL] != 0xB8U ||
            !kswordArkWin32kFallbackReadUlong(
                code, sizeof(code), index + 3UL, &sizeOffset)) {
            continue;
        }
        for (search = index + 7UL; search <= index + 24UL; ++search) {
            if (code[search] == 0x4CU && code[search + 1UL] == 0x03U &&
                code[search + 2UL] == 0xB3U) {
                entriesIndex = search;
                break;
            }
        }
        if (entriesIndex == 0UL ||
            !kswordArkWin32kFallbackReadUlong(
                code, sizeof(code), entriesIndex + 3UL, &entriesOffset)) {
            continue;
        }
        for (search = entriesIndex + 7UL;
            search + 2UL < sizeof(code) && search <= entriesIndex + 36UL;
            ++search) {
            if (code[search] == 0x48U && code[search + 1UL] == 0x8BU &&
                code[search + 2UL] == 0x80U) {
                objectsIndex = search;
                break;
            }
        }
        if (objectsIndex == 0UL ||
            !kswordArkWin32kFallbackReadUlong(
                code, sizeof(code), objectsIndex + 3UL, &objectsOffset)) {
            continue;
        }
        if (!kswordArkWin32kFallbackSetUniqueOffset(
                &layout.siloHandleEntrySize, sizeOffset, KSW_WIN32K_MAX_SILO_OFFSET) ||
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.siloHandleEntries, entriesOffset, KSW_WIN32K_MAX_SILO_OFFSET) ||
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.siloObjectSlots, objectsOffset, KSW_WIN32K_MAX_SILO_OFFSET)) {
            return FALSE;
        }
        foundTableSequence = TRUE;

        for (search = objectsIndex + 7UL; search + 12UL < sizeof(code) &&
            search <= objectsIndex + 52UL; ++search) {
            if (code[search] == 0x48U && code[search + 1UL] == 0xC1U &&
                code[search + 2UL] == 0xF9U &&
                code[search + 4UL] == 0x8BU && code[search + 5UL] == 0xC9U &&
                code[search + 6UL] == 0x48U && code[search + 7UL] == 0x8DU &&
                code[search + 8UL] == 0x14U && code[search + 9UL] == 0x89U) {
                ULONG scaleSearch = 0UL;

                if (!kswordArkWin32kFallbackSetUniqueOffset(
                        &layout.handleEntryShift,
                        code[search + 3UL],
                        6UL)) {
                    return FALSE;
                }
                for (scaleSearch = search + 10UL;
                    scaleSearch + 3UL < sizeof(code) && scaleSearch <= search + 28UL;
                    ++scaleSearch) {
                    if (code[scaleSearch] == 0x48U &&
                        code[scaleSearch + 1UL] == 0x8DU &&
                        code[scaleSearch + 2UL] == 0x3CU &&
                        code[scaleSearch + 3UL] == 0xD0U) {
                        layout.objectSlotStride = 5UL * sizeof(ULONG64);
                        foundObjectScale = TRUE;
                        break;
                    }
                }
            }
        }
    }

    for (index = 0UL; index + 80UL < sizeof(code); ++index) {
        ULONG typeIndex = 0UL;
        ULONG flagIndex = 0UL;
        ULONG search = 0UL;

        if (code[index] != 0x66U || code[index + 1UL] != 0x41U ||
            code[index + 2UL] != 0x3BU || code[index + 3UL] != 0x46U) {
            continue;
        }
        for (search = index + 5UL;
            search + 4UL < sizeof(code) && search <= index + 64UL;
            ++search) {
            if (code[search] == 0x41U && code[search + 1UL] == 0x80U &&
                code[search + 2UL] == 0x7EU && code[search + 4UL] == 0x01U) {
                typeIndex = search;
                break;
            }
        }
        if (typeIndex == 0UL) {
            continue;
        }
        for (search = typeIndex + 5UL;
            search + 4UL < sizeof(code) && search <= typeIndex + 64UL;
            ++search) {
            if (code[search] == 0x41U && code[search + 1UL] == 0xF6U &&
                code[search + 2UL] == 0x46U && code[search + 4UL] == 0x01U) {
                flagIndex = search;
                break;
            }
        }
        if (flagIndex == 0UL ||
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.handleGeneration, code[index + 4UL], 0x80UL) ||
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.handleType, code[typeIndex + 3UL], 0x80UL) ||
            !kswordArkWin32kFallbackSetUniqueOffset(
                &layout.handleFlags, code[flagIndex + 3UL], 0x80UL)) {
            return FALSE;
        }
        flagsInstruction = flagIndex;
        foundHandleMetadata = TRUE;
    }

    if (flagsInstruction != KSW_WIN32K_OFFSET_UNKNOWN) {
        for (index = flagsInstruction + 5UL;
            index + 3UL < sizeof(code) && index <= flagsInstruction + 32UL;
            ++index) {
            if (code[index] == 0x48U && code[index + 1UL] == 0x8BU &&
                code[index + 2UL] == 0x77U &&
                !kswordArkWin32kFallbackSetUniqueOffset(
                    &layout.tagWndThreadInfo,
                    code[index + 3UL],
                    0x100UL)) {
                return FALSE;
            }
        }
    }

    if (!foundTableSequence || !foundObjectScale || !foundHandleMetadata ||
        layout.siloServerInfo == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.serverHandleCount == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.handleEntryShift == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.handleEntryShift < 3UL || layout.handleEntryShift > 6UL ||
        layout.objectSlotStride == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.tagWndThreadInfo == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.handleGeneration == layout.handleType ||
        layout.handleGeneration == layout.handleFlags ||
        layout.handleType == layout.handleFlags) {
        return FALSE;
    }
    *layoutOut = layout;
    return TRUE;
}

static BOOLEAN
kswordArkWin32kFallbackDecodeHandleLayout(
    _In_ const KswRuntimeImageView* view,
    _Out_ KswWiN32KFallbackLayout* layoutOut
    )
{
    ULONG_PTR exportAddress = 0U;
    ULONG_PTR target = 0U;
    ULONG index = 0UL;

    exportAddress = (ULONG_PTR)kswordArkRuntimeFindExport(view, "ValidateHwnd");
    if (exportAddress == 0U) {
        return FALSE;
    }
    if (kswordArkWin32kFallbackDecodeHandleLayoutAt(view, exportAddress, layoutOut)) {
        return TRUE;
    }
    for (index = 0UL; index < 0x40UL; ++index) {
        if (kswordArkWin32kFallbackDecodeDirectBranch(
                view, exportAddress + index, &target) &&
            kswordArkWin32kFallbackDecodeHandleLayoutAt(view, target, layoutOut)) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
kswordArkWin32kFallbackReferenceSessionProcess(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ ULONG sessionId,
    _Outptr_ PEPROCESS* processOut
    )
{
    ULONG index = 0UL;

    if (context == NULL || processOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processOut = NULL;
    for (index = 0UL; index < context->threadMapCount; ++index) {
        if (context->threadMap[index].sessionId == sessionId) {
            NTSTATUS status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)context->threadMap[index].processId,
                processOut);
            if (NT_SUCCESS(status) && *processOut != NULL) {
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_NOT_FOUND;
}

static const KswordArkWiN32KGuiThreadMapEntry*
kswordArkWin32kFallbackFindThreadInfo(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ ULONG64 threadInfo,
    _In_ ULONG sessionId
    )
{
    ULONG index = 0UL;

    if (context == NULL || threadInfo == 0ULL) {
        return NULL;
    }
    for (index = 0UL; index < context->threadMapCount; ++index) {
        if (context->threadMap[index].threadInfo == threadInfo &&
            context->threadMap[index].sessionId == sessionId) {
            return &context->threadMap[index];
        }
    }
    return NULL;
}

static BOOLEAN
kswordArkWin32kFallbackRequestMatchesSession(
    _In_ const KswWiN32KFallbackContext* context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG sessionId
    )
{
    ULONG index = 0UL;
    KswordWiN32KPsGetProcessSessionIdFn getSessionId = NULL;

    if (request == NULL) {
        return TRUE;
    }
    if (request->sessionId == 0UL &&
        (request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL) {
        getSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
        if (getSessionId == NULL ||
            getSessionId(PsGetCurrentProcess()) != sessionId) {
            return FALSE;
        }
    }
    if (request->sessionId != 0UL && request->sessionId != sessionId) {
        return FALSE;
    }
    if (request->processId == 0UL && request->threadId == 0UL) {
        return TRUE;
    }
    for (index = 0UL; index < context->threadMapCount; ++index) {
        const KswordArkWiN32KGuiThreadMapEntry* entry =
            &context->threadMap[index];
        if (entry->sessionId == sessionId &&
            (request->processId == 0UL || request->processId == entry->processId) &&
            (request->threadId == 0UL || request->threadId == entry->threadId)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kFallbackSessionAlreadyVisited(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ ULONG mapIndex
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < mapIndex; ++index) {
        if (context->threadMap[index].sessionId ==
            context->threadMap[mapIndex].sessionId) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kFallbackInferHandleOffset(
    _In_ ULONG_PTR tagWnd,
    _In_ ULONG64 hwnd,
    _Out_ ULONG* offsetOut
    )
{
    UCHAR head[KSW_WIN32K_WINDOW_HEAD_BYTES];
    ULONG matchCount = 0UL;
    ULONG matchOffset = 0UL;
    ULONG offset = 0UL;

    if (offsetOut == NULL ||
        !kswordArkWin32kFallbackRead(tagWnd, head, sizeof(head))) {
        return FALSE;
    }
    for (offset = 0UL; offset + sizeof(ULONG64) <= sizeof(head);
        offset += sizeof(ULONG64)) {
        ULONG64 value = 0ULL;
        RtlCopyMemory(&value, head + offset, sizeof(value));
        if (value == hwnd) {
            matchOffset = offset;
            matchCount += 1UL;
        }
    }
    if (matchCount != 1UL) {
        return FALSE;
    }
    *offsetOut = matchOffset;
    return TRUE;
}

NTSTATUS
kswordArkWin32kFallbackInitialize(
    _Out_ KswWiN32KFallbackContext* context
    )
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleBytes = 0UL;
    KswRuntimeImageView baseView;
    KswRuntimeImageView fullView;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(context, sizeof(*context));
    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    if (!kswordArkWin32kFindModuleByName(
            moduleInfo, "win32kbase.sys", &context->win32kbase) ||
        !kswordArkWin32kFindModuleByName(
            moduleInfo, "win32kfull.sys", &context->win32kfull)) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        return STATUS_NOT_FOUND;
    }
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    UNREFERENCED_PARAMETER(moduleBytes);

    if (!kswordArkRuntimeInitializeImageView(
            context->win32kbase.imageBase,
            context->win32kbase.imageSize,
            &baseView) ||
        !kswordArkRuntimeInitializeImageView(
            context->win32kfull.imageBase,
            context->win32kfull.imageSize,
            &fullView)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    context->userGetSiloGlobals = (ULONG_PTR)kswordArkRuntimeFindExport(
        &baseView,
        "UserGetSiloGlobals");
    context->handleLayoutResolved =
        context->userGetSiloGlobals != 0U &&
        kswordArkWin32kFallbackDecodeHandleLayout(&baseView, &context->layout);
    if (!context->handleLayoutResolved) {
        RtlZeroMemory(&context->layout, sizeof(context->layout));
        context->layout.tagWndHandle = KSW_WIN32K_OFFSET_UNKNOWN;
        context->layout.tagQCaretWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    }
    context->queueLayoutResolved = kswordArkWin32kFallbackDecodeQueueLayout(
        &fullView,
        &context->layout);
    if (!context->handleLayoutResolved && !context->queueLayoutResolved) {
        return STATUS_NOT_SUPPORTED;
    }

    status = kswordArkWin32kBuildGuiThreadMap(
        KSW_WIN32K_FALLBACK_MAP_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG,
        &context->threadMap,
        &context->threadMapCount,
        &context->threadMapTruncated);
    if (!NT_SUCCESS(status) || context->threadMap == NULL ||
        context->threadMapCount == 0UL) {
        kswordArkWin32kFallbackCleanup(context);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    return STATUS_SUCCESS;
}

VOID
kswordArkWin32kFallbackCleanup(
    _Inout_ KswWiN32KFallbackContext* context
    )
{
    if (context == NULL) {
        return;
    }
    if (context->threadMap != NULL) {
        ExFreePoolWithTag(context->threadMap, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    RtlZeroMemory(context, sizeof(*context));
}

NTSTATUS
kswordArkWin32kFallbackEnumerateWindows(
    _Inout_ KswWiN32KFallbackContext* context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_writes_(windowCapacity) KswWiN32KFallbackWindow* windows,
    _In_ ULONG windowCapacity,
    _Out_ ULONG* windowCountOut,
    _Out_ ULONG* totalCountOut,
    _Out_ BOOLEAN* truncatedOut
    )
{
    ULONG mapIndex = 0UL;
    ULONG windowCount = 0UL;
    ULONG totalCount = 0UL;
    ULONG inferredHandleOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    BOOLEAN truncated = FALSE;
    BOOLEAN validatedSession = FALSE;

    if (context == NULL || windows == NULL || windowCapacity == 0UL ||
        windowCountOut == NULL || totalCountOut == NULL || truncatedOut == NULL ||
        !context->handleLayoutResolved || context->threadMap == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *windowCountOut = 0UL;
    *totalCountOut = 0UL;
    *truncatedOut = FALSE;
    RtlZeroMemory(windows, sizeof(*windows) * windowCapacity);

    for (mapIndex = 0UL; mapIndex < context->threadMapCount; ++mapIndex) {
        const ULONG kSessionId = context->threadMap[mapIndex].sessionId;
        PEPROCESS sessionProcess = NULL;
        DECLSPEC_ALIGN(16) UCHAR attachState[128];
        BOOLEAN attached = FALSE;
        PVOID siloGlobals = NULL;
        ULONG_PTR serverInfo = 0U;
        ULONG_PTR handleEntries = 0U;
        ULONG_PTR objectSlots = 0U;
        ULONG_PTR handleCountValue = 0U;
        ULONG handleEntrySize = 0UL;
        ULONG handleCount = 0UL;
        ULONG handleIndex = 0UL;
        NTSTATUS status = STATUS_SUCCESS;

        if (kswordArkWin32kFallbackSessionAlreadyVisited(context, mapIndex) ||
            !kswordArkWin32kFallbackRequestMatchesSession(context, request, kSessionId)) {
            continue;
        }
        status = kswordArkWin32kFallbackReferenceSessionProcess(
            context,
            kSessionId,
            &sessionProcess);
        if (!NT_SUCCESS(status) || sessionProcess == NULL) {
            truncated = TRUE;
            continue;
        }
        RtlZeroMemory(attachState, sizeof(attachState));
        KeStackAttachProcess((PVOID)sessionProcess, attachState);
        attached = TRUE;
        __try {
            siloGlobals = ((KswUserGetSiloGlobalsFn)
                context->userGetSiloGlobals)();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            siloGlobals = NULL;
        }
        if (siloGlobals == NULL ||
            !kswordArkWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + context->layout.siloServerInfo,
                &serverInfo,
                sizeof(serverInfo)) ||
            !kswordArkWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + context->layout.siloHandleEntrySize,
                &handleEntrySize,
                sizeof(handleEntrySize)) ||
            !kswordArkWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + context->layout.siloHandleEntries,
                &handleEntries,
                sizeof(handleEntries)) ||
            !kswordArkWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + context->layout.siloObjectSlots,
                &objectSlots,
                sizeof(objectSlots)) ||
            !kswordArkWin32kFallbackRead(
                serverInfo + context->layout.serverHandleCount,
                &handleCountValue,
                sizeof(handleCountValue)) ||
            !KswordARKWin32kFallbackIsKernelAddress(serverInfo) ||
            !KswordARKWin32kFallbackIsKernelAddress(handleEntries) ||
            !KswordARKWin32kFallbackIsKernelAddress(objectSlots) ||
            handleEntrySize != (1UL << context->layout.handleEntryShift) ||
            handleEntrySize < 8UL || handleEntrySize > 0x40UL ||
            handleCountValue == 0U) {
            truncated = TRUE;
            goto DetachSession;
        }
        handleCount = handleCountValue > KSW_WIN32K_MAX_SESSION_HANDLES
            ? KSW_WIN32K_MAX_SESSION_HANDLES
            : (ULONG)handleCountValue;
        if (handleCountValue > KSW_WIN32K_MAX_SESSION_HANDLES) {
            truncated = TRUE;
        }

        for (handleIndex = 0UL; handleIndex < handleCount; ++handleIndex) {
            ULONG_PTR entryAddress = 0U;
            ULONG_PTR slotAddress = 0U;
            ULONG_PTR tagWnd = 0U;
            ULONG64 threadInfo = 0ULL;
            ULONG64 hwnd = 0ULL;
            USHORT generation = 0U;
            UCHAR type = 0U;
            UCHAR flags = 0U;
            ULONG handleOffset = 0UL;
            const KswordArkWiN32KGuiThreadMapEntry* owner = NULL;

            if (handleEntries > MAXULONG_PTR -
                    ((ULONG_PTR)handleIndex * handleEntrySize) ||
                objectSlots > MAXULONG_PTR -
                    ((ULONG_PTR)handleIndex * context->layout.objectSlotStride)) {
                truncated = TRUE;
                break;
            }
            entryAddress = handleEntries + ((ULONG_PTR)handleIndex * handleEntrySize);
            slotAddress = objectSlots +
                ((ULONG_PTR)handleIndex * context->layout.objectSlotStride);
            if (!kswordArkWin32kFallbackRead(
                    entryAddress + context->layout.handleType,
                    &type,
                    sizeof(type)) ||
                !kswordArkWin32kFallbackRead(
                    entryAddress + context->layout.handleFlags,
                    &flags,
                    sizeof(flags)) ||
                !kswordArkWin32kFallbackRead(
                    entryAddress + context->layout.handleGeneration,
                    &generation,
                    sizeof(generation)) ||
                type != 1U || (flags & 1U) != 0U ||
                !kswordArkWin32kFallbackRead(
                    slotAddress,
                    &tagWnd,
                    sizeof(tagWnd)) ||
                !KswordARKWin32kFallbackIsKernelAddress(tagWnd) ||
                !kswordArkWin32kFallbackRead(
                    tagWnd + context->layout.tagWndThreadInfo,
                    &threadInfo,
                    sizeof(threadInfo))) {
                continue;
            }
            owner = kswordArkWin32kFallbackFindThreadInfo(
                context,
                threadInfo,
                kSessionId);
            if (owner == NULL) {
                continue;
            }
            hwnd = (ULONG64)((handleIndex & 0xFFFFUL) |
                (((ULONG)generation & 0x7FFFUL) << 16U));
            if (!kswordArkWin32kFallbackInferHandleOffset(
                    tagWnd,
                    hwnd,
                    &handleOffset)) {
                continue;
            }
            if (inferredHandleOffset == KSW_WIN32K_OFFSET_UNKNOWN) {
                inferredHandleOffset = handleOffset;
            }
            else if (inferredHandleOffset != handleOffset) {
                if (attached) {
                    KeUnstackDetachProcess(attachState);
                }
                ObDereferenceObject(sessionProcess);
                RtlZeroMemory(windows, sizeof(*windows) * windowCapacity);
                return STATUS_DATA_ERROR;
            }
            validatedSession = TRUE;
            if (request != NULL &&
                ((request->processId != 0UL && request->processId != owner->processId) ||
                 (request->threadId != 0UL && request->threadId != owner->threadId))) {
                continue;
            }
            totalCount += 1UL;
            if (windowCount >= windowCapacity) {
                truncated = TRUE;
                continue;
            }
            windows[windowCount].hwnd = hwnd;
            windows[windowCount].tagWnd = (ULONG64)tagWnd;
            windows[windowCount].threadInfo = threadInfo;
            windows[windowCount].processId = owner->processId;
            windows[windowCount].threadId = owner->threadId;
            windows[windowCount].sessionId = owner->sessionId;
            windowCount += 1UL;
        }

DetachSession:
        if (attached) {
            KeUnstackDetachProcess(attachState);
        }
        ObDereferenceObject(sessionProcess);
    }

    if (!validatedSession || inferredHandleOffset == KSW_WIN32K_OFFSET_UNKNOWN) {
        RtlZeroMemory(windows, sizeof(*windows) * windowCapacity);
        return STATUS_NOT_FOUND;
    }
    context->layout.tagWndHandle = inferredHandleOffset;
    *windowCountOut = windowCount;
    *totalCountOut = totalCount;
    *truncatedOut = truncated || context->threadMapTruncated;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkWin32kFallbackResolveWindowPointer(
    _In_ ULONG64 windowPointer,
    _In_ ULONG sessionId,
    _In_reads_(windowCount) const KswWiN32KFallbackWindow* windows,
    _In_ ULONG windowCount,
    _Out_ ULONG64* hwndOut
    )
{
    ULONG index = 0UL;

    if (hwndOut == NULL) {
        return FALSE;
    }
    *hwndOut = 0ULL;
    if (windowPointer == 0ULL) {
        return TRUE;
    }
    for (index = 0UL; index < windowCount; ++index) {
        if (windows[index].tagWnd == windowPointer &&
            windows[index].sessionId == sessionId) {
            *hwndOut = windows[index].hwnd;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
kswordArkWin32kFallbackReadQueue(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ const KswordArkWiN32KGuiThreadMapEntry* threadEntry,
    _In_reads_(windowCount) const KswWiN32KFallbackWindow* windows,
    _In_ ULONG windowCount,
    _Out_ KswWiN32KFallbackQueue* queueOut
    )
{
    PEPROCESS sessionProcess = NULL;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    ULONG_PTR queue = 0U;
    ULONG64 active = 0ULL;
    ULONG64 focus = 0ULL;
    ULONG64 capture = 0ULL;
    ULONG64 caret = 0ULL;
    BOOLEAN result = FALSE;

    if (context == NULL || threadEntry == NULL || windows == NULL ||
        queueOut == NULL || !context->queueLayoutResolved ||
        context->layout.tagThreadInfoQueue == KSW_WIN32K_OFFSET_UNKNOWN ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !NT_SUCCESS(kswordArkWin32kFallbackReferenceSessionProcess(
            context, threadEntry->sessionId, &sessionProcess)) ||
        sessionProcess == NULL) {
        return FALSE;
    }
    RtlZeroMemory(queueOut, sizeof(*queueOut));
    RtlZeroMemory(attachState, sizeof(attachState));
    KeStackAttachProcess((PVOID)sessionProcess, attachState);

    if (kswordArkWin32kFallbackRead(
            (ULONG_PTR)threadEntry->threadInfo + context->layout.tagThreadInfoQueue,
            &queue,
            sizeof(queue)) &&
        KswordARKWin32kFallbackIsKernelAddress(queue) &&
        kswordArkWin32kFallbackRead(
            queue + context->layout.tagQActiveWindow,
            &active,
            sizeof(active)) &&
        kswordArkWin32kFallbackRead(
            queue + context->layout.tagQFocusWindow,
            &focus,
            sizeof(focus)) &&
        kswordArkWin32kFallbackRead(
            queue + context->layout.tagQCaptureWindow,
            &capture,
            sizeof(capture)) &&
        kswordArkWin32kFallbackResolveWindowPointer(
            active, threadEntry->sessionId, windows, windowCount,
            &queueOut->activeHwnd) &&
        kswordArkWin32kFallbackResolveWindowPointer(
            focus, threadEntry->sessionId, windows, windowCount,
            &queueOut->focusHwnd) &&
        kswordArkWin32kFallbackResolveWindowPointer(
            capture, threadEntry->sessionId, windows, windowCount,
            &queueOut->captureHwnd)) {
        if (context->layout.tagQCaretWindow != KSW_WIN32K_OFFSET_UNKNOWN) {
            if (!kswordArkWin32kFallbackRead(
                    queue + context->layout.tagQCaretWindow,
                    &caret,
                    sizeof(caret)) ||
                !kswordArkWin32kFallbackResolveWindowPointer(
                    caret, threadEntry->sessionId, windows, windowCount,
                    &queueOut->caretHwnd)) {
                queueOut->caretHwnd = 0ULL;
            }
        }
        queueOut->queueObject = (ULONG64)queue;
        result = TRUE;
    }
    KeUnstackDetachProcess(attachState);
    ObDereferenceObject(sessionProcess);
    return result;
}

VOID
kswordArkWin32kFallbackPublishOffsets(
    _In_ const KswWiN32KFallbackContext* context,
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* offsets
    )
{
    if (offsets == NULL) {
        return;
    }
    kswordArkWin32kInitializeOffsets(offsets);
    if (context == NULL) {
        return;
    }
    if (context->handleLayoutResolved) {
        offsets->tagWndThreadInfo = context->layout.tagWndThreadInfo;
    }
    if (context->queueLayoutResolved) {
        offsets->tagThreadInfoQueue = context->layout.tagThreadInfoQueue;
        offsets->tagQActiveWindow = context->layout.tagQActiveWindow;
        offsets->tagQFocusWindow = context->layout.tagQFocusWindow;
        offsets->tagQCaptureWindow = context->layout.tagQCaptureWindow;
        if (context->layout.tagQCaretWindow != KSW_WIN32K_OFFSET_UNKNOWN) {
            offsets->tagQCaretWindow = context->layout.tagQCaretWindow;
        }
    }
}

ULONG64
kswordArkWin32kFallbackProbeCapabilityMask(
    VOID
    )
{
    KswWiN32KFallbackContext context;
    NTSTATUS status = kswordArkWin32kFallbackInitialize(&context);
    ULONG64 mask = 0ULL;

    if (!NT_SUCCESS(status)) {
        return 0ULL;
    }
    if (context.handleLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGWND_SIGNATURE;
    }
    if (context.queueLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGQ_SIGNATURE;
    }
    kswordArkWin32kFallbackCleanup(&context);
    return mask;
}
