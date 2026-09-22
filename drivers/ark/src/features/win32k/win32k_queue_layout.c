/*++

Module Name:

    win32k_queue_layout.c

Abstract:

    PDB-independent tagTHREADINFO/tagQ layout decoder.  NtUserGetGUIThreadInfo
    is only an executable anchor: candidates must preserve the complete helper
    relationship and the caller later validates every non-null tagQ window
    pointer against the independently enumerated tagWND set.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query paths.

--*/

#include "win32k_fallback.h"

#define KSW_WIN32K_QUEUE_WRAPPER_BYTES     0x0160UL
#define KSW_WIN32K_QUEUE_HELPER_BYTES      0x0300UL
#define KSW_WIN32K_MAX_PRIVATE_OFFSET      0x00002000UL
#define KSW_WIN32K_OFFSET_UNKNOWN          MAXULONG

static BOOLEAN
kswordArkWin32kQueueReadUlong(
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
kswordArkWin32kQueueSetUniqueOffset(
    _Inout_ ULONG* destination,
    _In_ ULONG candidate
    )
{
    if (destination == NULL || candidate > KSW_WIN32K_MAX_PRIVATE_OFFSET) {
        return FALSE;
    }
    if (*destination == KSW_WIN32K_OFFSET_UNKNOWN) {
        *destination = candidate;
        return TRUE;
    }
    return *destination == candidate;
}

static BOOLEAN
kswordArkWin32kQueueDecodeDirectBranch(
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
kswordArkWin32kQueueDecodeHelper(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR helperAddress,
    _Inout_ KswWiN32KFallbackLayout* layout
    )
{
    UCHAR code[KSW_WIN32K_QUEUE_HELPER_BYTES];
    ULONG index = 0UL;
    BOOLEAN sizeCheck = FALSE;
    ULONG queueOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    ULONG activeOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    ULONG focusOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    ULONG captureOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    ULONG caretOffset = KSW_WIN32K_OFFSET_UNKNOWN;

    if (view == NULL || layout == NULL ||
        !kswordArkRuntimeAddressIsExecutable(view, helperAddress, sizeof(code)) ||
        !kswordArkRuntimeReadMemory((const VOID*)helperAddress, code, sizeof(code))) {
        return FALSE;
    }

    /* The helper first rejects any GUITHREADINFO packet that is not 0x48. */
    for (index = 0UL; index + 3UL < 0x30UL; ++index) {
        if (code[index] == 0x83U && code[index + 1UL] == 0x3AU &&
            code[index + 2UL] == 0x48U) {
            sizeCheck = TRUE;
            break;
        }
    }
    if (!sizeCheck) {
        return FALSE;
    }

    /* Null thread-info selects the current thread; both paths converge on tagQ. */
    for (index = 0UL; index + 14UL < 0x80UL; ++index) {
        ULONG candidate = 0UL;

        if (code[index] == 0x48U && code[index + 1UL] == 0x85U &&
            code[index + 2UL] == 0xC9U && code[index + 3UL] == 0x74U &&
            code[index + 5UL] == 0x48U && code[index + 6UL] == 0x8BU &&
            (code[index + 7UL] & 0xC7U) == 0x81U &&
            kswordArkWin32kQueueReadUlong(
                code, sizeof(code), index + 8UL, &candidate) &&
            !kswordArkWin32kQueueSetUniqueOffset(&queueOffset, candidate)) {
            return FALSE;
        }
    }

    /* active/focus/capture are dereferenced tagWND slots copied to +8/+10/+18. */
    for (index = 0UL; index + 18UL < sizeof(code); ++index) {
        ULONG sourceOffset = 0UL;
        UCHAR outputOffset = 0U;
        ULONG* destination = NULL;

        if (code[index] != 0x48U || code[index + 1UL] != 0x8BU ||
            code[index + 2UL] != 0x87U ||
            code[index + 7UL] != 0x48U || code[index + 8UL] != 0x85U ||
            code[index + 9UL] != 0xC0U || code[index + 10UL] != 0x74U ||
            code[index + 11UL] != 0x03U ||
            code[index + 12UL] != 0x48U || code[index + 13UL] != 0x8BU ||
            code[index + 14UL] != 0x00U ||
            code[index + 15UL] != 0x48U || code[index + 16UL] != 0x89U ||
            code[index + 17UL] != 0x43U ||
            !kswordArkWin32kQueueReadUlong(
                code, sizeof(code), index + 3UL, &sourceOffset)) {
            continue;
        }
        outputOffset = code[index + 18UL];
        if (outputOffset == 0x08U) {
            destination = &activeOffset;
        }
        else if (outputOffset == 0x10U) {
            destination = &focusOffset;
        }
        else if (outputOffset == 0x18U) {
            destination = &captureOffset;
        }
        if (destination != NULL &&
            !kswordArkWin32kQueueSetUniqueOffset(destination, sourceOffset)) {
            return FALSE;
        }
    }

    /* caret is optional on a build, but when present it is copied to +0x30. */
    for (index = 0UL; index + 16UL < sizeof(code); ++index) {
        ULONG sourceOffset = 0UL;
        ULONG search = 0UL;

        if (code[index] != 0x48U || code[index + 1UL] != 0x8BU ||
            code[index + 2UL] != 0x87U ||
            code[index + 7UL] != 0x48U || code[index + 8UL] != 0x85U ||
            code[index + 9UL] != 0xC0U || code[index + 10UL] != 0x0FU ||
            code[index + 11UL] != 0x84U ||
            !kswordArkWin32kQueueReadUlong(
                code, sizeof(code), index + 3UL, &sourceOffset)) {
            continue;
        }
        for (search = index + 16UL;
            search + 6UL < sizeof(code) && search <= index + 64UL;
            ++search) {
            if (code[search] == 0x48U && code[search + 1UL] == 0x8BU &&
                code[search + 2UL] == 0x00U &&
                code[search + 3UL] == 0x48U && code[search + 4UL] == 0x89U &&
                code[search + 5UL] == 0x43U && code[search + 6UL] == 0x30U) {
                if (!kswordArkWin32kQueueSetUniqueOffset(
                        &caretOffset, sourceOffset)) {
                    return FALSE;
                }
                break;
            }
        }
    }

    if (queueOffset == KSW_WIN32K_OFFSET_UNKNOWN ||
        activeOffset == KSW_WIN32K_OFFSET_UNKNOWN ||
        focusOffset == KSW_WIN32K_OFFSET_UNKNOWN ||
        captureOffset == KSW_WIN32K_OFFSET_UNKNOWN ||
        activeOffset == focusOffset || activeOffset == captureOffset ||
        focusOffset == captureOffset) {
        return FALSE;
    }
    layout->tagThreadInfoQueue = queueOffset;
    layout->tagQActiveWindow = activeOffset;
    layout->tagQFocusWindow = focusOffset;
    layout->tagQCaptureWindow = captureOffset;
    layout->tagQCaretWindow = caretOffset;
    return TRUE;
}

BOOLEAN
kswordArkWin32kFallbackDecodeQueueLayout(
    _In_ const KswRuntimeImageView* view,
    _Inout_ KswWiN32KFallbackLayout* layout
    )
{
    ULONG_PTR wrapper = 0U;
    ULONG_PTR acceptedTarget = 0U;
    KswWiN32KFallbackLayout acceptedLayout;
    ULONG index = 0UL;

    if (view == NULL || layout == NULL) {
        return FALSE;
    }
    wrapper = (ULONG_PTR)kswordArkRuntimeFindExport(view, "NtUserGetGUIThreadInfo");
    if (wrapper == 0U ||
        !kswordArkRuntimeAddressIsExecutable(view, wrapper, KSW_WIN32K_QUEUE_WRAPPER_BYTES)) {
        return FALSE;
    }
    RtlZeroMemory(&acceptedLayout, sizeof(acceptedLayout));
    for (index = 0UL; index < KSW_WIN32K_QUEUE_WRAPPER_BYTES; ++index) {
        ULONG_PTR target = 0U;
        KswWiN32KFallbackLayout candidate = *layout;

        if (!kswordArkWin32kQueueDecodeDirectBranch(
                view, wrapper + index, &target) ||
            !kswordArkWin32kQueueDecodeHelper(view, target, &candidate)) {
            continue;
        }
        if (acceptedTarget != 0U && acceptedTarget != target) {
            return FALSE;
        }
        acceptedTarget = target;
        acceptedLayout = candidate;
    }
    if (acceptedTarget == 0U) {
        return FALSE;
    }
    *layout = acceptedLayout;
    return TRUE;
}
