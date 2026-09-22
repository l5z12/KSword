/*++

Module Name:

    object_header_fallback.c

Abstract:

    Resolve OBJECT_HEADER counter locations without private symbols.  The body
    displacement must be encoded independently by ObGetObjectType and object
    reference/dereference exports.  The pointer-count candidate is then proved
    by a balanced temporary reference before either counter is published.

Environment:

    Kernel mode, read-only query paths at PASSIVE_LEVEL.

--*/

#include "object_header_fallback.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_OBJECT_HEADER_SCAN_BYTES       0x0100UL
#define KSW_OBJECT_HEADER_MIN_BODY_OFFSET  0x0010UL
#define KSW_OBJECT_HEADER_MAX_BODY_OFFSET  0x0100UL
#define KSW_OBJECT_HEADER_MAX_COUNT        0x40000000ULL
#define KSW_OBJECT_HEADER_SAFE_REFERENCE_ATTEMPTS 64UL

typedef struct KswObjectHeaderAnchorCode
{
    UCHAR bytes[KSW_OBJECT_HEADER_SCAN_BYTES];
    ULONG scanBytes;
    BOOLEAN present;
} KswObjectHeaderAnchorCode, *PkswObjectHeaderAnchorCode;

static volatile LONG gKswordObjectHeaderLayoutState = 0L;
static ULONG gKswordObjectHeaderBodyOffset = 0UL;
static ULONG gKswordObjectHeaderHandleCountOffset = 0UL;

static BOOLEAN
kswordArkObjectHeaderResolveHandleCountOffset(
    _In_ const KswObjectHeaderAnchorCode* dereference,
    _In_ ULONG bodyOffset,
    _Out_ ULONG* handleCountOffsetOut
    );

static PVOID
kswordArkObjectHeaderResolveRoutine(
    _In_z_ PCWSTR name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, name);
    return MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
kswordArkObjectHeaderCaptureAnchor(
    _In_z_ PCWSTR name,
    _In_ ULONG scanBytes,
    _Out_ KswObjectHeaderAnchorCode* anchor
    )
{
    PVOID routine = NULL;

    if (anchor == NULL || scanBytes == 0UL ||
        scanBytes > sizeof(anchor->bytes)) {
        return FALSE;
    }
    RtlZeroMemory(anchor, sizeof(*anchor));
    routine = kswordArkObjectHeaderResolveRoutine(name);
    if (routine == NULL ||
        !kswordArkRuntimeReadMemory(
            routine,
            anchor->bytes,
            scanBytes)) {
        return FALSE;
    }
    anchor->scanBytes = scanBytes;
    anchor->present = TRUE;
    return TRUE;
}

static VOID
kswordArkObjectHeaderMarkCandidate(
    _Inout_updates_(candidateCount) UCHAR* candidates,
    _In_ ULONG candidateCount,
    _In_ CHAR negativeDisplacement
    )
{
    ULONG bodyOffset = 0UL;

    if (candidates == NULL || negativeDisplacement >= 0) {
        return;
    }
    bodyOffset = (ULONG)(-(LONG)negativeDisplacement);
    if (bodyOffset < KSW_OBJECT_HEADER_MIN_BODY_OFFSET ||
        bodyOffset > KSW_OBJECT_HEADER_MAX_BODY_OFFSET ||
        (bodyOffset & (sizeof(ULONG_PTR) - 1U)) != 0U ||
        bodyOffset >= candidateCount) {
        return;
    }
    candidates[bodyOffset] = 1U;
}

static VOID
kswordArkObjectHeaderCollectBodyCandidates(
    _In_ const KswObjectHeaderAnchorCode* anchor,
    _Out_writes_(candidateCount) UCHAR* candidates,
    _In_ ULONG candidateCount
    )
{
    ULONG index = 0UL;

    RtlZeroMemory(candidates, candidateCount);
    if (anchor == NULL || !anchor->present) {
        return;
    }
    for (index = 0UL; index + 6UL < anchor->scanBytes; ++index) {
        const UCHAR* code = anchor->bytes;

        // lea reg,[rcx-negative_disp8]
        if (code[index] == 0x48U && code[index + 1UL] == 0x8DU &&
            (code[index + 2UL] & 0xC7U) == 0x41U) {
            kswordArkObjectHeaderMarkCandidate(
                candidates,
                candidateCount,
                (CHAR)code[index + 3UL]);
        }
        // add rcx,negative_disp8
        if (code[index] == 0x48U && code[index + 1UL] == 0x83U &&
            code[index + 2UL] == 0xC1U) {
            kswordArkObjectHeaderMarkCandidate(
                candidates,
                candidateCount,
                (CHAR)code[index + 3UL]);
        }
        // lock xadd qword ptr [reg-negative_disp8],reg
        if (code[index] == 0xF0U && code[index + 1UL] == 0x48U &&
            code[index + 2UL] == 0x0FU && code[index + 3UL] == 0xC1U &&
            (code[index + 4UL] & 0xC0U) == 0x40U) {
            kswordArkObjectHeaderMarkCandidate(
                candidates,
                candidateCount,
                (CHAR)code[index + 5UL]);
        }
    }
}

static BOOLEAN
kswordArkObjectHeaderResolveBodyOffsetFromAnchors(
    _In_ const KswObjectHeaderAnchorCode* getType,
    _In_ const KswObjectHeaderAnchorCode* dereference,
    _In_ const KswObjectHeaderAnchorCode* referenceWithTag,
    _Out_ ULONG* bodyOffsetOut
    )
{
    UCHAR getTypeCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    UCHAR dereferenceCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    UCHAR referenceCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    ULONG offset = 0UL;
    ULONG acceptedOffset = 0UL;
    ULONG acceptedCount = 0UL;

    if (bodyOffsetOut == NULL) {
        return FALSE;
    }
    kswordArkObjectHeaderCollectBodyCandidates(
        getType, getTypeCandidates, RTL_NUMBER_OF(getTypeCandidates));
    kswordArkObjectHeaderCollectBodyCandidates(
        dereference, dereferenceCandidates, RTL_NUMBER_OF(dereferenceCandidates));
    kswordArkObjectHeaderCollectBodyCandidates(
        referenceWithTag, referenceCandidates, RTL_NUMBER_OF(referenceCandidates));

    for (offset = KSW_OBJECT_HEADER_MIN_BODY_OFFSET;
        offset <= KSW_OBJECT_HEADER_MAX_BODY_OFFSET;
        offset += sizeof(ULONG_PTR)) {
        ULONG support = (ULONG)getTypeCandidates[offset] +
            (ULONG)dereferenceCandidates[offset] +
            (ULONG)referenceCandidates[offset];

        if (support >= 2UL) {
            acceptedOffset = offset;
            acceptedCount += 1UL;
        }
    }
    if (acceptedCount != 1UL) {
        return FALSE;
    }
    *bodyOffsetOut = acceptedOffset;
    return TRUE;
}

static NTSTATUS
kswordArkObjectHeaderResolveCachedLayout(
    _Out_ ULONG* bodyOffsetOut,
    _Out_ ULONG* handleCountOffsetOut
    )
{
    LONG state = 0L;
    ULONG spin = 0UL;

    if (bodyOffsetOut == NULL || handleCountOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    state = InterlockedCompareExchange(&gKswordObjectHeaderLayoutState, 0L, 0L);
    if (state == 2L) {
        *bodyOffsetOut = gKswordObjectHeaderBodyOffset;
        *handleCountOffsetOut = gKswordObjectHeaderHandleCountOffset;
        return STATUS_SUCCESS;
    }
    if (state < 0L) {
        return STATUS_NOT_SUPPORTED;
    }

    if (InterlockedCompareExchange(
            &gKswordObjectHeaderLayoutState,
            1L,
            0L) == 0L) {
        KswObjectHeaderAnchorCode getType;
        KswObjectHeaderAnchorCode dereference;
        KswObjectHeaderAnchorCode referenceWithTag;
        ULONG bodyOffset = 0UL;
        ULONG handleOffset = 0UL;
        BOOLEAN resolved = FALSE;

        resolved = kswordArkObjectHeaderCaptureAnchor(
                L"ObGetObjectType", 0x40UL, &getType) &&
            kswordArkObjectHeaderCaptureAnchor(
                L"ObfDereferenceObject", 0x80UL, &dereference) &&
            kswordArkObjectHeaderCaptureAnchor(
                L"ObfReferenceObjectWithTag", 0x80UL, &referenceWithTag) &&
            kswordArkObjectHeaderResolveBodyOffsetFromAnchors(
                &getType,
                &dereference,
                &referenceWithTag,
                &bodyOffset);
        if (!resolved) {
            InterlockedExchange(&gKswordObjectHeaderLayoutState, -1L);
            return STATUS_NOT_SUPPORTED;
        }

        // HandleCount is not read by every ObfDereferenceObject build.  Keep
        // it optional so a missing secondary pattern cannot discard the
        // independently proved body/PointerCount layout.
        (VOID)kswordArkObjectHeaderResolveHandleCountOffset(
            &dereference,
            bodyOffset,
            &handleOffset);
        gKswordObjectHeaderBodyOffset = bodyOffset;
        gKswordObjectHeaderHandleCountOffset = handleOffset;
        InterlockedExchange(&gKswordObjectHeaderLayoutState, 2L);
        *bodyOffsetOut = bodyOffset;
        *handleCountOffsetOut = handleOffset;
        return STATUS_SUCCESS;
    }

    for (spin = 0UL; spin < 4096UL; ++spin) {
        YieldProcessor();
        state = InterlockedCompareExchange(
            &gKswordObjectHeaderLayoutState,
            0L,
            0L);
        if (state != 1L) {
            break;
        }
    }
    if (state != 2L) {
        return (state < 0L) ? STATUS_NOT_SUPPORTED : STATUS_RETRY;
    }
    *bodyOffsetOut = gKswordObjectHeaderBodyOffset;
    *handleCountOffsetOut = gKswordObjectHeaderHandleCountOffset;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkObjectHeaderResolveBodyOffsetFallback(
    _Out_ ULONG* bodyOffsetOut
    )
{
    ULONG handleCountOffset = 0UL;

    if (bodyOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return kswordArkObjectHeaderResolveCachedLayout(
        bodyOffsetOut,
        &handleCountOffset);
}

static BOOLEAN
kswordArkObjectHeaderResolveHandleCountOffset(
    _In_ const KswObjectHeaderAnchorCode* dereference,
    _In_ ULONG bodyOffset,
    _Out_ ULONG* handleCountOffsetOut
    )
{
    ULONG index = 0UL;
    ULONG candidate = 0UL;
    ULONG candidateCount = 0UL;

    if (dereference == NULL || !dereference->present ||
        handleCountOffsetOut == NULL) {
        return FALSE;
    }
    for (index = 0UL; index + 9UL < dereference->scanBytes; ++index) {
        const UCHAR* code = dereference->bytes;
        UCHAR headerRegister = 0U;
        ULONG search = 0UL;

        if (code[index] != 0x48U || code[index + 1UL] != 0x8DU ||
            (code[index + 2UL] & 0xC7U) != 0x41U ||
            (CHAR)code[index + 3UL] >= 0 ||
            (ULONG)(-(LONG)(CHAR)code[index + 3UL]) != bodyOffset) {
            continue;
        }
        headerRegister = (UCHAR)((code[index + 2UL] >> 3U) & 7U);
        for (search = index + 4UL;
            search + 5UL < dereference->scanBytes && search <= index + 80UL;
            ++search) {
            if (code[search] == 0xF0U && code[search + 1UL] == 0x48U &&
                code[search + 2UL] == 0x0FU && code[search + 3UL] == 0xC1U &&
                (code[search + 4UL] & 0xC0U) == 0x00U &&
                (code[search + 4UL] & 7U) == headerRegister) {
                ULONG readSearch = 0UL;

                for (readSearch = search + 5UL;
                    readSearch + 3UL < dereference->scanBytes &&
                        readSearch <= search + 48UL;
                    ++readSearch) {
                    UCHAR displacement = 0U;

                    if (code[readSearch] != 0x48U ||
                        code[readSearch + 1UL] != 0x8BU ||
                        (code[readSearch + 2UL] & 0xC0U) != 0x40U ||
                        (code[readSearch + 2UL] & 7U) != headerRegister) {
                        continue;
                    }
                    displacement = code[readSearch + 3UL];
                    if (displacement == 0U || displacement > 0x20U ||
                        (displacement & (sizeof(ULONG_PTR) - 1U)) != 0U) {
                        continue;
                    }
                    if (candidateCount == 0UL || candidate == displacement) {
                        candidate = displacement;
                        candidateCount = 1UL;
                    }
                    else {
                        return FALSE;
                    }
                }
                break;
            }
        }
    }
    if (candidateCount != 1UL) {
        return FALSE;
    }
    *handleCountOffsetOut = candidate;
    return TRUE;
}

NTSTATUS
kswordArkObjectHeaderQueryFallback(
    _In_ PVOID object,
    _Out_ KswObjectHeaderFallbackResult* result
    )
{
    ULONG bodyOffset = 0UL;
    ULONG handleOffset = 0UL;
    ULONG_PTR header = 0U;
    LONG_PTR pointerBefore = 0;
    LONG_PTR pointerDuring = 0;
    LONG_PTR pointerAfter = 0;
    LONG_PTR handleCount = 0;
    BOOLEAN handleCountValid = FALSE;

    if (object == NULL || result == NULL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(result, sizeof(*result));
    if (!NT_SUCCESS(kswordArkObjectHeaderResolveCachedLayout(
            &bodyOffset,
            &handleOffset)) ||
        (ULONG_PTR)object < bodyOffset) {
        return STATUS_NOT_SUPPORTED;
    }
    header = (ULONG_PTR)object - bodyOffset;
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)header,
            &pointerBefore,
            sizeof(pointerBefore)) ||
        pointerBefore <= 0 ||
        (ULONG64)pointerBefore > KSW_OBJECT_HEADER_MAX_COUNT) {
        return STATUS_DATA_ERROR;
    }

    if (handleOffset != 0UL &&
        kswordArkRuntimeReadMemory(
            (const VOID*)(header + handleOffset),
            &handleCount,
            sizeof(handleCount)) &&
        handleCount >= 0 &&
        (ULONG64)handleCount <= KSW_OBJECT_HEADER_MAX_COUNT &&
        handleCount <= pointerBefore) {
        handleCountValid = TRUE;
    }

    ObReferenceObject(object);
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)header,
            &pointerDuring,
            sizeof(pointerDuring))) {
        ObDereferenceObject(object);
        return STATUS_PARTIAL_COPY;
    }
    ObDereferenceObject(object);
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)header,
            &pointerAfter,
            sizeof(pointerAfter)) ||
        pointerDuring != pointerBefore + 1 ||
        pointerAfter != pointerBefore ||
        (ULONG64)pointerDuring > MAXULONG) {
        return STATUS_DATA_ERROR;
    }

    result->validFields = KSW_OBJECT_HEADER_FALLBACK_FIELD_POINTER_COUNT;
    result->bodyOffset = bodyOffset;
    result->pointerCountOffset = 0UL;
    result->pointerCount = (ULONG)pointerAfter;
    if (handleCountValid && (ULONG64)handleCount <= MAXULONG) {
        result->validFields |= KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT;
        result->handleCountOffset = handleOffset;
        result->handleCount = (ULONG)handleCount;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkObjectHeaderReferenceObjectSafe(
    _In_ PVOID object
    )
/*++

Routine Description:

    Reference an object body that the caller does not own, without resurrecting
    one whose pointer count has already reached zero.

    The Ob reference exports all end in the same sequence: they add one to
    OBJECT_HEADER.PointerCount unconditionally and then bugcheck 0x18 when the
    result is not greater than one.  A caller holding a pointer picked out of a
    kernel structure - an ActiveProcessLinks node, a PspCidTable slot - cannot
    rule that out, and cannot catch it either.  So do the increment here with a
    compare-exchange that never starts from a non-positive count.

Arguments:

    Object - Object body pointer to reference.

Return Value:

    STATUS_SUCCESS when a reference was taken; the caller owns it and must
    release it with ObDereferenceObject.  STATUS_DELETE_PENDING when the object
    is already being deleted, STATUS_NOT_SUPPORTED when the header layout could
    not be resolved, STATUS_DATA_ERROR when the count is unreadable or absurd.

--*/
{
    ULONG bodyOffset = 0UL;
    ULONG handleOffset = 0UL;
    volatile LONG64* pointerCount = NULL;
    ULONG attempt = 0UL;

    if (object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(kswordArkObjectHeaderResolveCachedLayout(
            &bodyOffset,
            &handleOffset)) ||
        (ULONG_PTR)object < bodyOffset) {
        return STATUS_NOT_SUPPORTED;
    }
    pointerCount = (volatile LONG64*)((PUCHAR)object - bodyOffset);

    for (attempt = 0UL; attempt < KSW_OBJECT_HEADER_SAFE_REFERENCE_ATTEMPTS; ++attempt) {
        LONG64 observed = 0LL;
        LONG64 previous = 0LL;

        if (!kswordArkRuntimeReadMemory(
                (const VOID*)(ULONG_PTR)pointerCount,
                &observed,
                sizeof(observed))) {
            return STATUS_DATA_ERROR;
        }
        if (observed <= 0LL) {
            return STATUS_DELETE_PENDING;
        }
        if ((ULONG64)observed > KSW_OBJECT_HEADER_MAX_COUNT) {
            return STATUS_DATA_ERROR;
        }

        __try {
            previous = InterlockedCompareExchange64(
                (volatile LONG64*)pointerCount,
                observed + 1LL,
                observed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_DATA_ERROR;
        }
        if (previous == observed) {
            return STATUS_SUCCESS;
        }
        YieldProcessor();
    }

    //
    // Losing the compare-exchange this many times in a row means the count is
    // moving under us faster than it can be read.  Refusing is the only answer
    // that cannot resurrect a dying object.
    //
    return STATUS_DEVICE_BUSY;
}
