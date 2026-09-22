/*++

Module Name:

    process_resolver.c

Abstract:

    This file resolves optional kernel process routines dynamically.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "process_resolver.h"
#include "token_layout_resolver.h"
#include "runtime_signature_scan.h"

#define KSW_RUNTIME_PROCESS_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_THREAD_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_THREAD_LIST_BUDGET 0x1000U

typedef ULONG_PTR(NTAPI* KswordObjectAccessorFn)(
    _In_ PVOID object
    );

typedef BOOLEAN(NTAPI* KswordProcessBooleanAccessorFn)(
    _In_ PEPROCESS process
    );

typedef ULONG_PTR(NTAPI* KswordCurrentThreadAccessorFn)(
    VOID
    );

typedef UCHAR(NTAPI* KswordProcessProtectionAccessorFn)(
    _In_ PEPROCESS process
    );

typedef UCHAR(NTAPI* KswordProcessSignatureAccessorFn)(
    _In_ PEPROCESS process,
    _Out_opt_ PUCHAR sectionSignatureLevel
    );

typedef enum KswordAccessorLoadKind
{
    kKswordAccessorLoadPointer,
    kKswordAccessorLoadUlong,
    kKswordAccessorLoadUshort,
    kKswordAccessorLoadUchar,
    kKswordAccessorAddress
} KswordAccessorLoadKind;

typedef struct KswordAccessorDisplacement
{
    LONG offset;
    KswordAccessorLoadKind loadKind;
} KswordAccessorDisplacement;

static BOOLEAN
kswordArkDriverReadPointerGuarded(
    _In_ const VOID* address,
    _Out_ ULONG_PTR* valueOut
    );

static VOID
kswordArkDriverInitializeRuntimeDynDataOffsets(
    _Out_ PkswordRuntimeDyndataOffsets offsets
    )
{
    LONG* field = NULL;
    SIZE_T index = 0U;

    if (offsets == NULL) {
        return;
    }
    field = (LONG*)offsets;
    for (index = 0U; index < sizeof(*offsets) / sizeof(*field); ++index) {
        field[index] = -1;
    }
}

static BOOLEAN
kswordArkDriverDecodeAccessorDisplacement(
    _In_reads_bytes_(byteCount) const UCHAR* bytes,
    _In_ SIZE_T byteCount,
    _Out_ KswordAccessorDisplacement* displacementOut
    )
{
    SIZE_T index = 0U;

    if (bytes == NULL || displacementOut == NULL) {
        return FALSE;
    }
    displacementOut->offset = -1;
    displacementOut->loadKind = kKswordAccessorLoadPointer;

    for (index = 0U; index + 7U <= byteCount && index < 24U; ++index) {
        LONG displacement = -1;
        KswordAccessorLoadKind kind = kKswordAccessorLoadPointer;
        SIZE_T displacementIndex = 0U;

        if (bytes[index] == 0x48U &&
            (bytes[index + 1U] == 0x8BU || bytes[index + 1U] == 0x8DU) &&
            bytes[index + 2U] == 0x81U) {
            kind = (bytes[index + 1U] == 0x8DU)
                ? kKswordAccessorAddress
                : kKswordAccessorLoadPointer;
            displacementIndex = index + 3U;
        }
        else if (bytes[index] == 0x8BU && bytes[index + 1U] == 0x81U) {
            kind = kKswordAccessorLoadUlong;
            displacementIndex = index + 2U;
        }
        else if (bytes[index] == 0x0FU &&
                 bytes[index + 1U] == 0xB6U &&
                 bytes[index + 2U] == 0x81U) {
            kind = kKswordAccessorLoadUchar;
            displacementIndex = index + 3U;
        }
        else if (bytes[index] == 0x0FU &&
                 bytes[index + 1U] == 0xB7U &&
                 bytes[index + 2U] == 0x81U) {
            kind = kKswordAccessorLoadUshort;
            displacementIndex = index + 3U;
        }
        else {
            continue;
        }

        RtlCopyMemory(
            &displacement,
            bytes + displacementIndex,
            sizeof(displacement));
        if (displacement <= 0 || displacement > 0x00003FFF) {
            continue;
        }
        displacementOut->offset = displacement;
        displacementOut->loadKind = kind;
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
kswordArkDriverReadAccessorValue(
    _In_ PVOID object,
    _In_ const KswordAccessorDisplacement* displacement,
    _Out_ ULONG_PTR* valueOut
    )
{
    if (object == NULL || displacement == NULL || valueOut == NULL ||
        displacement->offset <= 0) {
        return FALSE;
    }
    *valueOut = 0U;

    // Displacement is derived from disassembling the accessor code; if guessed incorrectly, it may point outside the object, requiring safe reads.
    {
        const UCHAR* address = (const UCHAR*)object + displacement->offset;
        ULONG64 raw = 0ULL;
        SIZE_T width = 0U;

        switch (displacement->loadKind) {
        case kKswordAccessorAddress:
            *valueOut = (ULONG_PTR)address;
            return TRUE;
        case kKswordAccessorLoadPointer:
            width = sizeof(ULONG_PTR);
            break;
        case kKswordAccessorLoadUlong:
            width = sizeof(ULONG);
            break;
        case kKswordAccessorLoadUshort:
            width = sizeof(USHORT);
            break;
        case kKswordAccessorLoadUchar:
            width = sizeof(UCHAR);
            break;
        default:
            return FALSE;
        }
        if (!kswordArkRuntimeReadMemory(address, &raw, width)) {
            return FALSE;
        }
        *valueOut = (ULONG_PTR)raw;
    }
    return TRUE;
}

static LONG
kswordArkDriverResolveValidatedAccessorOffset(
    _In_ PCWSTR routineNameArg,
    _In_ PVOID validationObject
    )
{
    UNICODE_STRING routineName;
    KswordObjectAccessorFn accessor = NULL;
    UCHAR code[32] = { 0 };
    KswordAccessorDisplacement displacement;
    ULONG_PTR accessorValue = 0U;
    ULONG_PTR fieldValue = 0U;

    if (routineNameArg == NULL || validationObject == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, routineNameArg);
    accessor = (KswordObjectAccessorFn)MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }

    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(validationObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    if (!kswordArkDriverDecodeAccessorDisplacement(
            code,
            sizeof(code),
            &displacement) ||
        !kswordArkDriverReadAccessorValue(
            validationObject,
            &displacement,
            &fieldValue) ||
        fieldValue != accessorValue) {
        return -1;
    }
    return displacement.offset;
}

static LONG
kswordArkDriverResolveCurrentThreadStackOffset(
    _In_z_ PCWSTR routineNameArg,
    _In_ PETHREAD currentThread
    )
/*++

Routine Description:

    Decode a no-argument current-thread stack accessor.  Accepted x64 code is
    deliberately narrow: load KTHREAD from gs:[188h], load one pointer field
    using disp8/disp32, then return.  The candidate must equal the live export
    result for the same current thread before it is published.

Return Value:

    Validated KTHREAD field offset, or -1 for any missing/ambiguous shape.

--*/
{
    static const UCHAR kCurrentThreadLoad[] = {
        0x65U, 0x48U, 0x8BU, 0x04U, 0x25U,
        0x88U, 0x01U, 0x00U, 0x00U
    };
    UNICODE_STRING routineName;
    KswordCurrentThreadAccessorFn accessor = NULL;
    UCHAR code[32];
    LONG offset = -1;
    SIZE_T instructionEnd = 0U;
    ULONG_PTR accessorValue = 0U;
    ULONG_PTR fieldValue = 0U;

    if (routineNameArg == NULL || currentThread == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, routineNameArg);
    accessor = (KswordCurrentThreadAccessorFn)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    if (RtlCompareMemory(
            code,
            kCurrentThreadLoad,
            sizeof(kCurrentThreadLoad)) != sizeof(kCurrentThreadLoad)) {
        return -1;
    }

    if (code[9] == 0x48U && code[10] == 0x8BU && code[11] == 0x40U) {
        offset = (LONG)code[12];
        instructionEnd = 13U;
    }
    else if (code[9] == 0x48U && code[10] == 0x8BU &&
        code[11] == 0x80U) {
        RtlCopyMemory(&offset, &code[12], sizeof(offset));
        instructionEnd = 16U;
    }
    if (offset <= 0 || offset > (LONG)KSW_RUNTIME_THREAD_SCAN_BYTES ||
        code[instructionEnd] != 0xC3U ||
        accessorValue < (ULONG_PTR)MmSystemRangeStart) {
        return -1;
    }
    if (!kswordArkDriverReadPointerGuarded(
            (const UCHAR*)currentThread + offset,
            &fieldValue) ||
        fieldValue != accessorValue) {
        return -1;
    }
    return offset;
}

static LONG
kswordArkDriverResolveActiveProcessLinksOffset(
    _In_ PEPROCESS process,
    _In_ LONG uniqueProcessIdOffset
    )
{
    LONG activeProcessLinksOffset = -1;
    PLIST_ENTRY link = NULL;

    if (process == NULL || uniqueProcessIdOffset <= 0 ||
        uniqueProcessIdOffset > (LONG)(0x00003FFFU - sizeof(HANDLE))) {
        return -1;
    }
    activeProcessLinksOffset =
        uniqueProcessIdOffset + (LONG)sizeof(HANDLE);
    link = (PLIST_ENTRY)((PUCHAR)process + activeProcessLinksOffset);

    /*
     * Reciprocity validation requires double-dereferencing Flink/Blink, which come from memory at the candidate offset; if the offset guess
     * is wrong, these are arbitrary values. Perform safe hop-by-hop reads; do not follow pointers directly across exception boundaries.
     */
    {
        LIST_ENTRY head;
        LIST_ENTRY forward;
        LIST_ENTRY backward;

        if (!kswordArkRuntimeReadMemory(link, &head, sizeof(head)) ||
            head.Flink == NULL || head.Blink == NULL ||
            !kswordArkRuntimeReadMemory(head.Flink, &forward, sizeof(forward)) ||
            !kswordArkRuntimeReadMemory(head.Blink, &backward, sizeof(backward)) ||
            forward.Blink != link ||
            backward.Flink != link) {
            return -1;
        }
    }
    return activeProcessLinksOffset;
}

LONG
kswordArkDriverResolveProcessFlagsOffset(
    _In_ PEPROCESS process
    )
/*++

Routine Description:

    Recover EPROCESS.Flags from the exported PsGetProcessExitProcessCalled
    bit accessor.  The resolver accepts only the compact x64 sequence that
    loads one ULONG from RCX, shifts the result, and masks it to one bit.  The
    decoded bit is then compared with the live accessor result before the
    offset is published.

Arguments:

    Process - Live process object used for semantic validation.

Return Value:

    A validated EPROCESS.Flags offset, or -1 when the accessor shape or live
    value is ambiguous.

--*/
{
    UNICODE_STRING routineName;
    KswordProcessBooleanAccessorFn accessor = NULL;
    UCHAR code[32] = { 0 };
    ULONG index = 0UL;
    LONG resolvedOffset = -1;
    ULONG resolvedBit = MAXULONG;
    ULONG matchCount = 0UL;
    BOOLEAN accessorValue = FALSE;

    if (process == NULL) {
        return -1;
    }

    RtlInitUnicodeString(&routineName, L"PsGetProcessExitProcessCalled");
    accessor = (KswordProcessBooleanAccessorFn)MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }

    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(process) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    for (index = 0UL; index + 11UL <= RTL_NUMBER_OF(code); ++index) {
        LONG candidateOffset = -1;
        ULONG shift = MAXULONG;
        ULONG suffix = index + 6UL;

        /* mov r32, dword ptr [rcx+disp32] */
        if (code[index] != 0x8BU || (code[index + 1UL] & 0xC7U) != 0x81U) {
            continue;
        }
        RtlCopyMemory(&candidateOffset, code + index + 2UL, sizeof(candidateOffset));
        if (candidateOffset <= 0 || candidateOffset > 0x00003FFF) {
            continue;
        }

        /* shr eax, imm8; and al/eax, 1 */
        if (code[suffix] == 0xC1U && code[suffix + 1UL] == 0xE8U) {
            shift = code[suffix + 2UL];
            suffix += 3UL;
        }
        if (shift >= 32UL) {
            continue;
        }
        if (!((code[suffix] == 0x24U && code[suffix + 1UL] == 0x01U) ||
              (code[suffix] == 0x83U && code[suffix + 1UL] == 0xE0U &&
               code[suffix + 2UL] == 0x01U))) {
            continue;
        }

        resolvedOffset = candidateOffset;
        resolvedBit = shift;
        matchCount += 1UL;
    }

    if (matchCount != 1UL || resolvedOffset <= 0 || resolvedBit >= 32UL) {
        return -1;
    }

    __try {
        const ULONG kFlags = *(volatile const ULONG*)((const UCHAR*)process + resolvedOffset);
        if ((((kFlags >> resolvedBit) & 1UL) != 0UL) != accessorValue) {
            return -1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    return resolvedOffset;
}

static BOOLEAN
kswordArkDriverReadPointerGuarded(
    _In_ const VOID* address,
    _Out_ ULONG_PTR* valueOut
    )
/*++

Routine Description:

    Read one kernel pointer-sized value through an exception boundary.

Arguments:

    Address - Candidate readable kernel address.
    ValueOut - Receives the copied scalar value.

Return Value:

    TRUE when the read completed; otherwise FALSE.

--*/
{
    if (address == NULL || valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0U;

    // Same as ReadListEntryGuarded: the candidate address is untrusted; exception boundaries cannot block access to unmapped kernel addresses.
    return kswordArkRuntimeReadMemory(address, valueOut, sizeof(*valueOut));
}

static BOOLEAN
kswordArkDriverReadListEntryGuarded(
    _In_ const LIST_ENTRY* address,
    _Out_ LIST_ENTRY* entryOut
    )
/*++

Routine Description:

    Copy one candidate LIST_ENTRY without trusting the candidate mapping.

Arguments:

    Address - Candidate list-entry address.
    EntryOut - Receives a stable scalar snapshot of both links.

Return Value:

    TRUE when both links were copied; otherwise FALSE.

--*/
{
    if (address == NULL || entryOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(entryOut, sizeof(*entryOut));

    /*
     * Candidate addresses are arbitrary pointers read from the previous hop list and may not be mapped. Touching an unmapped
     * address in kernel mode triggers a bugcheck 0x50, not a catchable exception; __try/__except cannot intercept it. This
     * path previously caused a BSOD during the offset probing phase in DriverEntry. MmCopyMemory must be used instead.
     */
    return kswordArkRuntimeReadMemory(address, entryOut, sizeof(*entryOut));
}

static BOOLEAN
kswordArkDriverAddressInsideObjectWindow(
    _In_ ULONG_PTR address,
    _In_ ULONG_PTR objectBase,
    _In_ SIZE_T objectWindow
    )
/*++

Routine Description:

    Test whether an address lies inside one bounded live-object inspection window.

Arguments:

    Address - Address being classified.
    ObjectBase - Start of the live kernel object.
    ObjectWindow - Maximum number of bytes inspected from the object.

Return Value:

    TRUE when Address is within the non-wrapping half-open window.

--*/
{
    if (objectBase == 0U || objectWindow == 0U ||
        objectBase > MAXULONG_PTR - objectWindow) {
        return FALSE;
    }
    return (address >= objectBase && address < objectBase + objectWindow) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDriverValidateThreadListCandidate(
    _In_ PEPROCESS process,
    _In_ PETHREAD currentThread,
    _In_ LONG kthreadProcessOffset,
    _In_ ULONG threadListEntryOffset,
    _Out_ ULONG* processThreadListHeadOffsetOut
    )
/*++

Routine Description:

    Validate one ETHREAD list-entry candidate by walking only reciprocal links
    until the list reaches a head embedded in the owning EPROCESS. Every thread
    node must expose the already validated KTHREAD.Process pointer at the same
    offset. This turns the offset search into a structural identity check rather
    than a naked pointer-pattern match.

Arguments:

    Process - Owning live process object.
    CurrentThread - Referenced live thread known to belong to Process.
    KthreadProcessOffset - Accessor-derived KTHREAD.Process offset.
    ThreadListEntryOffset - Candidate ETHREAD.ThreadListEntry offset.
    ProcessThreadListHeadOffsetOut - Receives the matching EPROCESS head offset.

Return Value:

    TRUE when a complete bounded path reaches a reciprocal EPROCESS list head.

--*/
{
    ULONG_PTR processBase = (ULONG_PTR)process;
    ULONG_PTR currentLinkAddress = (ULONG_PTR)currentThread + threadListEntryOffset;
    LIST_ENTRY currentEntry;
    ULONG step = 0UL;

    if (process == NULL || currentThread == NULL ||
        kthreadProcessOffset < 0 || processThreadListHeadOffsetOut == NULL) {
        return FALSE;
    }
    *processThreadListHeadOffsetOut = 0UL;
    if (!kswordArkDriverReadListEntryGuarded((const LIST_ENTRY*)currentLinkAddress, &currentEntry) ||
        currentEntry.Flink == NULL || currentEntry.Blink == NULL) {
        return FALSE;
    }

    for (step = 0UL; step < KSW_RUNTIME_THREAD_LIST_BUDGET; ++step) {
        ULONG_PTR nextAddress = (ULONG_PTR)currentEntry.Flink;
        LIST_ENTRY nextEntry;

        if (!kswordArkDriverReadListEntryGuarded((const LIST_ENTRY*)nextAddress, &nextEntry) ||
            (ULONG_PTR)nextEntry.Blink != currentLinkAddress) {
            return FALSE;
        }

        if (kswordArkDriverAddressInsideObjectWindow(
                nextAddress,
                processBase,
                KSW_RUNTIME_PROCESS_SCAN_BYTES)) {
            ULONG_PTR firstThreadLinkAddress = (ULONG_PTR)nextEntry.Flink;
            LIST_ENTRY firstThreadEntry;
            ULONG_PTR firstThreadProcess = 0U;

            if (nextAddress < processBase ||
                nextAddress - processBase > MAXULONG ||
                firstThreadLinkAddress <= threadListEntryOffset ||
                !kswordArkDriverReadListEntryGuarded(
                    (const LIST_ENTRY*)firstThreadLinkAddress,
                    &firstThreadEntry) ||
                (ULONG_PTR)firstThreadEntry.Blink != nextAddress ||
                !kswordArkDriverReadPointerGuarded(
                    (const UCHAR*)(firstThreadLinkAddress - threadListEntryOffset) + kthreadProcessOffset,
                    &firstThreadProcess) ||
                firstThreadProcess != processBase) {
                return FALSE;
            }

            *processThreadListHeadOffsetOut = (ULONG)(nextAddress - processBase);
            return TRUE;
        }

        if (nextAddress <= threadListEntryOffset) {
            return FALSE;
        }
        {
            ULONG_PTR nextThreadAddress = nextAddress - threadListEntryOffset;
            ULONG_PTR nextThreadProcess = 0U;

            if (!kswordArkDriverReadPointerGuarded(
                    (const UCHAR*)nextThreadAddress + kthreadProcessOffset,
                    &nextThreadProcess) ||
                nextThreadProcess != processBase) {
                return FALSE;
            }
        }

        currentLinkAddress = nextAddress;
        currentEntry = nextEntry;
    }
    return FALSE;
}

static VOID
kswordArkDriverResolveThreadListOffsets(
    _In_opt_ PEPROCESS process,
    _In_ PETHREAD currentThread,
    _In_ LONG kthreadProcessOffset,
    _Out_ LONG* processThreadListHeadOffsetOut,
    _Out_ LONG* threadListEntryOffsetOut
    )
/*++

Routine Description:

    Find a unique reciprocal process/thread list pair in two live objects.

Arguments:

    Process - Current process object.
    CurrentThread - Current thread object.
    KthreadProcessOffset - Previously validated KTHREAD.Process offset.
    ProcessThreadListHeadOffsetOut - Receives EPROCESS.ThreadListHead.
    ThreadListEntryOffsetOut - Receives ETHREAD.ThreadListEntry.

Return Value:

    None. Both outputs remain unavailable unless exactly one pair validates.

--*/
{
    ULONG candidateOffset = 0UL;
    LONG foundProcessOffset = -1;
    LONG foundThreadOffset = -1;

    if (processThreadListHeadOffsetOut == NULL || threadListEntryOffsetOut == NULL) {
        return;
    }
    *processThreadListHeadOffsetOut = -1;
    *threadListEntryOffsetOut = -1;
    if (process == NULL || currentThread == NULL || kthreadProcessOffset < 0) {
        return;
    }

    for (candidateOffset = 0UL;
         candidateOffset + sizeof(LIST_ENTRY) <= KSW_RUNTIME_THREAD_SCAN_BYTES;
         candidateOffset += (ULONG)sizeof(PVOID)) {
        ULONG processHeadOffset = 0UL;

        if (!kswordArkDriverValidateThreadListCandidate(
                process,
                currentThread,
                kthreadProcessOffset,
                candidateOffset,
                &processHeadOffset)) {
            continue;
        }
        if (foundThreadOffset >= 0) {
            return;
        }
        foundProcessOffset = (LONG)processHeadOffset;
        foundThreadOffset = (LONG)candidateOffset;
    }

    *processThreadListHeadOffsetOut = foundProcessOffset;
    *threadListEntryOffsetOut = foundThreadOffset;
}

VOID
kswordArkDriverResolveReadOnlyDynDataOffsets(
    _Out_ PkswordRuntimeDyndataOffsets offsets
    )
{
    PEPROCESS process = PsGetCurrentProcess();
    PETHREAD thread = PsGetCurrentThread();
    PACCESS_TOKEN token = NULL;
    LONG threadProcessIdOffset = -1;
    LONG threadIdOffset = -1;

    if (offsets == NULL) {
        return;
    }
    kswordArkDriverInitializeRuntimeDynDataOffsets(offsets);
    if (process != NULL) {
        offsets->epUniqueProcessId =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessId",
                process);
        offsets->epActiveProcessLinks =
            kswordArkDriverResolveActiveProcessLinksOffset(
                process,
                offsets->epUniqueProcessId);
        offsets->epImageFileName =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessImageFileName",
                process);
        offsets->epCreateTime =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessCreateTimeQuadPart",
                process);
        offsets->epExitStatus =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessExitStatus",
                process);
        offsets->epPeb =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessPeb",
                process);
        offsets->epWin32Process =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWin32Process",
                process);
        offsets->epWow64Process =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWow64Process",
                process);
        offsets->epInheritedFromUniqueProcessId =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessInheritedFromUniqueProcessId",
                process);
        offsets->epSectionBaseAddress =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessSectionBaseAddress",
                process);
        offsets->epJob =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessJob",
                process);
        offsets->epDebugPort =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessDebugPort",
                process);
        offsets->epPriorityClass =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessPriorityClass",
                process);
        offsets->epActiveThreads =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessActiveThreadCount",
                process);
        offsets->epWin32WindowStation =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWin32WindowStation",
                process);
        offsets->epSecurityPort =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetProcessSecurityPort",
                process);

        token = PsReferencePrimaryToken(process);
        if (token != NULL) {
            offsets->epToken = kswordArkDriverResolveProcessTokenOffset(process, token);
            kswordArkDriverResolveTokenLayoutOffsets(
                token,
                &offsets->tokUserAndGroupCount,
                &offsets->tokUserAndGroups,
                &offsets->tokIntegrityLevelIndex,
                &offsets->tokMandatoryPolicy);
            PsDereferencePrimaryToken(token);
            token = NULL;
        }
        offsets->epFlags = kswordArkDriverResolveProcessFlagsOffset(process);
    }
    if (thread != NULL) {
        threadProcessIdOffset =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetThreadProcessId",
                thread);
        threadIdOffset =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetThreadId",
                thread);
        if (threadProcessIdOffset > 0 &&
            threadIdOffset ==
                threadProcessIdOffset + (LONG)sizeof(HANDLE)) {
            offsets->etCid = threadProcessIdOffset;
        }
        offsets->ktProcess =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetThreadProcess",
                thread);
        offsets->ktInitialStack =
            kswordArkDriverResolveCurrentThreadStackOffset(
                L"IoGetInitialStack",
                thread);
        offsets->ktStackLimit =
            kswordArkDriverResolveCurrentThreadStackOffset(
                L"PsGetCurrentThreadStackLimit",
                thread);
        offsets->ktStackBase =
            kswordArkDriverResolveCurrentThreadStackOffset(
                L"PsGetCurrentThreadStackBase",
                thread);
        offsets->etStartAddress =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetThreadStartAddress",
                thread);
        offsets->etWin32StartAddress =
            kswordArkDriverResolveValidatedAccessorOffset(
                L"PsGetThreadWin32StartAddress",
                thread);
        kswordArkDriverResolveThreadListOffsets(
            process,
            thread,
            offsets->ktProcess,
            &offsets->epThreadListHead,
            &offsets->etThreadListEntry);
    }
}

// Resolve PsSuspendProcess first; this export is available on more systems.
KswordPsSuspendProcessFn
kswordArkDriverResolvePsSuspendProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsSuspendProcess");
    return (KswordPsSuspendProcessFn)MmGetSystemRoutineAddress(&routineName);
}

// Fallback resolver for Zw/Nt suspend APIs that use process handle input.
KswordZwOrNtSuspendProcessFn
kswordArkDriverResolveZwOrNtSuspendProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwSuspendProcess");
    {
        KswordZwOrNtSuspendProcessFn routineAddress =
            (KswordZwOrNtSuspendProcessFn)MmGetSystemRoutineAddress(&routineName);
        if (routineAddress != NULL) {
            return routineAddress;
        }
    }

    RtlInitUnicodeString(&routineName, L"NtSuspendProcess");
    return (KswordZwOrNtSuspendProcessFn)MmGetSystemRoutineAddress(&routineName);
}

// Resolve PsResumeProcess first, mirroring the suspend path exactly.
KswordPsResumeProcessFn
kswordArkDriverResolvePsResumeProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsResumeProcess");
    return (KswordPsResumeProcessFn)MmGetSystemRoutineAddress(&routineName);
}

// Fallback resolver for Zw/Nt resume APIs that use process handle input.
KswordZwOrNtResumeProcessFn
kswordArkDriverResolveZwOrNtResumeProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwResumeProcess");
    {
        KswordZwOrNtResumeProcessFn routineAddress =
            (KswordZwOrNtResumeProcessFn)MmGetSystemRoutineAddress(&routineName);
        if (routineAddress != NULL) {
            return routineAddress;
        }
    }

    RtlInitUnicodeString(&routineName, L"NtResumeProcess");
    return (KswordZwOrNtResumeProcessFn)MmGetSystemRoutineAddress(&routineName);
}

KswordPsIsProtectedProcessFn
kswordArkDriverResolvePsIsProtectedProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
    return (KswordPsIsProtectedProcessFn)MmGetSystemRoutineAddress(&routineName);
}

KswordPsIsProtectedProcessLightFn
kswordArkDriverResolvePsIsProtectedProcessLight(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcessLight");
    return (KswordPsIsProtectedProcessLightFn)MmGetSystemRoutineAddress(&routineName);
}

static LONG
kswordArkDriverDecodeReturnedUcharOffset(
    _In_reads_bytes_(byteCount) const UCHAR* bytes,
    _In_ SIZE_T byteCount
    )
{
    LONG candidate = -1;
    SIZE_T index = 0U;

    if (bytes == NULL) {
        return -1;
    }
    for (index = 0U; index + 7U <= byteCount; ++index) {
        LONG offset = -1;
        SIZE_T instructionBytes = 0U;

        // mov al, byte ptr [rcx+disp32]
        if (bytes[index] == 0x8AU && bytes[index + 1U] == 0x81U) {
            RtlCopyMemory(&offset, bytes + index + 2U, sizeof(offset));
            instructionBytes = 6U;
        }
        // movzx eax, byte ptr [rcx+disp32]
        else if (index + 8U <= byteCount &&
            bytes[index] == 0x0FU && bytes[index + 1U] == 0xB6U &&
            bytes[index + 2U] == 0x81U) {
            RtlCopyMemory(&offset, bytes + index + 3U, sizeof(offset));
            instructionBytes = 7U;
        }
        else {
            continue;
        }
        if (offset <= 0 || offset > 0x0FFF ||
            index + instructionBytes >= byteCount ||
            bytes[index + instructionBytes] != 0xC3U) {
            continue;
        }
        if (candidate >= 0 && candidate != offset) {
            return -1;
        }
        candidate = offset;
    }
    return candidate;
}

static BOOLEAN
kswordArkDriverResolveProcessSignatureOffsets(
    _Out_ LONG* signatureLevelOffsetOut,
    _Out_ LONG* sectionSignatureLevelOffsetOut
    )
{
    UNICODE_STRING routineName;
    KswordProcessSignatureAccessorFn accessor = NULL;
    PEPROCESS process = PsGetCurrentProcess();
    UCHAR code[32];
    UCHAR signatureValue = 0U;
    UCHAR sectionValue = 0U;
    UCHAR signatureField = 0U;
    UCHAR sectionField = 0U;
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    SIZE_T index = 0U;

    if (signatureLevelOffsetOut == NULL ||
        sectionSignatureLevelOffsetOut == NULL || process == NULL) {
        return FALSE;
    }
    *signatureLevelOffsetOut = -1;
    *sectionSignatureLevelOffsetOut = -1;
    RtlInitUnicodeString(&routineName, L"PsGetProcessSignatureLevel");
    accessor = (KswordProcessSignatureAccessorFn)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return FALSE;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        signatureValue = accessor(process, &sectionValue);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    for (index = 0U; index + 8U <= sizeof(code); ++index) {
        LONG offset = -1;

        if (code[index] != 0x8AU || code[index + 1U] != 0x81U) {
            continue;
        }
        RtlCopyMemory(&offset, code + index + 2U, sizeof(offset));
        if (offset <= 0 || offset > 0x0FFF) {
            continue;
        }
        // The optional section-signing output is copied through RDX.
        if (code[index + 6U] == 0x88U && code[index + 7U] == 0x02U) {
            if (sectionOffset >= 0 && sectionOffset != offset) {
                return FALSE;
            }
            sectionOffset = offset;
        }
        // The signature level itself is returned in AL.
        if (code[index + 6U] == 0xC3U) {
            if (signatureOffset >= 0 && signatureOffset != offset) {
                return FALSE;
            }
            signatureOffset = offset;
        }
    }
    if (signatureOffset <= 0 || sectionOffset <= 0 ||
        signatureOffset == sectionOffset) {
        return FALSE;
    }
    __try {
        signatureField = *((volatile const UCHAR*)process + signatureOffset);
        sectionField = *((volatile const UCHAR*)process + sectionOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    if (signatureField != signatureValue || sectionField != sectionValue) {
        return FALSE;
    }
    *signatureLevelOffsetOut = signatureOffset;
    *sectionSignatureLevelOffsetOut = sectionOffset;
    return TRUE;
}

LONG
kswordArkDriverResolveProcessProtectionOffset(
    VOID
    )
{
    UNICODE_STRING routineName;
    KswordProcessProtectionAccessorFn accessor = NULL;
    PEPROCESS process = PsGetCurrentProcess();
    UCHAR code[32];
    UCHAR accessorValue = 0U;
    UCHAR fieldValue = 0U;
    LONG offset = -1;

    if (process == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, L"PsGetProcessProtection");
    accessor = (KswordProcessProtectionAccessorFn)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(process);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    offset = kswordArkDriverDecodeReturnedUcharOffset(code, sizeof(code));
    if (offset <= 0) {
        return -1;
    }
    __try {
        fieldValue = *((volatile const UCHAR*)process + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    return fieldValue == accessorValue ? offset : -1;
}

LONG
kswordArkDriverResolveProcessSignatureLevelOffset(
    VOID
    )
{
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    LONG protectionOffset = kswordArkDriverResolveProcessProtectionOffset();

    if (protectionOffset <= 0 ||
        !kswordArkDriverResolveProcessSignatureOffsets(
            &signatureOffset,
            &sectionOffset) ||
        sectionOffset + (LONG)sizeof(UCHAR) != protectionOffset ||
        signatureOffset + (LONG)sizeof(UCHAR) != sectionOffset) {
        return -1;
    }
    return signatureOffset;
}

LONG
kswordArkDriverResolveProcessSectionSignatureLevelOffset(
    VOID
    )
{
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    LONG protectionOffset = kswordArkDriverResolveProcessProtectionOffset();

    if (protectionOffset <= 0 ||
        !kswordArkDriverResolveProcessSignatureOffsets(
            &signatureOffset,
            &sectionOffset) ||
        sectionOffset + (LONG)sizeof(UCHAR) != protectionOffset ||
        signatureOffset + (LONG)sizeof(UCHAR) != sectionOffset) {
        return -1;
    }
    return sectionOffset;
}

//
// ============================================================================
// Runtime resolution of EPROCESS.SectionObject / EPROCESS.ObjectTable
// ----------------------------------------------------------------------------
// These two offsets originally relied solely on the System Informer offset table, which matches
// ntoskrnl precisely by TimeDateStamp + SizeOfImage. New kernels often fall outside this table,
// causing the "HandleTable" and "SectionObject" columns in the process list to remain
// Unavailable. This adds a runtime source that requires neither PDBs nor packaged profiles.
//
// Approach matches existing EpProtection/EpSignatureLevel resolution: disassemble the exported accessor
// to obtain the offset, then re-read to verify; no anchor-less kernel memory scanning is performed.
// ============================================================================
//

// ntifs.h does not export declarations for these symbols; declare them locally following the existing convention in this codebase.
NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

extern POBJECT_TYPE* MmSectionObjectType;

// kswordArkDriverDecodeSingleFieldAccessorOffset:
// - Input: An exported accessor name in the format `mov rax, [rcx+disp32]; ret`.
// - Processing: Extract the first 8 bytes and validate the 48 8B 81 <disp32> C3 encoding.
// - Returns: disp32; returns -1 if encoding is invalid or out of reasonable range.
static LONG
kswordArkDriverDecodeSingleFieldAccessorOffset(
    _In_z_ const WCHAR* routineNameArg
    )
{
    UNICODE_STRING routineName;
    const UCHAR* routineAddress = NULL;
    UCHAR code[8];
    LONG offset = -1;

    RtlInitUnicodeString(&routineName, (PWSTR)routineNameArg);
    routineAddress = (const UCHAR*)MmGetSystemRoutineAddress(&routineName);
    if (routineAddress == NULL) {
        return -1;
    }

    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, routineAddress, sizeof(code));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    // 48 8B 81 <disp32> C3 = mov rax, [rcx+disp32] / ret
    if (code[0] != 0x48U || code[1] != 0x8BU || code[2] != 0x81U || code[7] != 0xC3U) {
        return -1;
    }
    RtlCopyMemory(&offset, code + 3, sizeof(offset));
    if (offset <= 0 || offset > 0x0FFF) {
        return -1;
    }
    return offset;
}

// kswordArkDriverIsProbableKernelPointer:
// - Input: candidate kernel pointer and number of bytes to attempt reading;
// - Processing: Accept only 8-byte aligned canonical kernel addresses, requiring both the first and last bytes to be currently resident.
// - Returns: TRUE if it can be safely read within a __try block.
// Note: MmIsAddressValid only reduces the probability of triggering; the true fallback remains the caller's __try block.
static BOOLEAN
kswordArkDriverIsProbableKernelPointer(
    _In_opt_ const VOID* pointer,
    _In_ ULONG requiredBytes
    )
{
    const ULONG_PTR kValue = (ULONG_PTR)pointer;

    if (pointer == NULL || (kValue & 0x7ULL) != 0ULL) {
        return FALSE;
    }
    if (kValue < 0xFFFF800000000000ULL) {
        return FALSE;
    }
    if (!MmIsAddressValid((PVOID)pointer)) {
        return FALSE;
    }
    if (!MmIsAddressValid((PVOID)(kValue + requiredBytes - 1ULL))) {
        return FALSE;
    }
    return TRUE;
}

LONG
kswordArkDriverResolveProcessSectionObjectOffset(
    VOID
    )
/*++

Routine Description:

    Resolve EPROCESS.SectionObject offset.

    PsReferenceProcessFilePointer first takes the address of Process->RundownProtect (lea, 48 8D); immediately
    after obtaining the rundown protection, it loads Process->SectionObject and checks for null. Therefore,
    the first REX.W memory load with disp32 (48 8B) within the preceding few bytes is SectionObject.

    Candidate offset must pass object type validation: the read pointer must be an MmSectionObjectType object.
    This step makes an incorrect decoding very unlikely to pass validation.

Return Value:

    Returns offset on success; returns -1 if undetermined, signaling the caller to keep the field unavailable.

--*/
{
    UNICODE_STRING routineName;
    const UCHAR* routineAddress = NULL;
    PEPROCESS process = PsGetCurrentProcess();
    UCHAR code[64];
    SIZE_T index = 0U;

    if (process == NULL || MmSectionObjectType == NULL) {
        return -1;
    }

    RtlInitUnicodeString(&routineName, L"PsReferenceProcessFilePointer");
    routineAddress = (const UCHAR*)MmGetSystemRoutineAddress(&routineName);
    if (routineAddress == NULL) {
        return -1;
    }

    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, routineAddress, sizeof(code));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    for (index = 0U; index + 7U <= sizeof(code); ++index) {
        LONG candidateOffset = -1;
        const VOID* candidateObject = NULL;
        POBJECT_TYPE candidateType = NULL;

        // REX.W + 8B /r, requiring modrm.mod == 10b (disp32).
        if (code[index] != 0x48U || code[index + 1U] != 0x8BU) {
            continue;
        }
        if ((code[index + 2U] & 0xC0U) != 0x80U) {
            continue;
        }
        if ((code[index + 2U] & 0x07U) == 0x04U) {
            // r/m == 100b indicates a following SIB byte; the disp32 position differs, so skip guessing.
            continue;
        }
        RtlCopyMemory(&candidateOffset, code + index + 3U, sizeof(candidateOffset));
        if (candidateOffset < 0x100 || candidateOffset > 0x0FFF) {
            continue;
        }

        __try {
            candidateObject = *(const VOID* const volatile*)
                ((const UCHAR*)process + candidateOffset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!kswordArkDriverIsProbableKernelPointer(candidateObject, (ULONG)sizeof(VOID*))) {
            continue;
        }

        __try {
            candidateType = ObGetObjectType((PVOID)candidateObject);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (candidateType != *MmSectionObjectType) {
            continue;
        }
        return candidateOffset;
    }
    return -1;
}

LONG
kswordArkDriverResolveProcessObjectTableOffset(
    VOID
    )
/*++

Routine Description:

    Resolve the offset of EPROCESS.ObjectTable.

    Since no exported routine directly returns this field, it is changed to
    'restricted search between known anchors + cross-process consistency validation':

    - Anchor uses the UniqueProcessId offset resolved by PsGetProcessId, overwriting 0x600 bytes backward.
      Do not assume the order of ObjectTable versus Win32Process/SectionObject
      fields, as different EPROCESS versions may reorder them.
    - Criterion: The pointer at this slot points to a _HANDLE_TABLE containing a ULONG equal to the current process PID.
      Require the same slot offset and table offset to hold across multiple sampled processes, with a unique solution
      in the entire window. If a second self-consistent solution exists, treat the resolution as untrusted and abort.

    Both boundaries are derived from runtime decoding; no version-specific constants are hardcoded.

Return Value:

    Returns the offset on success; returns -1 if there is no solution within the window or if the solution is not unique.

--*/
{
    // More sampled processes reduce the false positive rate; parsing runs only once during initialization, so a sufficient count is enough.
    enum {
        kSampleProcessCapacity = 6,
        kHandleTableProbeBytes = 0x60,
        // Overwrite EPROCESS bodies backward anchored by UniqueProcessId; only accept if unique
        // within the window, so prefer a wider range over assuming field order for specific versions.
        kObjectTableSearchWindowBytes = 0x600
    };

    PEPROCESS sampleProcesses[kSampleProcessCapacity];
    ULONG samplePids[kSampleProcessCapacity];
    ULONG sampleCount = 0UL;
    ULONG scanPid = 0UL;
    LONG lowerBound = kswordArkDriverDecodeSingleFieldAccessorOffset(L"PsGetProcessId");
    LONG upperBound = 0;
    LONG candidateOffset = -1;
    LONG resolvedOffset = -1;
    ULONG sampleIndex = 0UL;

    if (lowerBound <= 0) {
        return -1;
    }
    lowerBound += (LONG)sizeof(VOID*);
    upperBound = lowerBound + (LONG)kObjectTableSearchWindowBytes;

    RtlZeroMemory(sampleProcesses, sizeof(sampleProcesses));
    RtlZeroMemory(samplePids, sizeof(samplePids));

    // Sampling: iterate by PID until enough samples are collected. PIDs are allocated in steps of 4.
    for (scanPid = 4UL;
         scanPid <= 0x4000UL && sampleCount < (ULONG)kSampleProcessCapacity;
         scanPid += 4UL) {
        PEPROCESS candidateProcess = NULL;

        if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(scanPid), &candidateProcess))) {
            continue;
        }
        if (PsGetProcessExitStatus(candidateProcess) != STATUS_PENDING) {
            // The ObjectTable of an exited process has been set to null and cannot be used as a criterion.
            ObDereferenceObject(candidateProcess);
            continue;
        }
        sampleProcesses[sampleCount] = candidateProcess;
        samplePids[sampleCount] = scanPid;
        ++sampleCount;
    }

    // Cross-process consistency validation is meaningless with fewer than two samples; better to abandon.
    if (sampleCount < 2UL) {
        goto Cleanup;
    }

    for (candidateOffset = lowerBound;
         candidateOffset + (LONG)sizeof(VOID*) <= upperBound;
         candidateOffset += (LONG)sizeof(VOID*)) {
        LONG agreedTableOffset = -1;
        BOOLEAN candidateOk = TRUE;

        for (sampleIndex = 0UL; sampleIndex < sampleCount && candidateOk; ++sampleIndex) {
            const UCHAR* handleTable = NULL;
            LONG tableOffset = 0;
            BOOLEAN matched = FALSE;

            __try {
                handleTable = *(const UCHAR* const volatile*)
                    ((const UCHAR*)sampleProcesses[sampleIndex] + candidateOffset);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                candidateOk = FALSE;
                break;
            }
            if (!kswordArkDriverIsProbableKernelPointer(handleTable, (ULONG)kHandleTableProbeBytes)) {
                candidateOk = FALSE;
                break;
            }

            // _HANDLE_TABLE header contains UniqueProcessId; do not hardcode its position, but require that
            // the offset within the same table matches the respective PID across all sampled processes.
            for (tableOffset = 0;
                 tableOffset + (LONG)sizeof(ULONG) <= (LONG)kHandleTableProbeBytes;
                 tableOffset += (LONG)sizeof(ULONG)) {
                ULONG tableValue = 0UL;

                if (agreedTableOffset >= 0 && tableOffset != agreedTableOffset) {
                    continue;
                }
                __try {
                    tableValue = *(const volatile ULONG*)(handleTable + tableOffset);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
                if (tableValue != samplePids[sampleIndex]) {
                    continue;
                }
                agreedTableOffset = tableOffset;
                matched = TRUE;
                break;
            }
            if (!matched) {
                candidateOk = FALSE;
            }
        }

        if (!candidateOk) {
            continue;
        }
        if (resolvedOffset >= 0) {
            // A second self-consistent solution within the window indicates the criteria are insufficient to distinguish; abandon rather than gamble on one.
            resolvedOffset = -1;
            goto Cleanup;
        }
        resolvedOffset = candidateOffset;
    }

Cleanup:
    for (sampleIndex = 0UL; sampleIndex < sampleCount; ++sampleIndex) {
        if (sampleProcesses[sampleIndex] != NULL) {
            ObDereferenceObject(sampleProcesses[sampleIndex]);
        }
    }
    return resolvedOffset;
}

// Resolve ZwSetInformationProcess dynamically for broad WDK compatibility.
KswordZwSetInformationProcessFn
kswordArkDriverResolveZwSetInformationProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ZwSetInformationProcess");
    return (KswordZwSetInformationProcessFn)MmGetSystemRoutineAddress(&routineName);
}
