/*++

Module Name:

    system_time_resolver.c

Abstract:

    Independently resolve Windows HAL performance counter descriptors and active function slots.

Third-Party Notice:

    The license and archival notes for the referenced mechanism are located at:
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_internal.h"

#include <ntstrsafe.h>

/* Only check a limited window at the start of exported functions to avoid unbounded feature searches in reference implementations. */
#define KSW_SYSTEM_TIME_SCAN_BYTES             0x500UL
#define KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET  0x48UL
#define KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET     0x70UL
#define KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET   0xBCUL
#define KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET  0xE0UL
#define KSW_SYSTEM_TIME_HANDLER_ROW_BYTES      16UL
#define KSW_SYSTEM_TIME_RDI_PATTERN_BUILD_MAX  20348UL
#define KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM  28000UL

/* Safely read a pointer value; treat exceptions or user-mode addresses as invalid candidates. */
static
BOOLEAN
kswordArkSystemTimeReadPointer(
    _In_ const VOID* address,
    _Out_ PVOID* value
    )
{
    if (address == NULL ||
        value == NULL ||
        (ULONG_PTR)address < (ULONG_PTR)MmSystemRangeStart) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(value, address, sizeof(*value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = NULL;
        return FALSE;
    }
    return TRUE;
}

/* Safely read a ULONG field for descriptor index and internal flag validation. */
static
BOOLEAN
kswordArkSystemTimeReadUlong(
    _In_ const VOID* address,
    _Out_ ULONG* value
    )
{
    if (address == NULL ||
        value == NULL ||
        (ULONG_PTR)address < (ULONG_PTR)MmSystemRangeStart) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(value, address, sizeof(*value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = 0UL;
        return FALSE;
    }
    return TRUE;
}

/*
 * The HAL counter entry may reside in runtime-generated kernel code regions in some
 * configurations, so RtlPcToFileHeader hitting an image cannot be a necessary condition.
 */
static
BOOLEAN
kswordArkSystemTimeIsKernelCodePointer(
    _In_opt_ PVOID address
    )
{
    return address != NULL &&
        (ULONG_PTR)address >= (ULONG_PTR)MmSystemRangeStart &&
        MmIsAddressValid(address);
}

/*
 * Reads a 7-byte RIP-relative instruction's disp32 and calculates its target address.
 * Caller has already validated the opcode and ModRM; the return value is responsible only for address calculation.
 */
static
PVOID
kswordArkSystemTimeRipTarget(
    _In_ ULONG_PTR instructionAddress,
    _In_reads_bytes_(7) const UCHAR* instructionBytes
    )
{
    LONG displacement = 0L;
    ULONG_PTR nextInstruction = 0U;

    RtlCopyMemory(
        &displacement,
        instructionBytes + 3,
        sizeof(displacement));
    nextInstruction = instructionAddress + 7U;
    return (PVOID)(nextInstruction + (LONG_PTR)displacement);
}

/*
 * Validates the descriptor directly referenced by the KeQueryPerformanceCounter feature corresponding to the version.
 * The precise feature already provides structural semantics; this function only validates fields that will be
 * read/written later, without requiring the function entry to belong to a loaded image resolvable by RtlPcToFileHeader.
 */
static
BOOLEAN
kswordArkSystemTimeValidateDescriptor(
    _In_ PVOID descriptor,
    _In_ ULONG osBuildNumber
    )
{
    PVOID secondaryFunction = NULL;
    PVOID legacyFunction = NULL;
    ULONG handlerIndex = 0UL;
    ULONG internalFlags = 0UL;

    if (descriptor == NULL ||
        (ULONG_PTR)descriptor < (ULONG_PTR)MmSystemRangeStart ||
        ((ULONG_PTR)descriptor & (sizeof(PVOID) - 1U)) != 0U) {
        return FALSE;
    }

    if (!kswordArkSystemTimeReadPointer(
            (const UCHAR*)descriptor +
                KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET,
            &secondaryFunction) ||
        !kswordArkSystemTimeIsKernelCodePointer(secondaryFunction)) {
        return FALSE;
    }

    /* The new main entry comes from the processor table; do not treat the old 0x70 slot, which no longer participates in takeover, as a prerequisite. */
    if (osBuildNumber < KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM &&
        (!kswordArkSystemTimeReadPointer(
            (const UCHAR*)descriptor +
                KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET,
            &legacyFunction) ||
         !kswordArkSystemTimeIsKernelCodePointer(legacyFunction))) {
        return FALSE;
    }

    if (!kswordArkSystemTimeReadUlong(
            (const UCHAR*)descriptor +
                KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET,
            &internalFlags)) {
        return FALSE;
    }
    UNREFERENCED_PARAMETER(internalFlags);

    if (osBuildNumber >= KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM &&
        (!kswordArkSystemTimeReadUlong(
            (const UCHAR*)descriptor +
                KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET,
            &handlerIndex) ||
         handlerIndex >= 256UL)) {
        return FALSE;
    }

    return TRUE;
}

/*
 * Locate the descriptor reference based on the system version branch: Up to build 20348,
 * the path uses MOV RDI,[RIP+disp32]; subsequent builds use MOV RSI,[RIP+disp32].
 * Both modes verify the descriptor fields actually accessed to prevent empty slots
 * or invalid addresses from reaching the runtime phase after a feature match.
 */
static
NTSTATUS
kswordArkSystemTimeFindDescriptor(
    _In_reads_bytes_(KSW_SYSTEM_TIME_SCAN_BYTES) const UCHAR* code,
    _In_ ULONG_PTR codeAddress,
    _In_ ULONG osBuildNumber,
    _In_ BOOLEAN guardedResolution,
    _Out_ PVOID* descriptor
    )
{
    ULONG offset = 0UL;
    PVOID guardedDescriptor = NULL;
    const UCHAR kExpectedModRm =
        osBuildNumber <= KSW_SYSTEM_TIME_RDI_PATTERN_BUILD_MAX
        ? 0x3DU
        : 0x35U;

    if (code == NULL || descriptor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *descriptor = NULL;

    for (offset = 0UL;
         offset + 7UL <= KSW_SYSTEM_TIME_SCAN_BYTES;
         ++offset) {
        PVOID storageAddress = NULL;
        PVOID candidateDescriptor = NULL;

        /* Accepts only the complete three-byte instruction prefix corresponding to the current system version. */
        if (code[offset] != 0x48U ||
            code[offset + 1UL] != 0x8BU ||
            code[offset + 2UL] != kExpectedModRm) {
            continue;
        }

        storageAddress = kswordArkSystemTimeRipTarget(
            codeAddress + offset,
            code + offset);
        if (!kswordArkSystemTimeReadPointer(
                storageAddress,
                &candidateDescriptor)) {
            continue;
        }

        if (!kswordArkSystemTimeValidateDescriptor(
                candidateDescriptor,
                osBuildNumber)) {
            continue;
        }
        if (!guardedResolution) {
            *descriptor = candidateDescriptor;
            return STATUS_SUCCESS;
        }
        if (guardedDescriptor == NULL) {
            guardedDescriptor = candidateDescriptor;
        } else if (guardedDescriptor != candidateDescriptor) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    if (guardedDescriptor != NULL) {
        *descriptor = guardedDescriptor;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/*
 * Newer Windows versions place the active counter entry in a handler table indexed by clock source.
 * enumerate LEA RCX,[RIP+disp32] candidates; the enhanced solution further validates using function pointers within the table.
 */
static
NTSTATUS
kswordArkSystemTimeFindHandlerSlot(
    _In_reads_bytes_(KSW_SYSTEM_TIME_SCAN_BYTES) const UCHAR* code,
    _In_ ULONG_PTR codeAddress,
    _In_ PVOID descriptor,
    _In_ BOOLEAN guardedResolution,
    _Out_ volatile PVOID** handlerSlot
    )
{
    ULONG handlerIndex = 0UL;
    ULONG offset = 0UL;
    volatile PVOID* guardedSlot = NULL;

    if (code == NULL ||
        descriptor == NULL ||
        handlerSlot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *handlerSlot = NULL;

    if (!kswordArkSystemTimeReadUlong(
            (const UCHAR*)descriptor +
                KSW_SYSTEM_TIME_HANDLER_INDEX_OFFSET,
            &handlerIndex) ||
        handlerIndex >= 256UL) {
        return STATUS_DATA_ERROR;
    }

    for (offset = 0UL;
         offset + 7UL <= KSW_SYSTEM_TIME_SCAN_BYTES;
         ++offset) {
        PVOID tableAddress = NULL;
        volatile PVOID* candidateSlot = NULL;
        PVOID candidateFunction = NULL;

        /*
         * Newer paths first use ADD RAX, RAX to form a 16-byte row offset, then load the table base address.
         * Verify two adjacent instructions simultaneously to avoid misclassifying unrelated LEA tables within the same function as processor tables.
         */
        if (offset < 3UL ||
            code[offset - 3UL] != 0x48U ||
            code[offset - 2UL] != 0x03U ||
            code[offset - 1UL] != 0xC0U ||
            code[offset] != 0x48U ||
            code[offset + 1UL] != 0x8DU ||
            code[offset + 2UL] != 0x0DU) {
            continue;
        }

        tableAddress = kswordArkSystemTimeRipTarget(
            codeAddress + offset,
            code + offset);
        candidateSlot = (volatile PVOID*)(
            (UCHAR*)tableAddress +
            ((SIZE_T)handlerIndex *
                KSW_SYSTEM_TIME_HANDLER_ROW_BYTES));
        /* Reject empty slots in compatibility mode; enhanced mode further requires the target to be valid kernel code. */
        if (!kswordArkSystemTimeReadPointer(
                (const VOID*)candidateSlot,
                &candidateFunction) ||
            candidateFunction == NULL ||
            (guardedResolution &&
             !kswordArkSystemTimeIsKernelCodePointer(
                candidateFunction))) {
            continue;
        }

        if (!guardedResolution) {
            *handlerSlot = candidateSlot;
            return STATUS_SUCCESS;
        }
        if (guardedSlot == NULL) {
            guardedSlot = candidateSlot;
        } else if (guardedSlot != candidateSlot) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    if (guardedSlot != NULL) {
        *handlerSlot = guardedSlot;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/*
 * The public resolution entry selects a compatible or enhanced validation mode based on the protocol.
 * x86 is currently unsupported to avoid incorrectly applying x64 RIP-relative rules to other architectures.
 */
NTSTATUS
kswordArkSystemTimeResolve(
    _In_ ULONG resolutionMode,
    _Out_ KswordArkSystemTimeResolution* resolution
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    UNICODE_STRING routineName = { 0 };
    PVOID queryCounterRoutine = NULL;
    UCHAR code[KSW_SYSTEM_TIME_SCAN_BYTES] = { 0 };
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    PVOID descriptor = NULL;
    volatile PVOID* primarySlot = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN guardedResolution = FALSE;

    if (resolution == NULL ||
        (resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
         resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED)) {
        return STATUS_INVALID_PARAMETER;
    }
    guardedResolution =
        resolutionMode ==
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED;
    RtlZeroMemory(resolution, sizeof(*resolution));

    RtlInitUnicodeString(
        &routineName,
        L"KeQueryPerformanceCounter");
    queryCounterRoutine =
        MmGetSystemRoutineAddress(&routineName);
    if (queryCounterRoutine == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Kernel image code pages should be resident; SEH still prevents anomalous image states from penetrating IOCTLs. */
    __try {
        RtlCopyMemory(
            code,
            queryCounterRoutine,
            sizeof(code));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (versionInfo.dwBuildNumber < 9200UL) {
        return STATUS_NOT_SUPPORTED;
    }
    resolution->osBuildNumber = versionInfo.dwBuildNumber;

    status = kswordArkSystemTimeFindDescriptor(
        code,
        (ULONG_PTR)queryCounterRoutine,
        versionInfo.dwBuildNumber,
        guardedResolution,
        &descriptor);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    primarySlot = (volatile PVOID*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_LEGACY_SLOT_OFFSET);
    if (versionInfo.dwBuildNumber >=
        KSW_SYSTEM_TIME_HANDLER_BUILD_MINIMUM) {
        status = kswordArkSystemTimeFindHandlerSlot(
            code,
            (ULONG_PTR)queryCounterRoutine,
            descriptor,
            guardedResolution,
            &primarySlot);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        resolution->usesHandlerTable = TRUE;
    }

    resolution->primarySlot = primarySlot;
    resolution->secondarySlot = (volatile PVOID*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_SECONDARY_SLOT_OFFSET);
    resolution->internalFlags = (volatile LONG*)(
        (UCHAR*)descriptor +
        KSW_SYSTEM_TIME_INTERNAL_FLAGS_OFFSET);
    resolution->counterDescriptor = descriptor;
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(ResolutionMode);
    UNREFERENCED_PARAMETER(Resolution);
    return STATUS_NOT_SUPPORTED;
#endif
}
