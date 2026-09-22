/*++

Module Name:

    callback_extended_support.c

Abstract:

    Provide read-only memory, RIP-relative address, and unified line construction helper functions for the extended kernel callback enumerator.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"

PVOID
kswordArkCallbackExtendedGetSystemRoutine(
    _In_z_ PCWSTR routineNameArg
    )
/*++

Routine Description:

    Parse an ntoskrnl exported routine. Note: All private chain locations start from
    public export entries to avoid unbounded searches across the entire kernel image.

Arguments:

    RoutineName - null-terminated exported name.

Return Value:

    Return the routine address on success; return NULL if parameters are invalid or the export does not exist.

--*/
{
    UNICODE_STRING routineName;

    if (routineNameArg == NULL || routineNameArg[0] == L'\0') {
        return NULL;
    }

    RtlInitUnicodeString(&routineName, routineNameArg);
    return MmGetSystemRoutineAddress(&routineName);
}

BOOLEAN
kswordArkCallbackExtendedResolveRipRelative(
    _In_ ULONG64 instructionAddress,
    _In_ ULONG displacementOffset,
    _In_ ULONG instructionLength,
    _Out_ ULONG64* targetAddressOut
    )
/*++

Routine Description:

    Parse x64 RIP-relative instruction targets. Note: Displacement reads use unified exception protection and
    check positive/negative displacement calculations to prevent code byte corruption and integer wraparound.

Arguments:

    InstructionAddress: Starting address of the instruction.
    DisplacementOffset: offset of the disp32 value within the instruction.
    InstructionLength - Total instruction length.
    TargetAddressOut - Output the resolved virtual address.

Return Value:

    Returns TRUE on success; returns FALSE on read failure or invalid arithmetic.

--*/
{
    LONG displacement = 0L;
    ULONG64 nextInstruction = 0ULL;

    if (targetAddressOut == NULL ||
        instructionAddress == 0ULL ||
        instructionLength < (displacementOffset + sizeof(displacement))) {
        return FALSE;
    }

    *targetAddressOut = 0ULL;
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)(instructionAddress + displacementOffset),
            &displacement,
            sizeof(displacement))) {
        return FALSE;
    }

    nextInstruction = instructionAddress + instructionLength;
    if (displacement < 0) {
        const ULONG64 kBackwardBytes = (ULONG64)(-(LONG64)displacement);
        if (nextInstruction < kBackwardBytes) {
            return FALSE;
        }
        *targetAddressOut = nextInstruction - kBackwardBytes;
    }
    else {
        *targetAddressOut = nextInstruction + (ULONG64)displacement;
    }
    return *targetAddressOut != 0ULL;
}

BOOLEAN
kswordArkCallbackExtendedReadPointer(
    _In_ ULONG64 address,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Read a kernel value of native pointer width.

Arguments:

    Address: Address to be read.
    ValueOut - Outputs a 64-bit pointer value.

Return Value:

    Returns TRUE on success; returns FALSE if parameters are invalid or the read fails.

--*/
{
    ULONG_PTR value = 0U;

    if (address == 0ULL || valueOut == NULL) {
        return FALSE;
    }

    *valueOut = 0ULL;
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)address,
            &value,
            sizeof(value))) {
        return FALSE;
    }

    *valueOut = (ULONG64)value;
    return TRUE;
}

BOOLEAN
kswordArkCallbackExtendedReadListEntry(
    _In_ ULONG64 address,
    _Out_ LIST_ENTRY* entryOut
    )
/*++

Routine Description:

    Read a snapshot of a LIST_ENTRY.

Arguments:

    Address - LIST_ENTRY address.
    EntryOut - Snapshot of the output linked list pointer.

Return Value:

    Returns TRUE on success; returns FALSE if parameters are invalid or the read fails.

--*/
{
    if (address == 0ULL || entryOut == NULL) {
        return FALSE;
    }

    RtlZeroMemory(entryOut, sizeof(*entryOut));
    return kswordArkCallbackEnumReadMemory(
        (const VOID*)(ULONG_PTR)address,
        entryOut,
        sizeof(*entryOut));
}

VOID
kswordArkCallbackExtendedAddRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_opt_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG callbackClass,
    _In_ ULONG source,
    _In_ ULONG status,
    _In_ NTSTATUS lastStatus,
    _In_ ULONG registrationType,
    _In_ ULONG operationMask,
    _In_ ULONG objectTypeMask,
    _In_ ULONG64 callbackAddress,
    _In_ ULONG64 contextAddress,
    _In_ ULONG64 registrationAddress,
    _In_ ULONG extraFieldFlags,
    _In_opt_z_ PCWSTR nameText,
    _In_opt_z_ PCWSTR detailText
    )
/*++

Routine Description:

    Write an extended callback entry. Note: This function uniformly maintains valid fields, source
    trustworthiness, and module ownership to prevent conflicting R3 semantics from multiple list enumerators.

Arguments:

    Builder: Response builder.
    ModuleCache - Optional module cache.
    CallbackClass - Callback category.
    Source - Enumeration source.
    Status - Row status.
    LastStatus - Underlying NTSTATUS.
    RegistrationType - The specific registration API type.
    OperationMask - Optional operation mask.
    ObjectTypeMask - Optional object type mask.
    CallbackAddress - Address of the callback function.
    ContextAddress - Callback context or diagnostic value.
    RegistrationAddress: registration record, device object, or linked list node.
    ExtraFieldFlags: caller-supplied field flags.
    NameText - Optional line name.
    DetailText - Optional details.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (builder == NULL) {
        return;
    }

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = callbackClass;
    entry->source = source;
    entry->status = status;
    entry->lastStatus = lastStatus;
    entry->registrationType = registrationType;
    entry->operationMask = operationMask;
    entry->objectTypeMask = objectTypeMask;
    entry->callbackAddress = callbackAddress;
    entry->contextAddress = contextAddress;
    entry->registrationAddress = registrationAddress;
    entry->fieldFlags = extraFieldFlags;

    if (callbackAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS;
    }
    if (contextAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    }
    if (registrationAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    if (registrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    if (operationMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (objectTypeMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK;
    }
    if (nameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        kswordArkCallbackEnumCopyWide(
            entry->name,
            RTL_NUMBER_OF(entry->name),
            nameText);
    }

    kswordArkCallbackEnumCopyWide(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        detailText);

    if (source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API;
    }
    else if (source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API;
        if (source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL &&
            status == KSWORD_ARK_CALLBACK_ENUM_STATUS_OK &&
            registrationType == KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT &&
            (extraFieldFlags &
                KSWORD_ARK_CALLBACK_ENUM_FIELD_CLASS_INIT_DATA_VALIDATED) != 0UL) {
            entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE;
        }
    }
    else {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    if (moduleCache != NULL && callbackAddress != 0ULL) {
        kswordArkCallbackEnumFinalizeModuleCached(moduleCache, entry);
    }
}
