#pragma once

#include "callback_internal.h"

EXTERN_C_START

PVOID
kswordArkCallbackExtendedGetSystemRoutine(
    _In_z_ PCWSTR routineName
    );

BOOLEAN
kswordArkCallbackExtendedResolveRipRelative(
    _In_ ULONG64 instructionAddress,
    _In_ ULONG displacementOffset,
    _In_ ULONG instructionLength,
    _Out_ ULONG64* targetAddressOut
    );

BOOLEAN
kswordArkCallbackExtendedReadPointer(
    _In_ ULONG64 address,
    _Out_ ULONG64* valueOut
    );

BOOLEAN
kswordArkCallbackExtendedReadListEntry(
    _In_ ULONG64 address,
    _Out_ LIST_ENTRY* entryOut
    );

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
    );

EXTERN_C_END
