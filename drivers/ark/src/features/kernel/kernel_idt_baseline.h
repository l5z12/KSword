#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkKernelBaselineIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkIdtBaselineInitialize(
    VOID
    );

VOID
kswordArkIdtBaselineUninitialize(
    VOID
    );

BOOLEAN
kswordArkIdtBaselineQuery(
    _In_ USHORT processorGroup,
    _In_ UCHAR processorNumber,
    _In_ UCHAR vector,
    _Out_opt_ ULONGLONG* tableBaseOut,
    _Out_opt_ ULONG* tableLimitOut,
    _Out_opt_ ULONGLONG* entryAddressOut,
    _Out_opt_ ULONGLONG* rawLowOut,
    _Out_opt_ ULONGLONG* rawHighOut,
    _Out_opt_ ULONGLONG* handlerOut,
    _Out_opt_ ULONG* generationOut
    );

NTSTATUS
kswordArkIdtBaselineRestore(
    _In_ const KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST* request,
    _Out_ KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE* response
    );

EXTERN_C_END
