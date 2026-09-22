#pragma once

#include <ntddk.h>

#include "page_state_table.h"
#include "x64_instruction_emulator.h"

EXTERN_C_START

#define KSW_RXPF_DISPATCH_CHAIN 0ULL
#define KSW_RXPF_DISPATCH_HANDLED 1ULL

NTSTATUS
kswRxpfPageFaultManagerInitialize(
    _In_ PkswRxpfPageTable pageTable,
    _In_ ULONG maximumProcessorCount
    );

VOID
kswRxpfPageFaultManagerUninitialize(
    VOID
    );

NTSTATUS
kswRxpfPageFaultInstall(
    VOID
    );

NTSTATUS
kswRxpfPageFaultRestore(
    VOID
    );

BOOLEAN
kswRxpfPageFaultIsInstalled(
    VOID
    );

ULONG
kswRxpfPageFaultProcessorCount(
    VOID
    );

ULONGLONG
NTAPI
KswRxpfPageFaultDispatch(
    _Inout_ PkswRxpfTrapFrame frame,
    _Out_ PVOID* transferTargetOut,
    _Out_ ULONGLONG* resumeRspOut,
    _Out_ PkswRxpfTrapFrame resumeFrameOut
    );

VOID
KswRxpfPageFaultStub(
    VOID
    );

EXTERN_C_END
