#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

#define KSW_RXPF_X64_MAX_INSTRUCTION_BYTES 15UL

/*
 * This layout exactly matches the register pushes in page_fault_stub.asm.
 * HardwareRsp/HardwareSs exist only for a privilege transition; kernel faults
 * calculate logical RSP from the address of HardwareRsp instead of reading it.
 */
typedef struct KswRxpfTrapFrame
{
    ULONGLONG r15;
    ULONGLONG r14;
    ULONGLONG r13;
    ULONGLONG r12;
    ULONGLONG r11;
    ULONGLONG r10;
    ULONGLONG r9;
    ULONGLONG r8;
    ULONGLONG rdi;
    ULONGLONG rsi;
    ULONGLONG rbp;
    ULONGLONG rbx;
    ULONGLONG rdx;
    ULONGLONG rcx;
    ULONGLONG rax;
    ULONGLONG errorCode;
    ULONGLONG rip;
    ULONGLONG cs;
    ULONGLONG rflags;
    ULONGLONG hardwareRsp;
    ULONGLONG hardwareSs;
} KswRxpfTrapFrame, *PkswRxpfTrapFrame;

typedef struct KswRxpfEmulationContext
{
    PkswRxpfTrapFrame frame;
    ULONGLONG logicalRsp;
    ULONGLONG stackLow;
    ULONGLONG stackHigh;
    ULONG availableBytes;
    ULONG decodedInstruction;
    ULONG emulationResult;
    ULONG instructionLength;
    NTSTATUS status;
    UCHAR instruction[KSW_RXPF_X64_MAX_INSTRUCTION_BYTES];
} KswRxpfEmulationContext, *PkswRxpfEmulationContext;

_Must_inspect_result_
NTSTATUS
kswRxpfX64EmulateOne(
    _Inout_ PkswRxpfEmulationContext context
    );

_Must_inspect_result_
NTSTATUS
kswRxpfX64RunUnitTests(
    VOID
    );

EXTERN_C_END
