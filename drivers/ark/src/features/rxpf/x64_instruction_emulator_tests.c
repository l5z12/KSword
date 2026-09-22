/*++

Module Name:

    x64_instruction_emulator_tests.c

Abstract:

    Load-time, allocation-free smoke tests for the RXPF scalar whitelist.

Environment:

    Kernel mode, PASSIVE_LEVEL during RXPF runtime initialization.

--*/

#include "x64_instruction_emulator.h"

#define KSW_TEST_EFLAGS_ZF 0x0000000000000040ULL
#define KSW_TEST_EFLAGS_OF 0x0000000000000800ULL

static VOID
kswRxpfInitializeTestContext(
    _Out_ PkswRxpfEmulationContext context,
    _Out_ PkswRxpfTrapFrame frame,
    _In_reads_bytes_(length) const UCHAR* instruction,
    _In_ ULONG length
    )
{
    ULONG_PTR stackLow = 0U;
    ULONG_PTR stackHigh = 0U;

    RtlZeroMemory(context, sizeof(*context));
    RtlZeroMemory(frame, sizeof(*frame));
    frame->rip = (ULONGLONG)(ULONG_PTR)kswRxpfX64RunUnitTests;
    frame->rflags = 2ULL;
    context->frame = frame;
    context->availableBytes = length;
    IoGetStackLimits(&stackLow, &stackHigh);
    context->stackLow = (ULONGLONG)stackLow;
    context->stackHigh = (ULONGLONG)stackHigh;
    context->logicalRsp = (ULONGLONG)stackHigh;
    RtlCopyMemory(context->instruction, instruction, length);
}

NTSTATUS
kswRxpfX64RunUnitTests(
    VOID
    )
{
    static const UCHAR kMovRaxImmediate[] = {
        0x48U, 0xB8U, 0x88U, 0x77U, 0x66U, 0x55U,
        0x44U, 0x33U, 0x22U, 0x11U
    };
    static const UCHAR kMovEaxImmediate[] = {
        0xB8U, 0xEFU, 0xCDU, 0xABU, 0x89U
    };
    static const UCHAR kAddRaxOne[] = {
        0x48U, 0x83U, 0xC0U, 0x01U
    };
    static const UCHAR kLeaRipRelative[] = {
        0x48U, 0x8DU, 0x05U, 0x10U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR kJumpIfZero[] = { 0x74U, 0x02U };
    static const UCHAR kPushRax[] = { 0x50U };
    static const UCHAR kPopRax[] = { 0x58U };
    static const UCHAR kCallNext[] = {
        0xE8U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR kReturnNear[] = { 0xC3U };
    static const UCHAR kLockNop[] = { 0xF0U, 0x90U };
    static const UCHAR kDuplicatePrefix[] = { 0x66U, 0x66U, 0x90U };
    static const UCHAR kMovRspImmediate[] = {
        0x48U, 0xBCU, 0x00U, 0x10U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U
    };
    static const UCHAR kPopRsp[] = { 0x5CU };
    KswRxpfEmulationContext context;
    KswRxpfTrapFrame frame;
    ULONGLONG stackSlots[16];
    ULONGLONG startRip = 0ULL;
    ULONGLONG startRsp = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kMovRaxImmediate,
        sizeof(kMovRaxImmediate));
    startRip = frame.rip;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.rax != 0x1122334455667788ULL ||
        frame.rip != startRip + sizeof(kMovRaxImmediate)) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kMovEaxImmediate,
        sizeof(kMovEaxImmediate));
    frame.rax = MAXULONGLONG;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.rax != 0x0000000089ABCDEFULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kAddRaxOne,
        sizeof(kAddRaxOne));
    frame.rax = 0x7FFFFFFFFFFFFFFFULL;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.rax != 0x8000000000000000ULL ||
        (frame.rflags & KSW_TEST_EFLAGS_OF) == 0ULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kLeaRipRelative,
        sizeof(kLeaRipRelative));
    startRip = frame.rip;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.rax != startRip + sizeof(kLeaRipRelative) + 0x10ULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kJumpIfZero,
        sizeof(kJumpIfZero));
    startRip = frame.rip;
    frame.rflags |= KSW_TEST_EFLAGS_ZF;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.rip != startRip + sizeof(kJumpIfZero) + 2ULL) {
        return STATUS_DATA_ERROR;
    }

    RtlZeroMemory(stackSlots, sizeof(stackSlots));
    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kPushRax,
        sizeof(kPushRax));
    frame.rax = 0x123456789ABCDEF0ULL;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.logicalRsp = startRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || context.logicalRsp != startRsp - 8ULL ||
        stackSlots[11] != frame.rax) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kPopRax,
        sizeof(kPopRax));
    stackSlots[12] = 0x0FEDCBA987654321ULL;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.logicalRsp = startRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.rax != stackSlots[12] ||
        context.logicalRsp != startRsp + 8ULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kCallNext,
        sizeof(kCallNext));
    startRip = frame.rip;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.logicalRsp = startRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) ||
        frame.rip != startRip + sizeof(kCallNext) ||
        context.logicalRsp != startRsp - 8ULL ||
        stackSlots[11] != startRip + sizeof(kCallNext)) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kReturnNear,
        sizeof(kReturnNear));
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    stackSlots[12] = frame.rip + 0x40ULL;
    context.logicalRsp = startRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (!NT_SUCCESS(status) || frame.rip != stackSlots[12] ||
        context.logicalRsp != startRsp + 8ULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kLockNop,
        sizeof(kLockNop));
    startRip = frame.rip;
    frame.rax = 0x55AAULL;
    status = kswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.rip != startRip ||
        frame.rax != 0x55AAULL) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kDuplicatePrefix,
        sizeof(kDuplicatePrefix));
    startRip = frame.rip;
    status = kswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.rip != startRip) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kMovRspImmediate,
        sizeof(kMovRspImmediate));
    startRip = frame.rip;
    startRsp = context.logicalRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (NT_SUCCESS(status) || frame.rip != startRip ||
        context.logicalRsp != startRsp) {
        return STATUS_DATA_ERROR;
    }

    kswRxpfInitializeTestContext(
        &context,
        &frame,
        kPopRsp,
        sizeof(kPopRsp));
    startRip = frame.rip;
    startRsp = (ULONGLONG)(ULONG_PTR)&stackSlots[12];
    context.logicalRsp = startRsp;
    status = kswRxpfX64EmulateOne(&context);
    if (status != STATUS_NOT_SUPPORTED || frame.rip != startRip ||
        context.logicalRsp != startRsp) {
        return STATUS_DATA_ERROR;
    }

    return STATUS_SUCCESS;
}
