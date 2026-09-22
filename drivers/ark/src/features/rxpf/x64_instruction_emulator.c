/*++

Module Name:

    x64_instruction_emulator.c

Abstract:

    Allocation-free x86-64 whitelist decoder and one-instruction emulator.

Environment:

    Kernel mode, nonpaged vector-14 path.  Memory operands are rejected except
    for validated accesses to the current kernel stack by PUSH/POP/CALL/RET.

--*/

#include "x64_instruction_emulator.h"

#define KSW_EFLAGS_CF 0x0000000000000001ULL
#define KSW_EFLAGS_PF 0x0000000000000004ULL
#define KSW_EFLAGS_AF 0x0000000000000010ULL
#define KSW_EFLAGS_ZF 0x0000000000000040ULL
#define KSW_EFLAGS_SF 0x0000000000000080ULL
#define KSW_EFLAGS_OF 0x0000000000000800ULL
#define KSW_EFLAGS_ARITHMETIC_MASK \
    (KSW_EFLAGS_CF | KSW_EFLAGS_PF | KSW_EFLAGS_AF | \
     KSW_EFLAGS_ZF | KSW_EFLAGS_SF | KSW_EFLAGS_OF)

typedef struct KswRxpfDecoder
{
    PkswRxpfEmulationContext context;
    ULONG cursor;
    UCHAR rex;
    BOOLEAN operandSize16;
    BOOLEAN rexPresent;
} KswRxpfDecoder, *PkswRxpfDecoder;

static BOOLEAN
kswRxpfIsCanonical(
    _In_ ULONGLONG address
    )
{
    /* Bit 47, not merely the high word, selects canonical sign extension. */
    return address <= 0x00007FFFFFFFFFFFULL ||
        address >= 0xFFFF800000000000ULL;
}

static BOOLEAN
kswRxpfIsCanonicalKernelTarget(
    _In_ ULONGLONG address
    )
{
    /* Emulated kernel control flow never transfers into the user half. */
    return kswRxpfIsCanonical(address) &&
        address >= (ULONGLONG)(ULONG_PTR)MmSystemRangeStart;
}

static ULONGLONG
kswRxpfWidthMask(
    _In_ ULONG width
    )
{
    /* Avoid an undefined shift by 64 while producing an operand mask. */
    return width == 64UL ? MAXULONGLONG : ((1ULL << width) - 1ULL);
}

static ULONGLONG
kswRxpfSignBit(
    _In_ ULONG width
    )
{
    /* Width is validated to one of the architectural scalar sizes. */
    return 1ULL << (width - 1UL);
}

static ULONGLONG
kswRxpfSignExtend(
    _In_ ULONGLONG value,
    _In_ ULONG sourceWidth
    )
{
    ULONGLONG mask = kswRxpfWidthMask(sourceWidth);
    ULONGLONG sign = kswRxpfSignBit(sourceWidth);

    /* Extend only the selected source width into the 64-bit result. */
    value &= mask;
    if ((value & sign) != 0ULL) {
        value |= ~mask;
    }
    return value;
}

static BOOLEAN
kswRxpfEvenParity(
    _In_ UCHAR value
    )
{
    UCHAR folded = value;

    /* Fold eight input bits and use the inverted low bit for even parity. */
    folded ^= (UCHAR)(folded >> 4);
    folded ^= (UCHAR)(folded >> 2);
    folded ^= (UCHAR)(folded >> 1);
    return (folded & 1U) == 0U;
}

static PULONGLONG
kswRxpfRegisterStorage(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONG registerIndex
    )
{
    /* Map architectural register codes to the assembly-saved frame slots. */
    switch (registerIndex) {
    case 0UL: return &context->frame->rax;
    case 1UL: return &context->frame->rcx;
    case 2UL: return &context->frame->rdx;
    case 3UL: return &context->frame->rbx;
    case 5UL: return &context->frame->rbp;
    case 6UL: return &context->frame->rsi;
    case 7UL: return &context->frame->rdi;
    case 8UL: return &context->frame->r8;
    case 9UL: return &context->frame->r9;
    case 10UL: return &context->frame->r10;
    case 11UL: return &context->frame->r11;
    case 12UL: return &context->frame->r12;
    case 13UL: return &context->frame->r13;
    case 14UL: return &context->frame->r14;
    case 15UL: return &context->frame->r15;
    default: return NULL;
    }
}

static ULONGLONG
kswRxpfReadRegister(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONG registerCode,
    _In_ ULONG width,
    _In_ BOOLEAN rexPresent
    )
{
    PULONGLONG storage = NULL;
    ULONGLONG value = 0ULL;

    /* AH/CH/DH/BH are selected by byte codes 4..7 only without REX. */
    if (width == 8UL && !rexPresent &&
        registerCode >= 4UL && registerCode <= 7UL) {
        storage = kswRxpfRegisterStorage(context, registerCode - 4UL);
        return (*storage >> 8) & 0xFFULL;
    }
    /* Register code four represents the logical interrupted RSP. */
    if (registerCode == 4UL) {
        value = context->logicalRsp;
    } else {
        storage = kswRxpfRegisterStorage(context, registerCode);
        if (storage == NULL) {
            return 0ULL;
        }
        value = *storage;
    }
    return value & kswRxpfWidthMask(width);
}

static BOOLEAN
kswRxpfWriteRegister(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONG registerCode,
    _In_ ULONG width,
    _In_ BOOLEAN rexPresent,
    _In_ ULONGLONG value
    )
{
    PULONGLONG storage = NULL;
    ULONGLONG current = 0ULL;
    ULONGLONG mask = kswRxpfWidthMask(width);

    /* Update legacy high-byte registers without disturbing other bits. */
    if (width == 8UL && !rexPresent &&
        registerCode >= 4UL && registerCode <= 7UL) {
        storage = kswRxpfRegisterStorage(context, registerCode - 4UL);
        current = *storage;
        current &= ~0xFF00ULL;
        current |= (value & 0xFFULL) << 8;
        *storage = current;
        return TRUE;
    }
    /* Only explicit PUSH/POP/CALL/RET paths may change logical RSP. */
    if (registerCode == 4UL) {
        return FALSE;
    }
    storage = kswRxpfRegisterStorage(context, registerCode);
    if (storage == NULL) {
        return FALSE;
    }
    current = *storage;
    if (width == 64UL) {
        *storage = value;
    } else if (width == 32UL) {
        /* x86-64 zero-extends every 32-bit general-register write. */
        *storage = value & 0xFFFFFFFFULL;
    } else {
        *storage = (current & ~mask) | (value & mask);
    }
    return TRUE;
}

static BOOLEAN
kswRxpfReadByte(
    _Inout_ PkswRxpfDecoder decoder,
    _Out_ UCHAR* valueOut
    )
{
    /* A truncated instruction at the managed-page boundary is unsupported. */
    if (decoder->cursor >= decoder->context->availableBytes ||
        decoder->cursor >= KSW_RXPF_X64_MAX_INSTRUCTION_BYTES) {
        return FALSE;
    }
    *valueOut = decoder->context->instruction[decoder->cursor];
    decoder->cursor += 1UL;
    return TRUE;
}

static BOOLEAN
kswRxpfReadImmediate(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ ULONG byteCount,
    _Out_ ULONGLONG* valueOut
    )
{
    ULONGLONG value = 0ULL;

    /* Copy little-endian scalar bytes only from the pre-copied instruction. */
    if (byteCount == 0UL || byteCount > sizeof(value) ||
        decoder->cursor > decoder->context->availableBytes ||
        byteCount > decoder->context->availableBytes - decoder->cursor ||
        decoder->cursor > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES ||
        byteCount > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES - decoder->cursor) {
        return FALSE;
    }
    RtlCopyMemory(
        &value,
        &decoder->context->instruction[decoder->cursor],
        byteCount);
    decoder->cursor += byteCount;
    *valueOut = value;
    return TRUE;
}

static ULONG
kswRxpfOperandWidth(
    _In_ const KswRxpfDecoder* decoder,
    _In_ BOOLEAN byteOperation
    )
{
    /* Scalar width follows byte opcode, REX.W, 66h, then x64 default 32. */
    if (byteOperation) {
        return 8UL;
    }
    if ((decoder->rex & 0x08U) != 0U) {
        return 64UL;
    }
    if (decoder->operandSize16) {
        return 16UL;
    }
    return 32UL;
}

static VOID
kswRxpfUpdateLogicFlags(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONGLONG result,
    _In_ ULONG width
    )
{
    ULONGLONG masked = result & kswRxpfWidthMask(width);
    ULONGLONG flags = context->frame->rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Logical operations clear CF/OF and derive SF/ZF/PF from the result. */
    if (masked == 0ULL) {
        flags |= KSW_EFLAGS_ZF;
    }
    if ((masked & kswRxpfSignBit(width)) != 0ULL) {
        flags |= KSW_EFLAGS_SF;
    }
    if (kswRxpfEvenParity((UCHAR)masked)) {
        flags |= KSW_EFLAGS_PF;
    }
    context->frame->rflags = flags;
}

static VOID
kswRxpfUpdateAddFlags(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONGLONG leftArg,
    _In_ ULONGLONG rightArg,
    _In_ ULONGLONG resultArg,
    _In_ ULONG width
    )
{
    ULONGLONG mask = kswRxpfWidthMask(width);
    ULONGLONG sign = kswRxpfSignBit(width);
    ULONGLONG left = leftArg & mask;
    ULONGLONG right = rightArg & mask;
    ULONGLONG result = resultArg & mask;
    ULONGLONG flags = context->frame->rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Compute the six arithmetic status flags for an addition. */
    if (result < left) flags |= KSW_EFLAGS_CF;
    if (((~(left ^ right)) & (left ^ result) & sign) != 0ULL) flags |= KSW_EFLAGS_OF;
    if (((left ^ right ^ result) & 0x10ULL) != 0ULL) flags |= KSW_EFLAGS_AF;
    if (result == 0ULL) flags |= KSW_EFLAGS_ZF;
    if ((result & sign) != 0ULL) flags |= KSW_EFLAGS_SF;
    if (kswRxpfEvenParity((UCHAR)result)) flags |= KSW_EFLAGS_PF;
    context->frame->rflags = flags;
}

static VOID
kswRxpfUpdateSubFlags(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONGLONG leftArg,
    _In_ ULONGLONG rightArg,
    _In_ ULONGLONG resultArg,
    _In_ ULONG width
    )
{
    ULONGLONG mask = kswRxpfWidthMask(width);
    ULONGLONG sign = kswRxpfSignBit(width);
    ULONGLONG left = leftArg & mask;
    ULONGLONG right = rightArg & mask;
    ULONGLONG result = resultArg & mask;
    ULONGLONG flags = context->frame->rflags &
        ~KSW_EFLAGS_ARITHMETIC_MASK;

    /* Compute the six arithmetic status flags for subtraction/comparison. */
    if (left < right) flags |= KSW_EFLAGS_CF;
    if ((((left ^ right) & (left ^ result)) & sign) != 0ULL) flags |= KSW_EFLAGS_OF;
    if (((left ^ right ^ result) & 0x10ULL) != 0ULL) flags |= KSW_EFLAGS_AF;
    if (result == 0ULL) flags |= KSW_EFLAGS_ZF;
    if ((result & sign) != 0ULL) flags |= KSW_EFLAGS_SF;
    if (kswRxpfEvenParity((UCHAR)result)) flags |= KSW_EFLAGS_PF;
    context->frame->rflags = flags;
}

static BOOLEAN
kswRxpfStackRangeValid(
    _In_ const KswRxpfEmulationContext* context,
    _In_ ULONGLONG address,
    _In_ ULONG byteCount
    )
{
    ULONGLONG end = address + byteCount;

    /* Require a non-wrapping range wholly inside the current kernel stack. */
    if (byteCount == 0UL || end < address ||
        address < context->stackLow || end > context->stackHigh) {
        return FALSE;
    }
    /* Stack pages must already be resident; the emulator never pages them in. */
    return MmIsAddressValid((PVOID)(ULONG_PTR)address) &&
        MmIsAddressValid((PVOID)(ULONG_PTR)(end - 1ULL));
}

static BOOLEAN
kswRxpfResumeScratchValid(
    _In_ const KswRxpfEmulationContext* context,
    _In_ ULONGLONG resumeRsp
    )
{
    /* The assembly return path needs four resident qwords below resume RSP. */
    if (resumeRsp < 32ULL) {
        return FALSE;
    }
    return kswRxpfStackRangeValid(context, resumeRsp - 32ULL, 32UL);
}

static BOOLEAN
kswRxpfStackRead(
    _In_ const KswRxpfEmulationContext* context,
    _In_ ULONGLONG address,
    _Out_writes_bytes_(byteCount) PVOID buffer,
    _In_ ULONG byteCount
    )
{
    /* Refuse every memory read outside the resident current kernel stack. */
    if (!kswRxpfStackRangeValid(context, address, byteCount)) {
        return FALSE;
    }
    __try {
        RtlCopyMemory(buffer, (const VOID*)(ULONG_PTR)address, byteCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswRxpfStackWrite(
    _In_ const KswRxpfEmulationContext* context,
    _In_ ULONGLONG address,
    _In_reads_bytes_(byteCount) const VOID* buffer,
    _In_ ULONG byteCount
    )
{
    /* Refuse every memory write outside the resident current kernel stack. */
    if (!kswRxpfStackRangeValid(context, address, byteCount)) {
        return FALSE;
    }
    __try {
        RtlCopyMemory((VOID*)(ULONG_PTR)address, buffer, byteCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
kswRxpfApplyBinary(
    _Inout_ PkswRxpfEmulationContext context,
    _In_ ULONG operation,
    _In_ ULONG destinationRegister,
    _In_ ULONG width,
    _In_ BOOLEAN rexPresent,
    _In_ ULONGLONG left,
    _In_ ULONGLONG right
    )
{
    ULONGLONG mask = kswRxpfWidthMask(width);
    ULONGLONG result = 0ULL;
    BOOLEAN writeResult = TRUE;

    /* Execute only the explicitly enumerated scalar ALU operations. */
    switch (operation) {
    case KSWORD_ARK_RXPF_DECODE_ADD:
        result = (left + right) & mask;
        kswRxpfUpdateAddFlags(context, left, right, result, width);
        break;
    case KSWORD_ARK_RXPF_DECODE_SUB:
    case KSWORD_ARK_RXPF_DECODE_CMP:
        result = (left - right) & mask;
        kswRxpfUpdateSubFlags(context, left, right, result, width);
        writeResult = operation != KSWORD_ARK_RXPF_DECODE_CMP;
        break;
    case KSWORD_ARK_RXPF_DECODE_XOR:
        result = (left ^ right) & mask;
        kswRxpfUpdateLogicFlags(context, result, width);
        break;
    case KSWORD_ARK_RXPF_DECODE_AND:
    case KSWORD_ARK_RXPF_DECODE_TEST:
        result = (left & right) & mask;
        kswRxpfUpdateLogicFlags(context, result, width);
        writeResult = operation != KSWORD_ARK_RXPF_DECODE_TEST;
        break;
    case KSWORD_ARK_RXPF_DECODE_OR:
        result = (left | right) & mask;
        kswRxpfUpdateLogicFlags(context, result, width);
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }
    if (writeResult &&
        !kswRxpfWriteRegister(
            context,
            destinationRegister,
            width,
            rexPresent,
            result)) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswRxpfConditionTrue(
    _In_ UCHAR condition,
    _In_ ULONGLONG flags
    )
{
    BOOLEAN cf = (flags & KSW_EFLAGS_CF) != 0ULL;
    BOOLEAN pf = (flags & KSW_EFLAGS_PF) != 0ULL;
    BOOLEAN zf = (flags & KSW_EFLAGS_ZF) != 0ULL;
    BOOLEAN sf = (flags & KSW_EFLAGS_SF) != 0ULL;
    BOOLEAN of = (flags & KSW_EFLAGS_OF) != 0ULL;

    /* Evaluate all sixteen architectural Jcc condition encodings. */
    switch (condition & 0x0FU) {
    case 0x0U: return of;
    case 0x1U: return !of;
    case 0x2U: return cf;
    case 0x3U: return !cf;
    case 0x4U: return zf;
    case 0x5U: return !zf;
    case 0x6U: return cf || zf;
    case 0x7U: return !cf && !zf;
    case 0x8U: return sf;
    case 0x9U: return !sf;
    case 0xAU: return pf;
    case 0xBU: return !pf;
    case 0xCU: return sf != of;
    case 0xDU: return sf == of;
    case 0xEU: return zf || (sf != of);
    default: return !zf && (sf == of);
    }
}

static NTSTATUS
kswRxpfDecodeLea(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR modRm
    )
{
    PkswRxpfEmulationContext context = decoder->context;
    ULONG mod = (modRm >> 6) & 3U;
    ULONG destination = ((modRm >> 3) & 7U) |
        (((decoder->rex >> 2) & 1U) << 3);
    ULONG rm = modRm & 7U;
    ULONG width = kswRxpfOperandWidth(decoder, FALSE);
    ULONGLONG base = 0ULL;
    ULONGLONG index = 0ULL;
    ULONGLONG displacementRaw = 0ULL;
    LONGLONG displacement = 0LL;
    ULONG scale = 1UL;
    BOOLEAN ripRelative = FALSE;
    BOOLEAN basePresent = TRUE;

    /* LEA requires a memory encoding but never dereferences the address. */
    if (mod == 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    if (rm == 4UL) {
        UCHAR sib = 0U;
        ULONG sibIndex = 0UL;
        ULONG sibBase = 0UL;

        if (!kswRxpfReadByte(decoder, &sib)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        scale = 1UL << ((sib >> 6) & 3U);
        sibIndex = ((sib >> 3) & 7U) |
            (((decoder->rex >> 1) & 1U) << 3);
        sibBase = (sib & 7U) | ((decoder->rex & 1U) << 3);
        if (((sib >> 3) & 7U) != 4U ||
            ((decoder->rex >> 1) & 1U) != 0U) {
            index = kswRxpfReadRegister(context, sibIndex, 64UL, TRUE);
        }
        if (mod == 0UL && (sib & 7U) == 5U) {
            basePresent = FALSE;
        } else {
            base = kswRxpfReadRegister(context, sibBase, 64UL, TRUE);
        }
    } else if (mod == 0UL && rm == 5UL) {
        ripRelative = TRUE;
        basePresent = FALSE;
    } else {
        ULONG baseRegister = rm | ((decoder->rex & 1U) << 3);

        base = kswRxpfReadRegister(context, baseRegister, 64UL, TRUE);
    }

    /* Consume the displacement selected by ModRM/SIB addressing. */
    if (mod == 1UL) {
        if (!kswRxpfReadImmediate(decoder, 1UL, &displacementRaw)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)kswRxpfSignExtend(displacementRaw, 8UL);
    } else if (mod == 2UL || ripRelative || !basePresent) {
        if (!kswRxpfReadImmediate(decoder, 4UL, &displacementRaw)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)kswRxpfSignExtend(displacementRaw, 32UL);
    }
    if (ripRelative) {
        base = context->frame->rip + decoder->cursor;
    }
    base = base + (index * scale) + (ULONGLONG)displacement;
    if (!kswRxpfIsCanonical(base) ||
        !kswRxpfWriteRegister(
            context,
            destination,
            width,
            decoder->rexPresent,
            base)) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_LEA;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodeRegisterBinary(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode,
    _In_ ULONG operation,
    _In_ BOOLEAN byteOperation,
    _In_ BOOLEAN reverseOperands
    )
{
    UCHAR modRm = 0U;
    ULONG mod = 0UL;
    ULONG reg = 0UL;
    ULONG rm = 0UL;
    ULONG destination = 0UL;
    ULONG source = 0UL;
    ULONG width = kswRxpfOperandWidth(decoder, byteOperation);
    ULONGLONG left = 0ULL;
    ULONGLONG right = 0ULL;

    UNREFERENCED_PARAMETER(opcode);
    if (!kswRxpfReadByte(decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    mod = (modRm >> 6) & 3U;
    reg = ((modRm >> 3) & 7U) |
        (((decoder->rex >> 2) & 1U) << 3);
    rm = (modRm & 7U) | ((decoder->rex & 1U) << 3);
    if (mod != 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    destination = reverseOperands ? reg : rm;
    source = reverseOperands ? rm : reg;
    left = kswRxpfReadRegister(
        decoder->context,
        destination,
        width,
        decoder->rexPresent);
    right = kswRxpfReadRegister(
        decoder->context,
        source,
        width,
        decoder->rexPresent);
    decoder->context->decodedInstruction = operation;
    return kswRxpfApplyBinary(
        decoder->context,
        operation,
        destination,
        width,
        decoder->rexPresent,
        left,
        right);
}

static NTSTATUS
kswRxpfDecodeImmediateGroup(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    UCHAR modRm = 0U;
    ULONG extension = 0UL;
    ULONG destination = 0UL;
    ULONG width = kswRxpfOperandWidth(decoder, opcode == 0x80U);
    ULONG operation = KSWORD_ARK_RXPF_DECODE_NONE;
    ULONG immediateBytes = 0UL;
    ULONGLONG immediate = 0ULL;
    ULONGLONG left = 0ULL;

    if (!kswRxpfReadByte(decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (((modRm >> 6) & 3U) != 3U) {
        return STATUS_NOT_SUPPORTED;
    }
    extension = (modRm >> 3) & 7U;
    destination = (modRm & 7U) | ((decoder->rex & 1U) << 3);
    switch (extension) {
    case 0UL: operation = KSWORD_ARK_RXPF_DECODE_ADD; break;
    case 1UL: operation = KSWORD_ARK_RXPF_DECODE_OR; break;
    case 4UL: operation = KSWORD_ARK_RXPF_DECODE_AND; break;
    case 5UL: operation = KSWORD_ARK_RXPF_DECODE_SUB; break;
    case 6UL: operation = KSWORD_ARK_RXPF_DECODE_XOR; break;
    case 7UL: operation = KSWORD_ARK_RXPF_DECODE_CMP; break;
    default: return STATUS_NOT_SUPPORTED;
    }
    immediateBytes = opcode == 0x81U
        ? (width == 16UL ? 2UL : 4UL)
        : 1UL;
    if (!kswRxpfReadImmediate(decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (opcode == 0x83U || (opcode == 0x81U && width == 64UL)) {
        immediate = kswRxpfSignExtend(
            immediate,
            opcode == 0x83U ? 8UL : 32UL);
    }
    left = kswRxpfReadRegister(
        decoder->context,
        destination,
        width,
        decoder->rexPresent);
    decoder->context->decodedInstruction = operation;
    return kswRxpfApplyBinary(
        decoder->context,
        operation,
        destination,
        width,
        decoder->rexPresent,
        left,
        immediate);
}

static NTSTATUS
kswRxpfDecodeMovModRm(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    UCHAR modRm = 0U;
    ULONG reg = 0UL;
    ULONG rm = 0UL;
    ULONG destination = 0UL;
    ULONG source = 0UL;
    ULONG width = kswRxpfOperandWidth(
        decoder,
        opcode == 0x88U || opcode == 0x8AU);
    ULONGLONG value = 0ULL;

    if (!kswRxpfReadByte(decoder, &modRm)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (((modRm >> 6) & 3U) != 3U) {
        return STATUS_NOT_SUPPORTED;
    }
    reg = ((modRm >> 3) & 7U) |
        (((decoder->rex >> 2) & 1U) << 3);
    rm = (modRm & 7U) | ((decoder->rex & 1U) << 3);
    destination = (opcode == 0x8BU || opcode == 0x8AU) ? reg : rm;
    source = (opcode == 0x8BU || opcode == 0x8AU) ? rm : reg;
    value = kswRxpfReadRegister(
        decoder->context,
        source,
        width,
        decoder->rexPresent);
    if (!kswRxpfWriteRegister(
            decoder->context,
            destination,
            width,
            decoder->rexPresent,
            value)) {
        return STATUS_INVALID_PARAMETER;
    }
    decoder->context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodeMovImmediateModRm(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    UCHAR modRm = 0U;
    ULONG destination = 0UL;
    ULONG width = kswRxpfOperandWidth(decoder, opcode == 0xC6U);
    ULONG immediateBytes = width == 8UL ? 1UL :
        (width == 16UL ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;

    if (!kswRxpfReadByte(decoder, &modRm) ||
        ((modRm >> 6) & 3U) != 3U ||
        ((modRm >> 3) & 7U) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    destination = (modRm & 7U) | ((decoder->rex & 1U) << 3);
    if (!kswRxpfReadImmediate(decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (width == 64UL) {
        immediate = kswRxpfSignExtend(immediate, 32UL);
    }
    if (!kswRxpfWriteRegister(
            decoder->context,
            destination,
            width,
            decoder->rexPresent,
            immediate)) {
        return STATUS_INVALID_PARAMETER;
    }
    decoder->context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodeTestImmediate(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    UCHAR modRm = 0U;
    ULONG source = 0UL;
    ULONG width = kswRxpfOperandWidth(decoder, opcode == 0xF6U);
    ULONG immediateBytes = width == 8UL ? 1UL :
        (width == 16UL ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;
    ULONGLONG left = 0ULL;

    if (!kswRxpfReadByte(decoder, &modRm) ||
        ((modRm >> 6) & 3U) != 3U ||
        ((modRm >> 3) & 7U) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    source = (modRm & 7U) | ((decoder->rex & 1U) << 3);
    if (!kswRxpfReadImmediate(decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (width == 64UL) {
        immediate = kswRxpfSignExtend(immediate, 32UL);
    }
    left = kswRxpfReadRegister(
        decoder->context,
        source,
        width,
        decoder->rexPresent);
    decoder->context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_TEST;
    return kswRxpfApplyBinary(
        decoder->context,
        KSWORD_ARK_RXPF_DECODE_TEST,
        source,
        width,
        decoder->rexPresent,
        left,
        immediate);
}

static NTSTATUS
kswRxpfDecodeControlFlow(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode,
    _In_ BOOLEAN twoByteOpcode,
    _In_ UCHAR secondOpcode
    )
{
    PkswRxpfEmulationContext context = decoder->context;
    ULONGLONG immediate = 0ULL;
    ULONGLONG nextRip = 0ULL;
    ULONGLONG target = 0ULL;
    LONGLONG displacement = 0LL;

    /* Decode relative JMP/CALL/Jcc displacements before calculating next RIP. */
    if (opcode == 0xEBU ||
        (!twoByteOpcode && opcode >= 0x70U && opcode <= 0x7FU)) {
        if (!kswRxpfReadImmediate(decoder, 1UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)kswRxpfSignExtend(immediate, 8UL);
    } else {
        if (!kswRxpfReadImmediate(decoder, 4UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        displacement = (LONGLONG)kswRxpfSignExtend(immediate, 32UL);
    }
    nextRip = context->frame->rip + decoder->cursor;
    target = nextRip + (ULONGLONG)displacement;
    if (!kswRxpfIsCanonicalKernelTarget(target)) {
        return STATUS_ACCESS_VIOLATION;
    }

    /* CALL first writes the architectural return address to the kernel stack. */
    if (opcode == 0xE8U) {
        ULONGLONG newRsp = context->logicalRsp - sizeof(ULONGLONG);

        if (newRsp > context->logicalRsp ||
            !kswRxpfResumeScratchValid(context, newRsp) ||
            !kswRxpfStackWrite(
                context,
                newRsp,
                &nextRip,
                sizeof(nextRip))) {
            return STATUS_STACK_OVERFLOW;
        }
        context->logicalRsp = newRsp;
        context->frame->rip = target;
        context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_CALL;
        return STATUS_SUCCESS;
    }
    if (twoByteOpcode || (opcode >= 0x70U && opcode <= 0x7FU)) {
        UCHAR condition = twoByteOpcode
            ? (UCHAR)(secondOpcode & 0x0FU)
            : (UCHAR)(opcode & 0x0FU);

        context->frame->rip = kswRxpfConditionTrue(
            condition,
            context->frame->rflags) ? target : nextRip;
        context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_JCC;
        return STATUS_SUCCESS;
    }
    context->frame->rip = target;
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_JMP;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodeStackRegister(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    PkswRxpfEmulationContext context = decoder->context;
    ULONG registerCode = (opcode & 7U) |
        ((decoder->rex & 1U) << 3);
    ULONG width = decoder->operandSize16 ? 16UL : 64UL;
    ULONG byteCount = width / 8UL;
    ULONGLONG value = 0ULL;

    /* PUSH writes before publishing the decremented logical RSP. */
    if (opcode >= 0x50U && opcode <= 0x57U) {
        ULONGLONG newRsp = context->logicalRsp - byteCount;

        value = kswRxpfReadRegister(
            context,
            registerCode,
            width,
            decoder->rexPresent);
        if (newRsp > context->logicalRsp ||
            !kswRxpfResumeScratchValid(context, newRsp) ||
            !kswRxpfStackWrite(context, newRsp, &value, byteCount)) {
            return STATUS_STACK_OVERFLOW;
        }
        context->logicalRsp = newRsp;
        context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_PUSH;
        return STATUS_SUCCESS;
    }

    /* POP SP/ESP/RSP can select an arbitrary handler-overlapping stack. */
    if (registerCode == 4UL) {
        return STATUS_NOT_SUPPORTED;
    }

    /* POP reads from old RSP, increments it, then applies the register write. */
    if (!kswRxpfStackRead(
            context,
            context->logicalRsp,
            &value,
            byteCount)) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->logicalRsp += byteCount;
    if (!kswRxpfWriteRegister(
            context,
            registerCode,
            width,
            decoder->rexPresent,
            value)) {
        return STATUS_INVALID_PARAMETER;
    }
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_POP;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodePushImmediate(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    PkswRxpfEmulationContext context = decoder->context;
    ULONG width = decoder->operandSize16 ? 16UL : 64UL;
    ULONG byteCount = width / 8UL;
    ULONG immediateBytes = opcode == 0x6AU ? 1UL :
        (decoder->operandSize16 ? 2UL : 4UL);
    ULONGLONG immediate = 0ULL;
    ULONGLONG newRsp = 0ULL;

    if (!kswRxpfReadImmediate(decoder, immediateBytes, &immediate)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = kswRxpfSignExtend(
        immediate,
        immediateBytes * 8UL);
    newRsp = context->logicalRsp - byteCount;
    if (newRsp > context->logicalRsp ||
        !kswRxpfResumeScratchValid(context, newRsp) ||
        !kswRxpfStackWrite(context, newRsp, &immediate, byteCount)) {
        return STATUS_STACK_OVERFLOW;
    }
    context->logicalRsp = newRsp;
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_PUSH;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfDecodeRet(
    _Inout_ PkswRxpfDecoder decoder,
    _In_ UCHAR opcode
    )
{
    PkswRxpfEmulationContext context = decoder->context;
    ULONGLONG target = 0ULL;
    ULONGLONG stackAdjustment = sizeof(ULONGLONG);
    ULONGLONG immediate = 0ULL;

    /* RET C2 adds an unsigned 16-bit caller-pop adjustment after the target. */
    if (opcode == 0xC2U) {
        if (!kswRxpfReadImmediate(decoder, 2UL, &immediate)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        stackAdjustment += immediate & 0xFFFFULL;
    }
    if (!kswRxpfStackRead(
            context,
            context->logicalRsp,
            &target,
            sizeof(target)) ||
        !kswRxpfIsCanonicalKernelTarget(target) ||
        context->logicalRsp + stackAdjustment < context->logicalRsp ||
        context->logicalRsp + stackAdjustment > context->stackHigh) {
        return STATUS_ACCESS_VIOLATION;
    }
    context->logicalRsp += stackAdjustment;
    context->frame->rip = target;
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_RET;
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfX64EmulateOne(
    _Inout_ PkswRxpfEmulationContext context
    )
{
    KswRxpfDecoder decoder;
    UCHAR opcode = 0U;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    BOOLEAN ripWasAssigned = FALSE;

    /* Validate fixed, pre-copied instruction and trap-frame inputs. */
    if (context == NULL || context->frame == NULL ||
        context->availableBytes == 0UL ||
        context->availableBytes > KSW_RXPF_X64_MAX_INSTRUCTION_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_NONE;
    context->emulationResult =
        KSWORD_ARK_RXPF_EMULATION_UNSUPPORTED_INSTRUCTION;
    context->instructionLength = 0UL;
    context->status = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&decoder, sizeof(decoder));
    decoder.context = context;

    /* Accept only operand-size and one final REX prefix; reject risky classes. */
    for (;;) {
        UCHAR prefix = 0U;

        if (!kswRxpfReadByte(&decoder, &prefix)) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }
        if (prefix == 0x66U) {
            if (decoder.operandSize16 || decoder.rexPresent) {
                status = STATUS_NOT_SUPPORTED;
                goto Exit;
            }
            decoder.operandSize16 = TRUE;
            continue;
        }
        if (prefix >= 0x40U && prefix <= 0x4FU) {
            if (decoder.rexPresent) {
                status = STATUS_NOT_SUPPORTED;
                goto Exit;
            }
            decoder.rex = prefix;
            decoder.rexPresent = TRUE;
            continue;
        }
        if (prefix == 0xF0U || prefix == 0xF2U || prefix == 0xF3U ||
            prefix == 0x67U || prefix == 0x2EU || prefix == 0x36U ||
            prefix == 0x3EU || prefix == 0x26U || prefix == 0x64U ||
            prefix == 0x65U) {
            status = STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        opcode = prefix;
        break;
    }

    /* Decode the bounded scalar whitelist without treating failures as NOPs. */
    if (opcode == 0x90U && !decoder.rexPresent) {
        context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_NOP;
        status = STATUS_SUCCESS;
    } else if (opcode >= 0xB8U && opcode <= 0xBFU) {
        ULONG registerCode = (opcode & 7U) |
            ((decoder.rex & 1U) << 3);
        ULONG width = kswRxpfOperandWidth(&decoder, FALSE);
        ULONG immediateBytes = width == 64UL ? 8UL :
            (width == 16UL ? 2UL : 4UL);
        ULONGLONG immediate = 0ULL;

        if (!kswRxpfReadImmediate(&decoder, immediateBytes, &immediate)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (!kswRxpfWriteRegister(
                context,
                registerCode,
                width,
                decoder.rexPresent,
                immediate)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
            status = STATUS_SUCCESS;
        }
    } else if (opcode >= 0xB0U && opcode <= 0xB7U) {
        ULONG registerCode = (opcode & 7U) |
            ((decoder.rex & 1U) << 3);
        ULONGLONG immediate = 0ULL;

        if (!kswRxpfReadImmediate(&decoder, 1UL, &immediate)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (!kswRxpfWriteRegister(
                context,
                registerCode,
                8UL,
                decoder.rexPresent,
                immediate)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            context->decodedInstruction = KSWORD_ARK_RXPF_DECODE_MOV;
            status = STATUS_SUCCESS;
        }
    } else if (opcode == 0x89U || opcode == 0x8BU ||
               opcode == 0x88U || opcode == 0x8AU) {
        status = kswRxpfDecodeMovModRm(&decoder, opcode);
    } else if (opcode == 0xC6U || opcode == 0xC7U) {
        status = kswRxpfDecodeMovImmediateModRm(&decoder, opcode);
    } else if (opcode == 0x8DU) {
        UCHAR modRm = 0U;

        if (!kswRxpfReadByte(&decoder, &modRm)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = kswRxpfDecodeLea(&decoder, modRm);
        }
    } else if (opcode == 0x01U || opcode == 0x03U ||
               opcode == 0x00U || opcode == 0x02U) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_ADD,
            opcode == 0x00U || opcode == 0x02U,
            opcode == 0x03U || opcode == 0x02U);
    } else if (opcode == 0x29U || opcode == 0x2BU ||
               opcode == 0x28U || opcode == 0x2AU) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_SUB,
            opcode == 0x28U || opcode == 0x2AU,
            opcode == 0x2BU || opcode == 0x2AU);
    } else if (opcode == 0x31U || opcode == 0x33U ||
               opcode == 0x30U || opcode == 0x32U) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_XOR,
            opcode == 0x30U || opcode == 0x32U,
            opcode == 0x33U || opcode == 0x32U);
    } else if (opcode == 0x21U || opcode == 0x23U ||
               opcode == 0x20U || opcode == 0x22U) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_AND,
            opcode == 0x20U || opcode == 0x22U,
            opcode == 0x23U || opcode == 0x22U);
    } else if (opcode == 0x09U || opcode == 0x0BU ||
               opcode == 0x08U || opcode == 0x0AU) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_OR,
            opcode == 0x08U || opcode == 0x0AU,
            opcode == 0x0BU || opcode == 0x0AU);
    } else if (opcode == 0x39U || opcode == 0x3BU ||
               opcode == 0x38U || opcode == 0x3AU) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_CMP,
            opcode == 0x38U || opcode == 0x3AU,
            opcode == 0x3BU || opcode == 0x3AU);
    } else if (opcode == 0x85U || opcode == 0x84U) {
        status = kswRxpfDecodeRegisterBinary(
            &decoder,
            opcode,
            KSWORD_ARK_RXPF_DECODE_TEST,
            opcode == 0x84U,
            FALSE);
    } else if (opcode == 0x80U || opcode == 0x81U || opcode == 0x83U) {
        status = kswRxpfDecodeImmediateGroup(&decoder, opcode);
    } else if (opcode == 0xF6U || opcode == 0xF7U) {
        status = kswRxpfDecodeTestImmediate(&decoder, opcode);
    } else if (opcode >= 0x50U && opcode <= 0x5FU) {
        status = kswRxpfDecodeStackRegister(&decoder, opcode);
    } else if (opcode == 0x68U || opcode == 0x6AU) {
        status = kswRxpfDecodePushImmediate(&decoder, opcode);
    } else if (opcode == 0xE8U || opcode == 0xE9U ||
               opcode == 0xEBU ||
               (opcode >= 0x70U && opcode <= 0x7FU)) {
        status = kswRxpfDecodeControlFlow(
            &decoder,
            opcode,
            FALSE,
            0U);
        ripWasAssigned = NT_SUCCESS(status);
    } else if (opcode == 0x0FU) {
        UCHAR secondOpcode = 0U;

        if (!kswRxpfReadByte(&decoder, &secondOpcode)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (secondOpcode >= 0x80U && secondOpcode <= 0x8FU) {
            status = kswRxpfDecodeControlFlow(
                &decoder,
                opcode,
                TRUE,
                secondOpcode);
            ripWasAssigned = NT_SUCCESS(status);
        } else {
            status = STATUS_NOT_SUPPORTED;
        }
    } else if (opcode == 0xC3U || opcode == 0xC2U) {
        status = kswRxpfDecodeRet(&decoder, opcode);
        ripWasAssigned = NT_SUCCESS(status);
    } else {
        status = STATUS_NOT_SUPPORTED;
    }

Exit:
    /* Never advance RIP on unsupported, truncated, or invalid instructions. */
    if (NT_SUCCESS(status)) {
        if (!ripWasAssigned) {
            context->frame->rip += decoder.cursor;
        }
        context->instructionLength = decoder.cursor;
        context->emulationResult = KSWORD_ARK_RXPF_EMULATION_SUCCESS;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        context->emulationResult = KSWORD_ARK_RXPF_EMULATION_CROSS_PAGE;
    } else if (status == STATUS_STACK_OVERFLOW ||
               status == STATUS_ACCESS_VIOLATION) {
        context->emulationResult = KSWORD_ARK_RXPF_EMULATION_STACK_RANGE;
    } else {
        context->emulationResult =
            KSWORD_ARK_RXPF_EMULATION_UNSUPPORTED_INSTRUCTION;
    }
    context->status = status;
    return status;
}
