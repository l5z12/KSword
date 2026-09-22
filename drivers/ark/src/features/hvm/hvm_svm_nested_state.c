/* Do not memcpy whole VMCBs: VMLOAD state and host physical controls have different owners. */
#include "hvm_svm_nested_state.h"

/* Copy explicit byte spans, including segment records, without unaligned word loads. */
static void kswNsvmCopy(KswSvmVmcb* destinationArg, const KswSvmVmcb* sourceArg,
    unsigned int offset, unsigned int bytes)
{
    /* Both images are processor-owned pages, never untrusted mapped guest pointers. */
    unsigned char* destination = (unsigned char*)destinationArg;
    /* Source snapshots remain immutable during a single state transition. */
    const unsigned char* source = (const unsigned char*)sourceArg;
    /* Every range below is a fixed architectural offset/length within one page. */
    unsigned int index;
    /* Byte copying avoids descriptor alignment and C strict-aliasing assumptions. */
    for (index = 0; index < bytes; ++index) { destination[offset + index] = source[offset + index]; }
}

/* Copy state that a VMRUN alone must NOT load from its operand. */
void kswSvmNestedCopyVmload(KswSvmVmcb* destination, const KswSvmVmcb* source)
{
    /* FS/GS include hidden bases, limits and attributes. */
    kswNsvmCopy(destination, source, KSW_VMCB_FS, 32);
    /* LDTR is explicitly excluded from the automatic VMEXIT host restore. */
    kswNsvmCopy(destination, source, KSW_VMCB_LDTR, 16);
    /* TR is part of software-controlled VMLOAD/VMSAVE state. */
    kswNsvmCopy(destination, source, KSW_VMCB_TR, 16);
    /* STAR/LSTAR/CSTAR/SFMASK/KERNEL_GS_BASE and all three SYSENTER registers. */
    kswNsvmCopy(destination, source, KSW_VMCB_STAR, 64);
}

/* Copy the baseline automatic guest state, preserving VMLOAD and control ownership. */
void kswSvmNestedCopyVmrun(KswSvmVmcb* destination, const KswSvmVmcb* source,
    unsigned int nestedPaging)
{
    /* Four automatic segment records: ES, CS, SS, DS. */
    kswNsvmCopy(destination, source, KSW_VMCB_ES, 64);
    /* GDTR is a descriptor-table pseudo-descriptor, not a task register. */
    kswNsvmCopy(destination, source, KSW_VMCB_GDTR, 16);
    /* IDTR switches independently of LDTR. */
    kswNsvmCopy(destination, source, KSW_VMCB_IDTR, 16);
    /* The entry validator, not this byte transfer, canonicalizes architectural modes. */
    kswNsvmCopy(destination, source, KSW_VMCB_CPL, 1);
    /* EFER is loaded from VMCB12 after virtual ownership checks. */
    kswNsvmCopy(destination, source, KSW_VMCB_EFER, 8);
    /* CR4/CR3/CR0/DR7/DR6/RFLAGS/RIP form one documented contiguous range. */
    kswNsvmCopy(destination, source, KSW_VMCB_CR4, 56);
    /* RSP and RAX have dedicated VMCB fields; other GPRs are not switched by VMRUN. */
    kswNsvmCopy(destination, source, KSW_VMCB_RSP, 8);
    /* CET core state is part of VMRUN, not the VMLOAD-managed user state. */
    kswNsvmCopy(destination, source, KSW_VMCB_S_CET, 24);
    /* Preserve the architectural special handling of accumulator state. */
    kswNsvmCopy(destination, source, KSW_VMCB_RAX, 8);
    /* CR2 is automatic guest state, but is not automatically restored as host CR2. */
    kswNsvmCopy(destination, source, KSW_VMCB_CR2, 8);
    /* G_PAT switches only when NP is enabled; it is not the real host PAT MSR. */
    if (nestedPaging) { kswNsvmCopy(destination, source, KSW_VMCB_PAT, 8); }
}

/* Reflect hardware-written core fields; supervisor CET admission remains restricted. */
void kswSvmNestedReflectExit(KswSvmVmcb* vmcb12, const KswSvmVmcb* vmcb02,
    unsigned int nestedPaging)
{
    /* EXITCODE/INFO1/INFO2/EXITINTINFO retain all 64 bits, including INVALID. */
    kswNsvmCopy(vmcb12, vmcb02, KSW_VMCB_EXITCODE, 32);
    /* NRIP is already zero for exits without architecturally defined next RIP. */
    kswNsvmCopy(vmcb12, vmcb02, KSW_VMCB_NRIP, 8);
    /* The hardware-updated V_IRQ and V_TPR bits coexist with L1-owned controls. */
    kswSvmWrite64(vmcb12, KSW_VMCB_INTCTL,
        (kswSvmRead64(vmcb12, KSW_VMCB_INTCTL) & ~0x10fULL) |
        (kswSvmRead64(vmcb02, KSW_VMCB_INTCTL) & 0x10fULL));
    /* Only interrupt-shadow bit zero is included in the baseline state contract. */
    kswSvmWrite64(vmcb12, 0x068U, (kswSvmRead64(vmcb12, 0x068U) & ~1ULL) |
        (kswSvmRead64(vmcb02, 0x068U) & 1ULL));
    /* Automatic state writes must not impersonate an explicit VMSAVE instruction. */
    kswSvmNestedCopyVmrun(vmcb12, vmcb02, nestedPaging);
}

/* Test the raw intercept bitmap by the APM exit-number ranges. */
unsigned int kswSvmNestedInterceptRequested(const KswSvmVmcb* vmcb12,
    KswSvmU64 exitCode)
{
    /* Exit ranges use 16-bit CR/DR, 32-bit exception and miscellaneous fields. */
    unsigned int offset, bit;
    /* Read one byte, avoiding an unaligned 16/32-bit access to the control image. */
    const unsigned char* bytes = (const unsigned char*)vmcb12;
    /* These four ranges map consecutively to the first eight intercept bytes. */
    if (exitCode < 0x40ULL) {
        /* CR read/write and DR read/write each consume 16 bits. */
        offset = (unsigned int)(exitCode >> 4) * 2U;
        /* The register number selects one bit within that 16-bit field. */
        bit = (unsigned int)(exitCode & 15ULL);
    } else if (exitCode < 0x60ULL) {
        /* Exception intercepts are a separate 32-bit bitmap at offset eight. */
        offset = 8U;
        /* Exceptions retain their architectural vector numbering. */
        bit = (unsigned int)(exitCode - 0x40ULL);
    } else if (exitCode < 0xa0ULL) {
        /* Baseline miscellaneous intercept words are at offsets 0x0c and 0x10. */
        offset = exitCode < 0x80ULL ? KSW_VMCB_MISC1 : KSW_VMCB_MISC2;
        /* Low five bits identify the intercept within either word. */
        bit = (unsigned int)(exitCode & 31ULL);
    } else {
        /* NPF/INVALID/new extension exits require explicit routing by the owner. */
        return KSW_NSVM_INTERCEPT_UNKNOWN;
    }
    /* This reports a raw request; MSR/IOIO still require their permission-map lookup. */
    return (bytes[offset + bit / 8U] >> (bit & 7U)) & 1U;
}
