/* Run the production exit dispatcher as a host state machine, without SVM instructions. */
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_runtime.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KswSvmCpu cpu;
static KswSvmNested nested;
static KswSvmVmcb guest, operand[2];
static KswNpt outer;
static unsigned char stack[KSW_SVM_STACK_BYTES];
static unsigned char msrpm[KSW_NSVM_MSRPM_BYTES], iopm[KSW_NSVM_IOPM_BYTES];
static unsigned char merged[KSW_NSVM_MSRPM_BYTES + KSW_NSVM_IOPM_BYTES];
__declspec(align(4096)) static KswSvmU64 shadow[8][512];
static KswSvmU64 memory[64][512];
static ULONGLONG fakeRip;
static unsigned traces;
void kswordSvmTrace(KswSvmCpu* c, ULONG stage) { (void)c; (void)stage; ++traces; }
void kswordSvmAsmGuestResume(void) { }
void kswordSvmAsmNestedProbe(void) { }
void kswordSvmAsmNestedPayload(void) { }
int kswordSvmNestedRead(void* context, KswSvmU64 address, KswSvmU64* value)
{
    (void)context;
    if ((address & 7) || address >= sizeof(memory)) { return 0; }
    *value = memory[address >> 12][(address & 4095) / 8];
    return 1;
}
int kswordSvmNestedCompareOr(void* context, KswSvmU64 address, KswSvmU64 expected, KswSvmU64 bits)
{
    KswSvmU64* slot;
    (void)context;
    if ((address & 7) || address >= sizeof(memory)) { return 0; }
    slot = &memory[address >> 12][(address & 4095) / 8];
    if (*slot != expected) { return 0; }
    *slot |= bits;
    return 1;
}
static int initialize(void)
{
    unsigned i;
    memset(&cpu, 0, sizeof(cpu));
    memset(&nested, 0, sizeof(nested));
    memset(&guest, 0, sizeof(guest));
    memset(memory, 0, sizeof(memory));
    cpu.guest = &guest;
    memset(msrpm, 0, sizeof(msrpm));
    memset(iopm, 0, sizeof(iopm));
    cpu.msrpm = msrpm; cpu.iopm = iopm;
    msrpm[0x820] = 3; /* EFER read/write, independent APM offset. */
    cpu.nested = &nested;
    cpu.Caps.PhysicalBits = 45;
    cpu.Caps.Page1Gb = TRUE;
    cpu.Caps.Pat = 0x0007010600070106ULL;
    cpu.originalEfer = 0xd01;
    cpu.launchRsp = 0xabc000;
    cpu.launchFlags = 0x202;
    cpu.gpr[3] = 0x1122334455667788ULL;
    nested.operand = operand;
    nested.operandPa = 0x10000;
    nested.mergedMaps = merged;
    nested.mergedMapsPa = 0x80000;
    nested.stack = stack;
    nested.outer = &outer;
    outer.rootPa = 0x1000;
    outer.addressMask = kswNptAddressMask(45);
    for (i = 0; i < 8; ++i) { nested.pages[i].words = shadow[i]; nested.pages[i].physical = 0x100000 + 4096ULL * i; }
    CHECK(kswSvmNestedShadowInitialize(&nested.shadow, nested.pages, 8, 45) == KSW_NSHADOW_OK);
    memory[1][0] = 0x2007;
    memory[2][0] = 0x3007;
    memory[3][0] = 0x4007;
    for (i = 0; i < 64; ++i) { memory[4][i] = 4096ULL * i | 7; }
    kswSvmWrite64(&guest, KSW_VMCB_CR3, 0x12345000);
    kswSvmWrite64(&guest, KSW_VMCB_EFER, 0x1d01);
    kswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 0x202);
    kswSvmWrite64(&guest, KSW_VMCB_GS, 0xaabbccdd);
    kswSvmWrite32(&guest, KSW_VMCB_MISC1, (1U << 18) | KSW_NSVM_MSR_PROT);
    kswSvmWrite64(&guest, KSW_VMCB_MSRPM, 0x20000);
    kswSvmWrite64(&guest, KSW_VMCB_IOPM, 0x22000);
    CHECK(KswordSvmNestedBuildProbe(&cpu) == STATUS_SUCCESS);
    CHECK(nested.sequence == 1 && !nested.entries && !nested.reflections);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_RAX) == nested.operandPa);
    fakeRip = 0x8000;
    traces = 0;
    return 0;
}
static ULONG emit(ULONGLONG code, ULONGLONG rax)
{
    kswSvmWrite64(&guest, KSW_VMCB_EXITCODE, code);
    kswSvmWrite64(&guest, KSW_VMCB_RAX, rax);
    kswSvmWrite64(&guest, KSW_VMCB_RIP, fakeRip);
    kswSvmWrite64(&guest, KSW_VMCB_NRIP, fakeRip + 3);
    fakeRip += 3;
    return kswordSvmNestedProbeExit(&cpu);
}
static ULONG writeMsr(ULONG msr, ULONGLONG value)
{
    cpu.gpr[1] = msr;
    cpu.gpr[2] = value >> 32;
    kswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, 1);
    return emit(KSW_SVM_EXIT_MSR, (ULONG)value);
}
static int begin(void)
{
    cpu.gpr[1] = KSW_SVM_CALL_SIGNATURE;
    cpu.gpr[2] = KSW_NSVM_BEGIN;
    CHECK(emit(KSW_SVM_EXIT_VMMCALL, nested.operandPa) == 0);
    CHECK(nested.begun && nested.originalGpr[3] == 0x1122334455667788ULL);
    kswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 2);
    CHECK(writeMsr(KSW_SVM_MSR_EFER, 0x1d01) == 0);
    CHECK(writeMsr(KSW_SVM_MSR_HSAVE, nested.operandPa + 4096) == 0);
    return 0;
}
static int testRoundtrip(void)
{
    ULONGLONG continuation;
    if (initialize() || begin()) { return 1; }
    kswSvmWrite64(operand, KSW_VMCB_GS, 0xbeef);
    CHECK(emit(0x82, nested.operandPa) == 0 && kswSvmRead64(&guest, KSW_VMCB_GS) == 0xbeef);
    continuation = fakeRip + 3;
    CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa) == 0);
    CHECK(nested.runningL2 && nested.entries == 1 && !nested.reflections);
    CHECK(nested.permissions.ready == 1 && merged[0x820] == 3);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_MSRPM) == 0x80000);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_IOPM) == 0x82000);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_NCR3) == nested.pages[0].physical);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_RIP) == (ULONGLONG)(ULONG_PTR)kswordSvmAsmNestedPayload);
    kswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 6);
    kswSvmWrite64(&guest, KSW_VMCB_EXITINFO2, 0x2123);
    CHECK(emit(KSW_SVM_EXIT_NPF, 0) == 0);
    CHECK(nested.faults == 1 && nested.lastTranslation.status == KSW_NNPT_OK && nested.shadow.used == 4);
    CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_INNER_MARKER) == 0);
    CHECK(!nested.runningL2 && nested.reflections == 1 && nested.lastMarker == KSW_NSVM_INNER_MARKER);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_RIP) == continuation);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_RAX) == nested.operandPa);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_MSRPM) == 0x20000);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_IOPM) == 0x22000);
    CHECK(kswSvmRead64(operand, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_CPUID);
    CHECK(kswSvmRead64(operand, KSW_VMCB_GS) == 0xbeef);
    CHECK(emit(0x83, nested.operandPa) == 0);
    CHECK(emit(0x84, nested.operandPa) == 0 && nested.virtualGif);
    CHECK(writeMsr(KSW_SVM_MSR_HSAVE, 0) == 0);
    CHECK(writeMsr(KSW_SVM_MSR_EFER, 0xd01) == 0);
    cpu.gpr[3] = 0xdeaddead;
    CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_DONE_MARKER) == 1);
    CHECK(cpu.Result == STATUS_SUCCESS && !nested.RunningL2 && traces == 0);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_RSP) == cpu.launchRsp && kswSvmRead64(&guest, KSW_VMCB_RFLAGS) == 0x202);
    CHECK(kswSvmRead64(&guest, KSW_VMCB_GS) == 0xaabbccdd && cpu.gpr[3] == 0x1122334455667788ULL);
    CHECK(nested.sequence == 1); /* Only real native MSR readback may publish an even sequence. */
    return 0;
}
static int testFailures(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 9; ++scenario) {
        if (initialize() || begin()) { return 1; }
        if (scenario == 0) { CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_DONE_MARKER) == 1); }
        if (scenario == 1) { CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa + 4096) == 1); }
        if (scenario == 2) { CHECK(writeMsr(KSW_SVM_MSR_EFER, 0xffff) == 1); }
        if (scenario == 3) {
            kswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 0x202);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa) == 1);
        }
        if (scenario == 7) {
            kswSvmWrite64(operand, KSW_VMCB_MSRPM, 0x70000);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa) == 1);
            CHECK(!nested.permissions.ready && !nested.entries);
        }
        if (scenario == 8) {
            /* Hardware CPUID trapped by L0 cannot falsely count as an L1-requested exit. */
            kswSvmWrite32(operand, KSW_VMCB_MISC1, KSW_NSVM_MSR_PROT);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa) == 0);
            CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_INNER_MARKER) == 1);
            CHECK(!nested.reflections);
        }
        if (scenario >= 4 && scenario < 7) {
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.operandPa) == 0);
            if (scenario == 4) { CHECK(emit(KSW_SVM_EXIT_CPUID, 0) == 1); }
            if (scenario == 5) { CHECK(emit(KSW_SVM_EXIT_INVALID, 0) == 1); }
            if (scenario == 6) {
                kswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 6);
                kswSvmWrite64(&guest, KSW_VMCB_EXITINFO2, 1ULL << 45);
                CHECK(emit(KSW_SVM_EXIT_NPF, 0) == 1);
            }
        }
        CHECK(!NT_SUCCESS(cpu.Result) && !nested.runningL2 && traces == 1);
        CHECK(kswSvmRead64(&guest, KSW_VMCB_RSP) == cpu.launchRsp);
        CHECK(kswSvmRead64(&guest, KSW_VMCB_CR3) == 0x12345000);
        CHECK(cpu.gpr[3] == 0x1122334455667788ULL);
    }
    return 0;
}
int main(void)
{
    if (testRoundtrip() || testFailures()) { return 1; }
    printf("SVM_PRODUCTION_DISPATCH_CHECKS=%u RESULT=PASS (simulated exits, no hardware)\n", checks);
    return 0;
}
