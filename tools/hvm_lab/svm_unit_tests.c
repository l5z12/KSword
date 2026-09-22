#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "../../drivers/ark/src/features/hvm/hvm_svm_arch.h"

static unsigned checks;
static int check(int condition, unsigned line, const char* expression)
{
    ++checks;
    if (!condition) { printf("FAIL line %u: %s\n", line, expression); }
    return condition;
}
#define CHECK(x) do { if (!check((x), (unsigned)__LINE__, #x)) { return 1; } } while (0)
int main(void)
{
    KswSvmVmcb v;
    unsigned bank, msr, pat, level, bits, seen, active, start;
    const unsigned kBases[] = {0, 0xc0000000U, 0xc0010000U};
    CHECK(sizeof(v) == 4096);
    CHECK(sizeof(KswSvmSegment) == 16);
    memset(&v, 0xa5, sizeof(v));
    kswSvmWrite64(&v, KSW_VMCB_EXITCODE, ~0ULL);
    CHECK(kswSvmRead64(&v, KSW_VMCB_EXITCODE) == ~0ULL);
    CHECK(kswSvmRead64(&v, KSW_VMCB_EXITINFO1) == 0xa5a5a5a5a5a5a5a5ULL);
    kswSvmWrite32(&v, KSW_VMCB_ASID, 1);
    CHECK(((unsigned char*)&v)[KSW_VMCB_TLB] == 0xa5);
    CHECK(KSW_VMCB_RAX == 0x5f8 && KSW_VMCB_RSP == 0x5d8 && KSW_VMCB_RIP == 0x578);
    /* CET core fields occupy the gap between RSP and RAX in the ordinary VMCB. */
    CHECK(KSW_VMCB_S_CET == 0x5e0 && KSW_VMCB_SSP == 0x5e8 && KSW_VMCB_ISST == 0x5f0);
    /* Reproduce the physical host contract, with confirmed-disabled supervisor controls. */
    CHECK(kswSvmUserCetValid(0xb50ef8ULL, 0xe7, 0x800, 15, 1, 0));
    /* Missing XSAVES, missing CET, kernel CET and unsupported XSS must all refuse. */
    CHECK(!kswSvmUserCetValid(0xb50ef8ULL, 0xe7, 0x800, 7, 1, 0));
    CHECK(!kswSvmUserCetValid(0xb50ef8ULL, 0xe7, 0x800, 15, 0, 0));
    CHECK(!kswSvmUserCetValid(0xb50ef8ULL, 0xe7, 0x800, 15, 1, 1));
    CHECK(!kswSvmUserCetValid(0xb50ef8ULL, 0xe7, 0x1800, 15, 1, 0));
    CHECK(!kswSvmUserCetValid(0xb50ef8ULL, 0x8e7, 0x800, 15, 1, 0));
    /* A CPU without CET retains the preexisting standard-format path. */
    CHECK(kswSvmUserCetValid(0x350ef8, 7, 0, 1, 0, 0));
    /* Disabled CR4.CET is not proof that supervisor controls are zero. */
    CHECK(!kswSvmUserCetValid(0x350ef8, 7, 0, 15, 1, 1));
    for (bits = 0; bits < 64; ++bits) {
        /* enumerate every XSS and supervisor CET bit, including unknown future states. */
        CHECK(kswSvmUserCetValid(0xb50ef8, 0xe7, 1ULL << bits, 15, 1, 0) == (unsigned)(bits == 11));
        CHECK(!kswSvmUserCetValid(0xb50ef8, 0xe7, 0x800, 15, 1, 1ULL << bits));
    }
    CHECK(!kswSvmUserCetValid(0xb51ef8, 0xe7, 0x800, 15, 1, 0));
    CHECK(!kswSvmUserCetValid(0x1b50ef8, 0xe7, 0x800, 15, 1, 0));
    CHECK(!kswSvmUserCetValid(0x2b50ef8, 0xe7, 0x800, 15, 1, 0));
    /* Writes may repeat the existing XSS contract, never turn CET_U off or add CET_S. */
    CHECK(kswSvmStateMsrWriteAllowed(0xda0, 0x800, 0, 0x800));
    CHECK(!kswSvmStateMsrWriteAllowed(0xda0, 0, 0, 0x800));
    CHECK(!kswSvmStateMsrWriteAllowed(0xda0, 0x1800, 0, 0x800));
    CHECK(kswSvmStateMsrWriteAllowed(0xda0, 0, 0, 0));
    CHECK(kswSvmStateMsrWriteAllowed(0x6a2, 0, 0, 0x800));
    CHECK(!kswSvmStateMsrWriteAllowed(0x6a2, 1, 0, 0x800));
    CHECK(kswSvmStateMsrWriteAllowed(0x277, 0x70106, 0x70106, 0x800));
    CHECK(!kswSvmStateMsrWriteAllowed(0x277, 0, 0x70106, 0x800));
    CHECK(!kswSvmStateMsrWriteAllowed(0x123, 0, 0, 0));
    for (bank = 0; bank < 3; ++bank) {
        for (msr = 0; msr < 8192; ++msr) {
            unsigned bit = kswSvmMsrpmBit(kBases[bank] + msr, 0);
            CHECK(bit / 8 >= bank * 2048 && bit / 8 < (bank + 1) * 2048);
            CHECK(kswSvmMsrpmBit(kBases[bank] + msr, 1) == bit + 1);
            if (msr) { CHECK(bit == kswSvmMsrpmBit(kBases[bank] + msr - 1, 1) + 1); }
        }
        CHECK(kswSvmMsrpmBit(kBases[bank] + 8192, 0) == 0xffffffffU);
    }
    for (bits = 0; bits < 65; ++bits) {
        KswSvmU64 mask = kswNptAddressMask(bits);
        CHECK((mask != 0) == (bits >= 32 && bits <= 48));
        if (mask) { CHECK((mask & 4095) == 0 && ((mask | 4095) + 1) == (1ULL << bits)); }
    }
    for (level = 1; level <= 3; ++level) {
        for (pat = 0; pat < 8; ++pat) {
            KswSvmU64 f = kswNptLeafFlags(level, pat);
            unsigned decoded = (unsigned)((f >> 3) & 3) | (unsigned)(((f >> (level == 1 ? 7 : 12)) & 1) << 2);
            CHECK(decoded == pat && (f & 7) == 7);
            CHECK((f & (1ULL << 63)) == 0);
            if (level != 1) { CHECK((f & 128) != 0); }
        }
    }
    CHECK(!kswNptLeafFlags(0, 0) && !kswNptLeafFlags(4, 0) && !kswNptLeafFlags(1, 8));
    CHECK(!kswSvmNextRipValid(~0ULL, 0) && !kswSvmNextRipValid(7, 7));
    CHECK(kswSvmNextRipValid(7, 22) && !kswSvmNextRipValid(7, 23));
    for (seen = 0; seen < 4; ++seen) for (active = 0; active < 2; ++active) for (start = 0; start < 2; ++start) {
        CHECK(kswSvmParticipantValid(seen, active, start) == (unsigned)(seen == 1 && active == start));
    }
    /* A duplicate cannot compensate for a missing CPU even with equal totals. */
    CHECK(!kswSvmParticipantValid(2, 1, 1) && !kswSvmParticipantValid(0, 1, 1));
    CHECK(!kswSvmAsidValid(0,1) && !kswSvmAsidValid(1,1) && kswSvmAsidValid(2,1));
    CHECK(!kswSvmAsidValid(65536,0) && kswSvmAsidValid(65536,65535) && !kswSvmAsidValid(65536,65536));
    CHECK(kswSvmExceptionEvent(6)==0x80000306ULL && kswSvmExceptionEvent(13)==0x80000b0dULL);
    CHECK(!kswSvmExceptionEvent(14));
    {
        int r[4]={1,2,-1,4};
        kswSvmFilterCpuid(0x80000001U,r);
        CHECK(r[0]==1 && r[1]==2 && r[2]==-5 && r[3]==4);
        kswSvmFilterCpuid(0x40000000U,r);
        CHECK(r[0]==1 && r[1]==2 && r[2]==-5 && r[3]==4);
        kswSvmFilterCpuid(0x8000000aU,r);
        CHECK(!(r[0]|r[1]|r[2]|r[3]));
    }
    printf("SVM_LOGIC_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
