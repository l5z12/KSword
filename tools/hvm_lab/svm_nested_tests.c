/* Exercise production nested-MMU code without executing SVM instructions. */
#include <stdio.h>
#include <string.h>
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_mmu.h"
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_shadow.h"
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_state.h"
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_msr.h"

static unsigned checks;
static int check(int condition, unsigned line, const char* expression)
{
    ++checks;
    if (!condition) { printf("FAIL line %u: %s\n", line, expression); }
    return condition;
}
#define CHECK(x) do { if (!check((x), __LINE__, #x)) { return 1; } } while (0)
#define PAT 0x0007010600070106ULL
typedef struct Memory {
    KswSvmU64 page[64][512];
    KswSvmU64 failRead, mutateCas;
    unsigned reads, writes, mutation;
} MEMORY;
static MEMORY memory;
static int readWord(void* context, KswSvmU64 address, KswSvmU64* value)
{
    MEMORY* m = (MEMORY*)context;
    if ((address & 7) || address >= sizeof(m->page) || address == m->failRead) { return 0; }
    ++m->reads;
    *value = m->page[address >> 12][(address & 4095) >> 3];
    return 1;
}
static int compareOr(void* context, KswSvmU64 address, KswSvmU64 expected, KswSvmU64 bits)
{
    MEMORY* m = (MEMORY*)context;
    KswSvmU64* slot;
    if ((address & 7) || address >= sizeof(m->page)) { return 0; }
    slot = &m->page[address >> 12][(address & 4095) >> 3];
    if (address == m->mutateCas && !m->mutation++) { *slot ^= 0x1000ULL; }
    if (*slot != expected) { return 0; }
    *slot |= bits;
    ++m->writes;
    return 1;
}
static void resetMemory(void)
{
    memset(&memory, 0, sizeof(memory));
    memory.failRead = memory.mutateCas = ~0ULL;
    memory.page[1][0] = 0x2007;
    memory.page[2][0] = 0x3007;
    memory.page[3][0] = 0x4007;
    memory.page[4][2] = 0x200007;
}
static unsigned walk(KswSvmU64 gpa, unsigned access, KswNnptWalk* result)
{
    return kswSvmNestedNptWalk(0x1000, gpa, 45, 1, 1, access, readWord, &memory, result);
}
static int testWalk(void)
{
    KswNnptWalk w;
    unsigned level, pat;
    resetMemory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    CHECK(w.address == 0x200123 && w.inputAddress == 0x2123 && w.root == 0x1000);
    CHECK(w.count == 4 && w.leafShift == 12 && w.permissions == 7 && w.fault == 0);
    CHECK(w.entryAddress[3] == 0x4010 && memory.writes == 0);
    CHECK(walk(0x3123, 0, &w) == KSW_NNPT_FAULT && w.fault == 4 && !w.complete);
    CHECK(kswSvmNestedNptCommitAd(&w, 0, readWord, compareOr, &memory) == KSW_NNPT_UNSUPPORTED);
    for (level = 1; level <= 4; ++level) {
        unsigned slot = level == 4 ? 2 : 0;
        resetMemory();
        memory.page[level][slot] &= ~2ULL;
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_FAULT && w.fault == 7);
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK && !(w.permissions & 2));
        memory.page[level][slot] &= ~4ULL;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 5);
        resetMemory();
        memory.page[level][slot] |= KSW_NNPT_NX;
        CHECK(walk(0x2123, KSW_NNPT_EXECUTE, &w) == KSW_NNPT_FAULT && w.fault == 21);
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK && (w.permissions & KSW_NNPT_NX));
        CHECK(kswSvmNestedNptWalk(0x1000, 0x2123, 45, 1, 0, 0, readWord, &memory, &w) == KSW_NNPT_FAULT);
        CHECK(w.fault == 13);
        resetMemory();
        memory.page[level][slot] |= 1ULL << 45;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 13);
        memory.page[level][slot] &= ~1ULL;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 4);
    }
    resetMemory();
    memory.page[1][0] |= 128;
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 13);
    for (pat = 0; pat < 8; ++pat) {
        resetMemory();
        memory.page[4][2] = 0x200000 | kswNptLeafFlags(1, pat);
        CHECK(walk(0x2fff, 0, &w) == KSW_NNPT_OK && w.address == 0x200fff && w.patIndex == pat);
        memory.page[3][0] = 0x600000 | kswNptLeafFlags(2, pat);
        CHECK(walk(0x1fffff, 0, &w) == KSW_NNPT_OK && w.address == 0x7fffff && w.patIndex == pat);
        CHECK(w.leafShift == 21 && w.count == 3);
        memory.page[3][0] |= 1ULL << 13;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 13);
        memory.page[2][0] = 0x40000000 | kswNptLeafFlags(3, pat);
        CHECK(walk(0x3fffffff, 0, &w) == KSW_NNPT_OK && w.address == 0x7fffffff && w.patIndex == pat);
        CHECK(w.leafShift == 30 && w.count == 2);
        CHECK(kswSvmNestedNptWalk(0x1000, 0x2123, 45, 0, 1, 0, readWord, &memory, &w) == KSW_NNPT_FAULT);
        memory.page[2][0] |= 1ULL << 29;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.fault == 13);
    }
    resetMemory();
    memory.failRead = 0x3000;
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_UNREADABLE && w.count == 2 && !w.complete);
    CHECK(walk(1ULL << 45, 0, &w) == KSW_NNPT_UNSUPPORTED && !w.complete);
    CHECK(walk(0x2123, 8, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(kswSvmNestedNptWalk(0x1008, 0, 45, 1, 1, 0, readWord, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(kswSvmNestedNptWalk(0x1000, 0, 49, 1, 1, 0, readWord, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(kswSvmNestedNptWalk(0x1000, 0, 45, 1, 1, 0, NULL, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    return 0;
}
static int testAd(void)
{
    KswNnptWalk w;
    unsigned level;
    resetMemory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    CHECK(kswSvmNestedNptCommitAd(&w, 1, readWord, compareOr, &memory) == KSW_NNPT_UNSUPPORTED);
    CHECK(memory.writes == 0);
    CHECK(kswSvmNestedNptCommitAd(&w, 0, readWord, compareOr, &memory) == KSW_NNPT_OK);
    CHECK((memory.page[4][2] & 0x60) == 0x20 && w.complete);
    CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
    CHECK(kswSvmNestedNptCommitAd(&w, 1, readWord, compareOr, &memory) == KSW_NNPT_OK);
    CHECK((memory.page[4][2] & 0x60) == 0x60);
    CHECK((memory.page[1][0] & 0x60) == 0x20);
    for (level = 0; level < 4; ++level) {
        KswSvmU64 old;
        resetMemory();
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
        old = w.entryValue[level];
        memory.page[level + 1][level == 3 ? 2 : 0] ^= 0x1000;
        CHECK(kswSvmNestedNptCommitAd(&w, 1, readWord, compareOr, &memory) == KSW_NNPT_RETRY);
        CHECK(memory.writes == 0 && !w.complete);
        CHECK(memory.page[level + 1][level == 3 ? 2 : 0] == (old ^ 0x1000));
        resetMemory();
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
        old = w.entryValue[level];
        memory.mutateCas = w.entryAddress[level];
        CHECK(kswSvmNestedNptCommitAd(&w, 1, readWord, compareOr, &memory) == KSW_NNPT_RETRY);
        CHECK(memory.writes == level && !w.complete);
        CHECK(memory.page[level + 1][level == 3 ? 2 : 0] == (old ^ 0x1000));
    }
    resetMemory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    memory.failRead = 0x4010;
    CHECK(kswSvmNestedNptCommitAd(&w, 0, readWord, compareOr, &memory) == KSW_NNPT_UNREADABLE);
    CHECK(memory.writes == 0 && !w.complete);
    return 0;
}
static void setupMmu(KswNmmuConfig* config, KswNmmuIo* io)
{
    unsigned i;
    resetMemory();
    for (i = 0; i < 64; ++i) { memory.page[4][i] = (KswSvmU64)i * 4096 | 7; }
    /* NPT12's tables deliberately have different guest and host physical addresses. */
    for (i = 0; i < 4; ++i) { memory.page[4][8 + i] = (KswSvmU64)(16 + i) * 4096 | 7; }
    memory.page[16][0] = 0x9007;
    memory.page[17][0] = 0xa007;
    memory.page[18][0] = 0xb007;
    memory.page[19][2] = 0x18007;
    memory.page[4][24] = 0x28007;
    memset(config, 0, sizeof(*config));
    config->innerRoot = 0x8000;
    config->outerRoot = 0x1000;
    config->innerPat = config->outerPat = config->hardwarePat = PAT;
    config->innerBits = config->outerBits = 45;
    config->innerPage1Gb = config->outerPage1Gb = 1;
    config->innerNx = config->outerNx = 1;
    config->epoch = 42;
    io->read = readWord;
    io->compareOr = compareOr;
    io->context = &memory;
}
static int testMmu(void)
{
    KswNmmuConfig config;
    KswNmmuIo io;
    KswNmmuResult r;
    KswSvmU64 leaf;
    unsigned pat, access;
    for (access = 0; access <= 2; access += 2) {
        setupMmu(&config, &io);
        CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, access, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
        CHECK(r.gpa == 0x2123 && r.epoch == 42 && r.faultOwner == 0);
        CHECK(r.inner.address == 0x18123 && r.outer.address == 0x28123);
        CHECK((r.leaf & KSW_NNPT_FRAME) == 0x28000 && (r.leaf & 2) == access);
        CHECK((memory.page[19][2] & 0x60) == (access ? 0x60ULL : 0x20ULL));
        CHECK((memory.page[4][24] & 0x60) == (access ? 0x60ULL : 0x20ULL));
        CHECK((memory.page[4][8] & 0x60) == 0x60 && r.reads < 256);
        CHECK(kswSvmNestedNptCompose4k(&r.inner, &r.outer, PAT, PAT, PAT, &leaf) == KSW_NNPT_OK);
        r.outer.inputAddress += 4096;
        CHECK(kswSvmNestedNptCompose4k(&r.inner, &r.outer, PAT, PAT, PAT, &leaf) == KSW_NNPT_UNSUPPORTED && leaf == 0);
    }
    setupMmu(&config, &io);
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, KSW_NNPT_EXECUTE, KSW_NMMU_TABLE, &r) == KSW_NNPT_OK);
    CHECK((r.leaf & 0x62) == 0x62 && r.inner.access == KSW_NNPT_WRITE);
    for (pat = 0; pat < 8; ++pat) {
        unsigned type = (unsigned)((PAT >> (pat * 8)) & 255);
        setupMmu(&config, &io);
        memory.page[19][2] = 0x18000 | kswNptLeafFlags(1, pat);
        if (type == 0 || type == 6) {
            CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
            CHECK((r.leaf & 0x98) == (type == 0 ? 0x18ULL : 0ULL));
        } else {
            CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED);
            CHECK(!r.leaf && !(memory.page[19][2] & 0x60));
        }
    }
    setupMmu(&config, &io);
    memory.page[19][2] |= 0x18;
    config.hardwarePat = 0x0606060606060606ULL;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED && !r.leaf);
    setupMmu(&config, &io);
    memory.page[19][2] = 0;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.leaf && r.faultOwner == KSW_NMMU_INNER && r.faultAddress == 0x2123 && r.faultInfo == (KSW_NMMU_FINAL | 4));
    setupMmu(&config, &io);
    memory.page[4][8] &= ~2ULL;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.leaf && r.faultOwner == KSW_NMMU_OUTER_TABLE && r.faultAddress == 0x8000 && r.faultInfo == (KSW_NMMU_TABLE | 7));
    setupMmu(&config, &io);
    memory.page[4][24] = 0;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.leaf && r.faultOwner == KSW_NMMU_OUTER_DATA && r.faultAddress == 0x18123 && r.faultInfo == (KSW_NMMU_FINAL | 4));
    setupMmu(&config, &io);
    memory.failRead = 0x10000;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNREADABLE);
    CHECK(!r.leaf && r.faultOwner == KSW_NMMU_PHYSICAL && r.faultAddress == 0x10000);
    setupMmu(&config, &io);
    memory.mutateCas = 0x13010;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, KSW_NNPT_WRITE, KSW_NMMU_FINAL, &r) == KSW_NNPT_RETRY);
    CHECK(!r.leaf && (memory.page[19][2] & KSW_NNPT_FRAME) == 0x19000 && !(memory.page[19][2] & 0x40));
    setupMmu(&config, &io);
    config.epoch = 0;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED && !r.leaf && !memory.reads);
    return 0;
}
__declspec(align(4096)) static KswSvmU64 shadowWords[8][512];
static int testShadow(void)
{
    KswNshadowPage pages[8];
    KswNshadow shadow = {0}, bad = {0};
    KswNmmuConfig config;
    KswNmmuIo io;
    KswNmmuResult r;
    unsigned i;
    for (i = 0; i < 8; ++i) {
        pages[i].words = shadowWords[i];
        pages[i].physical = 0x100000 + 4096ULL * i;
    }
    memset(shadowWords, 0xa5, sizeof(shadowWords));
    CHECK(kswSvmNestedShadowInitialize(&shadow, pages, 3, 45) == KSW_NSHADOW_OK);
    CHECK(shadow.used == 1 && shadow.epoch == 1 && shadow.flushPending == 1);
    CHECK(shadowWords[0][0] == 0 && shadowWords[1][0] == 0xa5a5a5a5a5a5a5a5ULL);
    setupMmu(&config, &io);
    config.epoch = shadow.epoch;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 2, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_FULL);
    CHECK(shadow.used == 1 && shadowWords[0][0] == 0 && shadowWords[1][0] == 0xa5a5a5a5a5a5a5a5ULL);
    memset(&shadow, 0, sizeof(shadow));
    CHECK(kswSvmNestedShadowInitialize(&shadow, pages, 8, 45) == KSW_NSHADOW_OK);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK);
    CHECK(shadow.used == 4 && shadowWords[0][0] == 0x101007 && shadowWords[1][0] == 0x102007);
    CHECK(shadowWords[2][0] == 0x103007 && shadowWords[3][2] == r.leaf);
    CHECK(shadowWords[3][1] == 0 && shadowWords[3][3] == 0);
    shadow.flushPending = 0; /* Simulate the owning entry loop having consumed the flush request. */
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.used == 4 && shadow.flushPending);
    /* Hardware may set Accessed on any intermediate table. */
    shadowWords[1][0] |= 0x20;
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.used == 4);
    shadowWords[1][0] = 0x101007; /* A forged cycle must not be followed. */
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    CHECK(kswSvmNestedShadowReset(&shadow) == KSW_NSHADOW_OK && shadow.epoch == 2 && shadow.used == 1);
    CHECK(shadowWords[0][0] == 0);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_STALE);
    config.epoch = shadow.epoch;
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadowWords[1][0] == 0x102007);
    CHECK(!(shadowWords[3][2] & 2)); /* Read resolutions cannot bypass dirty logging. */
    r.gpa += 4096;
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    memory.page[16][1] = memory.page[16][0];
    CHECK(kswSvmNestedMmuResolve(&config, &io, (1ULL << 39) | 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.used == 7);
    CHECK(shadowWords[0][1] == 0x104007 && shadowWords[6][2] == r.leaf);
    memory.page[16][2] = memory.page[16][0];
    CHECK(kswSvmNestedMmuResolve(&config, &io, (2ULL << 39) | 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_FULL && shadow.used == 7 && shadowWords[0][2] == 0);
    CHECK(kswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    r.leaf |= 1ULL << 45;
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    r.leaf &= ~(1ULL << 45);
    r.leaf |= 2; /* A writable leaf cannot skip source dirty accounting. */
    CHECK(kswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    shadow.epoch = ~0ULL;
    CHECK(kswSvmNestedShadowReset(&shadow) == KSW_NSHADOW_INVALID && shadow.used == 7);
    pages[1].physical = pages[0].physical;
    CHECK(kswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.pages);
    pages[1].physical = 0x101008;
    CHECK(kswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.pages);
    pages[1].physical = 0x101000;
    pages[1].words = pages[0].words;
    CHECK(kswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.pages);
    pages[1].words = shadowWords[1] + 1;
    CHECK(kswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.pages);
    return 0;
}
static int testState(void)
{
    KswSvmVmcb source, destination;
    unsigned i;
    unsigned char* bytes = (unsigned char*)&destination;
    memset(&source, 0x33, sizeof(source));
    memset(&destination, 0xaa, sizeof(destination));
    kswSvmNestedCopyVmload(&destination, &source);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_FS) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_TR) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_SYSENTER_EIP) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_CR2) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_RAX) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_GDTR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    /* VMLOAD must not copy the VMRUN-managed CET core state. */
    CHECK(kswSvmRead64(&destination, KSW_VMCB_S_CET) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_ISST) == 0xaaaaaaaaaaaaaaaaULL);
    memset(&destination, 0xaa, sizeof(destination));
    kswSvmNestedCopyVmrun(&destination, &source, 0);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_S_CET) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_SSP) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_ISST) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_CR4) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_RIP) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_RAX) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_CR2) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_GS) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_PAT) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_LDTR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_STAR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(bytes[KSW_VMCB_CPL] == 0x33 && bytes[KSW_VMCB_CPL + 1] == 0xaa);
    kswSvmNestedCopyVmrun(&destination, &source, 1);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_PAT) == 0x3333333333333333ULL);
    kswSvmWrite64(&source, KSW_VMCB_INTCTL, 0xdeadbeef00000305ULL);
    kswSvmWrite64(&source, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_NPF);
    kswSvmWrite64(&source, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 7);
    kswSvmWrite64(&source, KSW_VMCB_EXITINFO2, 0x12345000);
    kswSvmWrite64(&source, KSW_VMCB_NCR3, 0x2468000);
    kswSvmWrite64(&source, 0x68, 1);
    memset(&destination, 0xaa, sizeof(destination));
    kswSvmNestedReflectExit(&destination, &source, 1);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_S_CET) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_SSP) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_ISST) == 0x3333333333333333ULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_NPF);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_EXITINFO1) == (KSW_NMMU_FINAL | 7));
    CHECK(kswSvmRead64(&destination, KSW_VMCB_EXITINFO2) == 0x12345000);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_MSRPM) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_GS) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(kswSvmRead64(&destination, KSW_VMCB_INTCTL) == ((0xaaaaaaaaaaaaaaaaULL & ~0x10fULL) | 0x105ULL));
    CHECK(kswSvmRead64(&destination, 0x68) == 0xaaaaaaaaaaaaaaabULL);
    memset(&destination, 0, sizeof(destination));
    bytes[0] = 8; /* CR3 read. */
    bytes[2] = 16; /* CR4 write. */
    bytes[4] = 64; /* DR6 read. */
    bytes[6] = 128; /* DR7 write. */
    bytes[9] = 32; /* #GP vector 13. */
    bytes[14] = 4; /* CPUID at misc1 bit 18. */
    bytes[16] = 1; /* VMRUN at misc2 bit 0. */
    for (i = 0; i < 160; ++i) {
        unsigned expected = i == 3 || i == 0x14 || i == 0x26 || i == 0x37 || i == 0x4d || i == 0x72 || i == 0x80;
        CHECK(kswSvmNestedInterceptRequested(&destination, i) == expected);
    }
    CHECK(kswSvmNestedInterceptRequested(&destination, KSW_SVM_EXIT_NPF) == KSW_NSVM_INTERCEPT_UNKNOWN);
    CHECK(kswSvmNestedInterceptRequested(&destination, KSW_SVM_EXIT_INVALID) == KSW_NSVM_INTERCEPT_UNKNOWN);
    return 0;
}
int main(void)
{
    KswNsvmMsrs msrs = {0xd01, 0, 8, 0};
    KswSvmU64 value;
    if (testWalk() || testAd() || testMmu() || testShadow() || testState()) { return 1; }
    msrs.addressMask = kswNptAddressMask(45);
    value = 0x1d01;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_OK);
    value = 0;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 0, &value) == KSW_NSVM_MSR_OK && value == 0x1d01);
    value = 0x1d00;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_GP && msrs.efer == 0x1d01);
    value = 0x1000;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_OK && msrs.hsave == 0x1000);
    value = 0x1001;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_GP && msrs.hsave == 0x1000);
    value = 1ULL << 45;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_GP);
    value = 0;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 0, &value) == KSW_NSVM_MSR_OK && value == 0x1000);
    value = 0;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_OK && !msrs.hsave);
    value = 0x10;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 1, &value) == KSW_NSVM_MSR_GP && msrs.vmCr == 8);
    value = 0;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 0, &value) == KSW_NSVM_MSR_OK && value == 8);
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 1, &value) == KSW_NSVM_MSR_OK);
    value = 0xd01;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_OK);
    msrs.vmCr |= 0x10;
    value = 0x1d01;
    CHECK(kswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_GP && msrs.efer == 0xd01);
    CHECK(kswSvmNestedMsrAccess(&msrs, 0x1234, 0, &value) == KSW_NSVM_MSR_OTHER);
    printf("SVM_NESTED_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
