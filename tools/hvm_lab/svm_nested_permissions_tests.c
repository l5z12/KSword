/* Execute the production map engine, without MSRs, I/O instructions or SVM. */
#include <stdio.h>
#include <string.h>
#include "../../drivers/ark/src/features/hvm/hvm_svm_nested_permissions.h"

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned char aMsr[8192], bMsr[8192], outMsr[8192];
static unsigned char aIo[12288], bIo[12288], outIo[12288];
static KswNsvmPermissionView a, b;
static KswNsvmPermissionImage image;
static unsigned char source[5][4096];
static unsigned reads, failPage;

static void clearMaps(void)
{
    memset(aMsr, 0, sizeof(aMsr)); memset(bMsr, 0, sizeof(bMsr));
    memset(aIo, 0, sizeof(aIo)); memset(bIo, 0, sizeof(bIo));
    a.flags = b.flags = KSW_NSVM_PERMISSION_FLAGS;
    a.msr = aMsr; a.io = aIo; b.msr = bMsr; b.io = bIo;
}
static void setBit(unsigned char* map, unsigned bit)
{
    map[bit / 8] |= (unsigned char)(1U << (bit % 8));
}
static int testMsrOwners(void)
{
    /* Expected offsets are from the APM table, not the function under test. */
    static const unsigned kMsrs[] = {0, 0x1fff, 0xc0000000, 0xc0001fff, 0xc0010000, 0xc0011fff};
    static const unsigned kBits[] = {0, 16382, 16384, 32766, 32768, 49150};
    static const unsigned kOutside[] = {0x2000, 0xbfffffff, 0xc0002000, 0xc000ffff, 0xc0012000, 0xffffffff};
    unsigned i, write, owner;
    for (i = 0; i < sizeof(kMsrs) / sizeof(kMsrs[0]); ++i) {
        for (write = 0; write < 2; ++write) {
            for (owner = 0; owner < 4; ++owner) {
                clearMaps();
                if (owner & 1) { setBit(aMsr, kBits[i] + write); }
                if (owner & 2) { setBit(bMsr, kBits[i] + write); }
                CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, write, kMsrs[i]) == owner);
                CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, write ^ 1, kMsrs[i]) == 0);
            }
        }
    }
    for (i = 0; i < sizeof(kOutside) / sizeof(kOutside[0]); ++i) {
        for (owner = 0; owner < 4; ++owner) {
            clearMaps();
            a.flags = owner & 1 ? KSW_NSVM_MSR_PROT : 0;
            b.flags = owner & 2 ? KSW_NSVM_MSR_PROT : 0;
            CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, kOutside[i]) == owner);
            CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 1, kOutside[i]) == owner);
        }
    }
    clearMaps();
    a.msr = NULL;
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, 0) == KSW_NSVM_OWNER_INVALID);
    a.flags = 0;
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, 0) == 0);
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 2, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7c, 1ULL << 32, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x72, 0, 0) == KSW_NSVM_OWNER_INVALID);
    return 0;
}
static int testIoOwners(void)
{
    unsigned port, width, owner;
    KswSvmU64 info;
    clearMaps();
    for (port = 0; port < 65536; ++port) {
        for (width = 1; width <= 4; width *= 2) {
            /* Last accessed byte forces the entire operation to exit, including the tail page. */
            setBit(bIo, port + width - 1);
            info = ((KswSvmU64)port << 16) | (width << 4);
            CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, info, 0) == 2);
            CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, info | 0xd, 0) == 2); /* IN+STR+REP */
            bIo[(port + width - 1) / 8] = 0;
            CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, info, 0) == 0);
        }
    }
    for (owner = 0; owner < 4; ++owner) {
        clearMaps();
        if (owner & 1) { setBit(aIo, 0x3f8); }
        if (owner & 2) { setBit(bIo, 0x3f9); }
        CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x3f80020, 0) == owner);
    }
    clearMaps(); setBit(bIo, 0); /* A wrap to port zero would falsely request this exit. */
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, 0xffff0040, 0) == 0);
    for (width = 0; width < 8; ++width) {
        if (width == 1 || width == 2 || width == 4) { continue; }
        CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, width << 4, 0) == KSW_NSVM_OWNER_INVALID);
    }
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x12, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x2010, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(kswSvmNestedPermissionOwners(&a, &b, 0x7b, (1ULL << 32) | 0x10, 0) == KSW_NSVM_OWNER_INVALID);
    return 0;
}
static int testMerge(void)
{
    unsigned i, enabled;
    clearMaps();
    for (i = 0; i < sizeof(aMsr); ++i) { aMsr[i] = (unsigned char)(i * 17); bMsr[i] = (unsigned char)(i * 31 + 1); }
    for (i = 0; i < sizeof(aIo); ++i) { aIo[i] = (unsigned char)(i * 13); bIo[i] = (unsigned char)(i * 7 + 3); }
    for (enabled = 0; enabled < 16; ++enabled) {
        a.flags = ((enabled & 1) ? KSW_NSVM_MSR_PROT : 0) | ((enabled & 2) ? KSW_NSVM_IOIO_PROT : 0);
        b.flags = ((enabled & 4) ? KSW_NSVM_MSR_PROT : 0) | ((enabled & 8) ? KSW_NSVM_IOIO_PROT : 0);
        CHECK(kswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
        for (i = 0; i < sizeof(aMsr); ++i) {
            CHECK(outMsr[i] == (((enabled & 1) ? aMsr[i] : 0) | ((enabled & 4) ? bMsr[i] : 0)));
        }
        for (i = 0; i < sizeof(aIo); ++i) {
            CHECK(outIo[i] == (((enabled & 2) ? aIo[i] : 0) | ((enabled & 8) ? bIo[i] : 0)));
        }
    }
    memset(outMsr, 0xaa, sizeof(outMsr)); memset(outIo, 0x55, sizeof(outIo));
    a.msr = NULL;
    CHECK(!kswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
    CHECK(outMsr[0] == 0xaa && outMsr[8191] == 0xaa && outIo[0] == 0x55 && outIo[12287] == 0x55);
    a.flags = b.flags = 0; a.io = b.io = NULL; b.msr = NULL;
    CHECK(kswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
    CHECK(outMsr[0] == 0 && outIo[12287] == 0);
    return 0;
}
static int readPage(void* context, KswSvmU64 address, unsigned char* page)
{
    unsigned index;
    (void)context;
    ++reads;
    /* Guest addresses deliberately differ from the source's actual user-mode address. */
    if (address < 0x100000 || address >= 0x105000 || (address & 4095)) { return 0; }
    index = (unsigned)((address - 0x100000) >> 12);
    if (index == failPage) { return 0; }
    memcpy(page, source[index], 4096);
    return 1;
}
static int testCapture(void)
{
    unsigned bits, i;
    KswSvmU64 base, limit;
    KswNsvmPermissionView view;
    for (bits = 32; bits <= 48; ++bits) {
        limit = 1ULL << bits;
        CHECK(kswSvmNestedMapAddress(limit - 8192 + 123, 8192, bits, &base) && base == limit - 8192);
        CHECK(!kswSvmNestedMapAddress(limit - 4096, 8192, bits, &base) && base == 0);
        CHECK(kswSvmNestedMapAddress(limit - 12288, 12288, bits, &base));
        CHECK(!kswSvmNestedMapAddress(limit - 8192, 12288, bits, &base));
        CHECK(!kswSvmNestedMapAddress(limit, 8192, bits, &base));
    }
    CHECK(!kswSvmNestedMapAddress(~0ULL, 8192, 48, &base));
    CHECK(!kswSvmNestedMapAddress(0, 4096, 48, &base));
    CHECK(!kswSvmNestedMapAddress(0, 8192, 64, &base));
    CHECK(kswSvmNestedMapAddress(0, 8192, 48, &base) && base == 0);
    for (i = 0; i < 5; ++i) { memset(source[i], (int)i + 1, 4096); }
    failPage = ~0U; reads = 0;
    CHECK(kswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100abc, 0x102def, 48, readPage, NULL));
    CHECK(reads == 5 && image.ready == 1);
    CHECK(kswSvmNestedPermissionView(&image, &view));
    CHECK(!memcmp(view.msr, source, 8192) && !memcmp(view.io, source[2], 12288));
    for (failPage = 0; failPage < 5; ++failPage) {
        reads = 0;
        CHECK(!kswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100000, 0x102000, 48, readPage, NULL));
        CHECK(!image.ready && reads == failPage + 1);
        CHECK(!kswSvmNestedPermissionView(&image, &view) && !view.msr && !view.io);
    }
    reads = 0;
    CHECK(!kswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100000, ~0ULL, 48, readPage, NULL));
    CHECK(!reads && !image.ready);
    CHECK(kswSvmNestedCapturePermissions(&image, 0, ~0ULL, ~0ULL, 48, NULL, NULL));
    CHECK(kswSvmNestedPermissionView(&image, &view) && !view.flags);
    CHECK(!image.msr[8191] && !image.io[12287]);
    failPage = ~0U; reads = 0;
    CHECK(kswSvmNestedCapturePermissions(&image, KSW_NSVM_IOIO_PROT, ~0ULL, 0x102000, 48, readPage, NULL));
    CHECK(reads == 3);
    reads = 0;
    CHECK(kswSvmNestedCapturePermissions(&image, KSW_NSVM_MSR_PROT, 0x100000, ~0ULL, 48, readPage, NULL));
    CHECK(reads == 2);
    return 0;
}
int main(void)
{
    if (testMsrOwners() || testIoOwners() || testMerge() || testCapture()) { return 1; }
    printf("SVM_PERMISSION_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
