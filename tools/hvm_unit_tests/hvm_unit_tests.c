/*
 * hvm_unit_tests: Host-side unit tests for KswordArkHvmControls.h
 *
 * These logic blocks are only executed after the driver loads, which requires a signed driver and a machine
 * without HVCI enabled; failure results in a BSOD. Since they are purely arithmetic, extracting them into a shared
 * header allows correctness to be verified directly on the build machine without any virtualization environment.
 *
 * Tests use invariants rather than just manually calculated values: manual values only cover the specific points I
 * calculated, while invariants (same page same item, 8-byte difference between adjacent pages, result within
 * self-mapped region bounds) cover the step most prone to error during derivation—sign extension not being masked.
 *
 * Compile:
 *   cl /nologo /O2 /MT /W4 hvm_unit_tests.c /Fe:hvm_unit_tests.exe
 */

#include <stdio.h>

#include "../../shared/driver/KswordArkHvmControls.h"

static int gChecks = 0;
static int gFailures = 0;
static const char* gGroup = "";

static void
group(const char* name)
{
    gGroup = name;
    printf("\n[%s]\n", name);
}

static void
check(int condition, const char* what)
{
    gChecks += 1;
    if (condition) {
        printf("  ok    %s\n", what);
    } else {
        gFailures += 1;
        printf("  FAIL  %s\n", what);
    }
}

static void
checkEqU64(unsigned long long actual,
           unsigned long long expected,
           const char* what)
{
    gChecks += 1;
    if (actual == expected) {
        printf("  ok    %s\n", what);
    } else {
        gFailures += 1;
        printf("  FAIL  %s\n        expected 0x%016llX got 0x%016llX\n",
               what, expected, actual);
    }
}

/* ------------------------------------------------------------------ */

static void
testAdjustControls(void)
{
    unsigned long long capability = 0ULL;
    unsigned long result = 0UL;

    group("VMX 控制位夹取");

    /*
     * Capability MSR: lower 32 bits = must be 1, upper 32 bits = allowed to be 1.
     * Construct a capability mask where bit0 must be set and bit0..bit3 are allowed to be set.
     */
    capability = 0x0000000FULL << 32 | 0x00000001ULL;

    /* Even if no bits are requested, the mandatory bits must still be retained. */
    result = KswordArkHvmAdjustControls(0UL, capability);
    checkEqU64(result, 0x1UL, "不请求任何位时仍保留 allowed-0 必须位");

    /* Request an allowed bit. */
    result = KswordArkHvmAdjustControls(0x4UL, capability);
    checkEqU64(result, 0x5UL, "被允许的请求位保留，必须位一并保留");

    /* Requesting an unauthorized bit—the most common failure cause in nested virtualization. */
    result = KswordArkHvmAdjustControls(0x10UL, capability);
    checkEqU64(result, 0x1UL, "硬件不允许的请求位被剔除，不会带进 VMCS");

    /*
     * One of the nested typical capability sets: the outer layer does not provide secondary controls.
     * We request bit31 (activate secondary controls), which must be cleared;
     * otherwise, VM entry fails immediately and returns only an error code.
     */
    capability = 0x7FFFFFFFULL << 32 | 0x00000016ULL;
    result = KswordArkHvmAdjustControls(0x80000000UL, capability);
    check((result & 0x80000000UL) == 0UL,
          "外层不暴露 secondary controls 时该位被剔除");
    checkEqU64(result & 0x16UL, 0x16UL, "同时必须位仍然完整保留");

    /* Under a fully allowed capability mask, the request passes through as-is (plus mandatory bits). */
    capability = 0xFFFFFFFFULL << 32 | 0x00000000ULL;
    result = KswordArkHvmAdjustControls(0xDEADBEEFUL, capability);
    checkEqU64(result, 0xDEADBEEFUL, "全允许时请求原样通过");

    /* When all capabilities are disallowed, the result must be zero. */
    capability = 0x00000000ULL << 32 | 0x00000000ULL;
    result = KswordArkHvmAdjustControls(0xFFFFFFFFUL, capability);
    checkEqU64(result, 0UL, "全不允许时结果为零");
}

/* ------------------------------------------------------------------ */

static void
testMsrBitmap(void)
{
    unsigned long offset = 0UL;
    unsigned char mask = 0U;
    int covered = 0;

    group("MSR 位图寻址");

    /* bit0 of the read bitmap for the 0th MSR in the low segment: bit0 of the first page byte. */
    covered = KswordArkHvmMsrBitmapLocate(0UL, 0, &offset, &mask);
    check(covered != 0, "索引 0 在覆盖范围内");
    checkEqU64(offset, 0x000U, "低段读位图从页首开始");
    checkEqU64(mask, 0x01U, "索引 0 对应 bit0");

    /* The low segment write bitmap starts at 0x800. */
    covered = KswordArkHvmMsrBitmapLocate(0UL, 1, &offset, &mask);
    checkEqU64(offset, 0x800U, "低段写位图从 0x800 开始");

    /*
     * The high segment must be offset by subtracting 0xC0000000 first. Skipping this
     * step causes IA32_LSTAR (0xC0000082) to map to the 0x82nd MSR in the low segment—a
     * valid location that won't trigger an error but will intercept the wrong object.
     */
    covered = KswordArkHvmMsrBitmapLocate(0xC0000082UL, 0, &offset, &mask);
    check(covered != 0, "IA32_LSTAR 在覆盖范围内");
    checkEqU64(offset, 0x400U + (0x82U >> 3), "高段读位图先减基址再定位");
    checkEqU64(mask, (unsigned char)(1U << (0x82U & 7U)),
               "IA32_LSTAR 的位掩码按相对索引算");

    /* Read and write operations at the same index must fall into different regions. */
    {
        unsigned long readOffset = 0UL;
        unsigned long writeOffset = 0UL;
        unsigned char ignored = 0U;

        KswordArkHvmMsrBitmapLocate(0xC0000082UL, 0, &readOffset, &ignored);
        KswordArkHvmMsrBitmapLocate(0xC0000082UL, 1, &writeOffset, &ignored);
        check(readOffset != writeOffset, "同一 MSR 的读写位于不同区");
        checkEqU64(writeOffset - readOffset, 0x800U,
                   "读区与写区相距正好 0x800");
    }

    /* The last index of each segment must still fall within the page. */
    covered = KswordArkHvmMsrBitmapLocate(
        KSWORD_ARK_HVM_MSR_LOW_LIMIT, 1, &offset, &mask);
    check(covered != 0, "低段末尾索引仍在覆盖范围内");
    check(offset < KSWORD_ARK_HVM_MSR_BITMAP_BYTES,
          "低段末尾的写偏移不越出位图页");
    checkEqU64(offset, 0x800U + 0x3FFU, "低段末尾正好落在写区最后一字节");

    covered = KswordArkHvmMsrBitmapLocate(
        KSWORD_ARK_HVM_MSR_HIGH_LIMIT, 1, &offset, &mask);
    check(covered != 0, "高段末尾索引仍在覆盖范围内");
    checkEqU64(offset, 0xC00U + 0x3FFU, "高段末尾正好落在页的最后一字节");

    /* Indices outside the range must be rejected, rather than calculating a seemingly reasonable offset. */
    check(KswordArkHvmMsrBitmapLocate(0x2000UL, 0, &offset, &mask) == 0,
          "低段之上的索引被拒绝");
    check(KswordArkHvmMsrBitmapLocate(0xBFFFFFFFUL, 0, &offset, &mask) == 0,
          "高段之下的索引被拒绝");
    check(KswordArkHvmMsrBitmapLocate(0xC0002000UL, 0, &offset, &mask) == 0,
          "高段之上的索引被拒绝");

    /* Iterate through all indices in both segments to confirm no out-of-bounds access. */
    {
        unsigned long index = 0UL;
        int allInside = 1;

        for (index = 0UL; index <= KSWORD_ARK_HVM_MSR_LOW_LIMIT; ++index) {
            if (!KswordArkHvmMsrBitmapLocate(index, 1, &offset, &mask) ||
                offset >= KSWORD_ARK_HVM_MSR_BITMAP_BYTES) {
                allInside = 0;
                break;
            }
        }
        for (index = KSWORD_ARK_HVM_MSR_HIGH_BASE;
             index <= KSWORD_ARK_HVM_MSR_HIGH_LIMIT;
             ++index) {
            if (!KswordArkHvmMsrBitmapLocate(index, 1, &offset, &mask) ||
                offset >= KSWORD_ARK_HVM_MSR_BITMAP_BYTES) {
                allInside = 0;
                break;
            }
        }
        check(allInside, "两段全部 16384 个索引的偏移都在页内");
    }
}

/* ------------------------------------------------------------------ */

static void
testSelfMap(void)
{
    /* Historically fixed self-mapping slot, used as a set of known values. */
    const unsigned long long kBase =
        KswordArkHvmSelfMapBaseFromIndex(0x1EDUL);
    const unsigned long long kKernelVa = 0xFFFFF80000000000ULL;
    const unsigned long long kUserVa = 0x00007FF000000000ULL;

    group("页表自映射寻址");

    checkEqU64(kBase, 0xFFFFF68000000000ULL,
               "槽位 0x1ED 推出的自映射基址与历史固定值一致");

    /*
     * This is the only part of the formula prone to error: the upper 16 bits of the kernel address are all 1s; failing to mask them
     * would push the result out of the self-mapping region. After masking, the result must still fall within [base, base+512GiB).
     */
    {
        const unsigned long long kEntry =
            KswordArkHvmSelfMapEntryAddress(kBase, kKernelVa);

        /*
         * Step-by-step verification: va & 0x0000FFFFFFFFFFFF = 0xF8 << 40, >>
         * 12 yields 0xF8 << 28, << 3 yields 0xF8 << 31 = 0x7C00000000, adding
         * the base address 0xFFFFF68000000000 results in 0xFFFFF6FC00000000.
         */
        checkEqU64(kEntry, 0xFFFFF6FC00000000ULL,
                   "内核地址的叶项地址与逐步验算一致");
        /*
         * Interval checks must be written as entry - base < 2^39. Writing entry < base + 2^39
         * causes wraparound overflow at high slots: base + 2^39 for slot 511 is exactly 0.
         */
        check(kEntry - kBase < (1ULL << 39),
              "内核地址的叶项落在自映射区内");
    }
    {
        const unsigned long long kEntry =
            KswordArkHvmSelfMapEntryAddress(kBase, kUserVa);

        check(kEntry - kBase < (1ULL << 39),
              "用户地址的叶项落在自映射区内");
    }

    /* Any address within the same page must yield the same leaf entry. */
    {
        const unsigned long long kA =
            KswordArkHvmSelfMapEntryAddress(kBase, kKernelVa);
        const unsigned long long kB =
            KswordArkHvmSelfMapEntryAddress(kBase, kKernelVa + 0xFFFULL);

        checkEqU64(kB, kA, "同一页内的地址映射到同一个叶项");
    }

    /* The leaf entries of adjacent pages must differ by exactly one entry (8 bytes). */
    {
        const unsigned long long kA =
            KswordArkHvmSelfMapEntryAddress(kBase, kKernelVa);
        const unsigned long long kB =
            KswordArkHvmSelfMapEntryAddress(kBase, kKernelVa + 0x1000ULL);

        checkEqU64(kB - kA, 8ULL, "相邻页的叶项相差 8 字节");
    }

    /* Iterate through all 512 slots to confirm none exceed their self-mapping region. */
    {
        unsigned long slot = 0UL;
        int allInside = 1;

        for (slot = 0UL; slot < 512UL; ++slot) {
            const unsigned long long kSlotBase =
                KswordArkHvmSelfMapBaseFromIndex(slot);
            const unsigned long long kEntry =
                KswordArkHvmSelfMapEntryAddress(kSlotBase, kKernelVa);

            if (kEntry - kSlotBase >= (1ULL << 39)) {
                allInside = 0;
                break;
            }
        }
        check(allInside, "512 个候选槽位的叶项都落在各自的自映射区内");
    }
}

/* ------------------------------------------------------------------ */

static void
testEptpValidation(void)
{
    /* Typical machine: supports WB, 4-level walk, and A/D. */
    const unsigned long long kCaps =
        KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4 |
        KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB |
        KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY;
    const unsigned long kMaxPa = 39UL;
    /* WB + 4-level walk + a valid page frame. */
    const unsigned long long kGoodEptp = 0x0000000012345000ULL | 6ULL | (3ULL << 3);

    group("EPTP 校验");

    check(KswordArkHvmEptpIsValid(kGoodEptp, kCaps, kMaxPa),
          "典型合法 EPTP 被接受");

    /*
     * All-zero entries are always invalid: a page traversal level field of 0 implies 'level 1', which the architecture does not support.
     * This directly ensures that unused slots in the EPTP list cannot be left empty.
     */
    check(!KswordArkHvmEptpIsValid(0ULL, kCaps, kMaxPa),
          "全零 EPTP 被拒绝——list 的空槽不能留零");

    /* Memory type must be supported by hardware. */
    check(!KswordArkHvmEptpIsValid(
              (kGoodEptp & ~7ULL) | 5ULL, kCaps, kMaxPa),
          "未定义的内存类型编码被拒绝");
    check(!KswordArkHvmEptpIsValid(
              (kGoodEptp & ~7ULL) | 0ULL, kCaps, kMaxPa),
          "硬件未报告支持 UC 时 UC 被拒绝");

    /* Page traversal level must be exactly 3 (for 4-level paging). */
    check(!KswordArkHvmEptpIsValid(
              (kGoodEptp & ~(7ULL << 3)) | (2ULL << 3), kCaps, kMaxPa),
          "三级页遍历被拒绝");

    /* Must not be enabled if hardware does not support A/D. */
    check(!KswordArkHvmEptpIsValid(
              kGoodEptp | KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY,
              kCaps & ~KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY,
              kMaxPa),
          "硬件不支持时开启 accessed/dirty 被拒绝");
    check(KswordArkHvmEptpIsValid(
              kGoodEptp | KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY, kCaps, kMaxPa),
          "硬件支持时开启 accessed/dirty 被接受");

    /* Reserved bits must be zero. */
    check(!KswordArkHvmEptpIsValid(kGoodEptp | (1ULL << 8), kCaps, kMaxPa),
          "低位保留域非零被拒绝");

    /* High bits exceeding the physical address width must be zero. */
    check(!KswordArkHvmEptpIsValid(
              kGoodEptp | (1ULL << 40), kCaps, kMaxPa),
          "超出 MAXPHYADDR 的页帧位被拒绝");
    check(KswordArkHvmEptpIsValid(
              kGoodEptp | (1ULL << 38), kCaps, kMaxPa),
          "MAXPHYADDR 之内的高位页帧被接受");

    /* Reject unconditionally if 4-level walk capability is missing. */
    check(!KswordArkHvmEptpIsValid(
              kGoodEptp,
              kCaps & ~KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4,
              kMaxPa),
          "硬件不支持四级页遍历时被拒绝");
}

/* ------------------------------------------------------------------ */

/*
 * EPT hierarchy index decomposition.
 *
 * This arithmetic in the driver determines which 2MiB leaf entry to tighten. An error here will not cause a fault but will silently alter permissions
 * for unrelated memory, with symptoms appearing far from the source. Therefore, this test verifies both manual calculation points and invariants: all
 * addresses within the same leaf entry must yield the same index, and crossing to the next leaf entry must increment the index by exactly one.
 */
static void
testEptIndices(void)
{
    unsigned long long address = 0ULL;
    unsigned long index = 0UL;

    group("EPT 层次索引分解");

    /* Zero address falls in slot 0 at every level. */
    check(KswordArkHvmEptPml4Index(0ULL) == 0UL &&
          KswordArkHvmEptPdptIndex(0ULL) == 0UL &&
          KswordArkHvmEptPdIndex(0ULL) == 0UL,
          "物理地址 0 落在三级 0 号槽");

    /* The second 2MiB leaf entry advances only the PD index. */
    address = KSWORD_ARK_HVM_LARGE_PAGE_BYTES;
    check(KswordArkHvmEptPml4Index(address) == 0UL &&
          KswordArkHvmEptPdptIndex(address) == 0UL &&
          KswordArkHvmEptPdIndex(address) == 1UL,
          "跨一个 2MiB 只推进 PD 索引");

    /* Advance PDPT at 1 GiB boundary and zero out PD. */
    address = KSWORD_ARK_HVM_ONE_GIB;
    check(KswordArkHvmEptPml4Index(address) == 0UL &&
          KswordArkHvmEptPdptIndex(address) == 1UL &&
          KswordArkHvmEptPdIndex(address) == 0UL,
          "1 GiB 边界推进 PDPT 且 PD 归零");

    /* Advance the PML4 at the 512 GiB boundary and zero out the lower two levels. */
    address = KSWORD_ARK_HVM_ONE_512_GIB;
    check(KswordArkHvmEptPml4Index(address) == 1UL &&
          KswordArkHvmEptPdptIndex(address) == 0UL &&
          KswordArkHvmEptPdIndex(address) == 0UL,
          "512 GiB 边界推进 PML4 且下两级归零");

    /* The last slot at each level is exactly 511, not 512. */
    address = KSWORD_ARK_HVM_ONE_512_GIB - 1ULL;
    check(KswordArkHvmEptPdptIndex(address) == 511UL &&
          KswordArkHvmEptPdIndex(address) == 511UL,
          "512 GiB 前最后一字节落在 511/511 槽");

    /*
     * Invariant: For any offset within a 2MiB leaf entry, the level-3 index must be identical.
     * This covers the case where modulo was mistakenly written as integer division (or vice versa).
     */
    for (index = 0UL; index < 64UL; ++index) {
        const unsigned long long kBase = 0x1C0000000ULL;
        const unsigned long long kProbe =
            kBase + (index * (KSWORD_ARK_HVM_LARGE_PAGE_BYTES / 64ULL));

        if (KswordArkHvmEptPml4Index(kProbe) !=
                KswordArkHvmEptPml4Index(kBase) ||
            KswordArkHvmEptPdptIndex(kProbe) !=
                KswordArkHvmEptPdptIndex(kBase) ||
            KswordArkHvmEptPdIndex(kProbe) !=
                KswordArkHvmEptPdIndex(kBase)) {
            break;
        }
    }
    check(index == 64UL, "同一 2MiB 叶项内所有偏移索引相同");

    /* Invariant: After flooring to the leaf base address, the index remains unchanged and the base address is aligned. */
    address = 0x1C012345ULL;
    check(KswordArkHvmEptLeafBase(address) ==
              (address & ~(KSWORD_ARK_HVM_LARGE_PAGE_BYTES - 1ULL)) &&
          (KswordArkHvmEptLeafBase(address) %
              KSWORD_ARK_HVM_LARGE_PAGE_BYTES) == 0ULL &&
          KswordArkHvmEptPdIndex(KswordArkHvmEptLeafBase(address)) ==
              KswordArkHvmEptPdIndex(address),
          "取整到叶项基址后对齐且索引不变");

    /* Rounding an already-aligned address leaves it unchanged. */
    check(KswordArkHvmEptLeafBase(KSWORD_ARK_HVM_ONE_GIB) ==
              KSWORD_ARK_HVM_ONE_GIB,
          "已对齐地址取整后不变");
}

/*
 * Domain restrictions can only reduce privileges.
 *
 * This is the sole basis for VMFUNC security: VMFUNC performs no CPL checks, allowing any ring 3 thread to switch into a domain.
 * As long as a domain can never be more permissive than the default view, switching into it grants no new access rights.
 */
static void
testDomainRestriction(void)
{
    const unsigned long long kRwx =
        KSWORD_ARK_HVM_EPT_READ |
        KSWORD_ARK_HVM_EPT_WRITE |
        KSWORD_ARK_HVM_EPT_EXECUTE;
    unsigned long long leaf = 0ULL;
    unsigned long long once = 0ULL;
    unsigned long long twice = 0ULL;
    unsigned long bits = 0UL;

    group("域限制只减不增");

    /* After removing write permission, only read and execute remain. */
    leaf = KswordArkHvmEptApplyRestriction(
        kRwx, KSWORD_ARK_HVM_EPT_WRITE);
    checkEqU64(leaf,
               KSWORD_ARK_HVM_EPT_READ | KSWORD_ARK_HVM_EPT_EXECUTE,
               "拿掉写权限后剩读与执行");

    /* Idempotent: applying the same restriction twice yields the same result as applying it once. */
    once = KswordArkHvmEptApplyRestriction(
        kRwx, KSWORD_ARK_HVM_EPT_EXECUTE);
    twice = KswordArkHvmEptApplyRestriction(
        once, KSWORD_ARK_HVM_EPT_EXECUTE);
    checkEqU64(twice, once, "同一限制重复施加是幂等的");

    /* Reserved bits are unaffected by restrictions: suppress-#VE and memory type must remain valid. */
    leaf = KswordArkHvmEptApplyRestriction(
        kRwx | (1ULL << 63) | (6ULL << 3),
        KSWORD_ARK_HVM_EPT_WRITE);
    check((leaf & (1ULL << 63)) != 0ULL &&
          ((leaf >> 3) & 7ULL) == 6ULL,
          "限制不影响 suppress-#VE 与内存类型");

    /*
     * Core invariant: Exhaustively testing all 8 permission combinations and 8 removal sets ensures the resulting permission bits are always
     * a subset of the original permission bits. This directly corresponds to "a domain cannot be more permissive than the default view."
     */
    for (bits = 0UL; bits < 64UL; ++bits) {
        const unsigned long long kOriginal = (unsigned long long)(bits & 7UL);
        const unsigned long long kRemoved =
            (unsigned long long)((bits >> 3) & 7UL);
        const unsigned long long kResult =
            KswordArkHvmEptApplyRestriction(kOriginal, kRemoved);

        if ((kResult & ~kOriginal) != 0ULL) {
            break;
        }
    }
    check(bits == 64UL, "任意组合下结果权限都是原权限的子集");
}

/* ------------------------------------------------------------------ */

/*
 * Construction arithmetic for the private EPT hierarchy (P4.1).
 *
 * The private layer replaces a few tables from the shared layer with private copies. An incorrect address swap won't fault
 * but will silently redirect to another page; therefore, this test verifies that every bit except the address survives.
 */
static void
testLocalEptArithmetic(void)
{
    const unsigned long long kSharedLeaf =
        0x0000000123456000ULL |
        KSWORD_ARK_HVM_EPT_READ |
        KSWORD_ARK_HVM_EPT_EXECUTE |
        (6ULL << 3) |
        (1ULL << 63);
    unsigned long long rebased = 0ULL;
    unsigned long long pointer = 0ULL;
    unsigned long index = 0UL;

    group("私有 EPT 构造算术");

    /* Non-leaf entries have no memory type, no large page bit, no suppress-#VE; permissions are the union. */
    pointer = KswordArkHvmEptTablePointer(0x00000000ABCDE123ULL);
    check((pointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) == 0x00000000ABCDE000ULL,
          "非叶项保留页对齐后的物理地址");
    check((pointer & (KSWORD_ARK_HVM_EPT_READ |
                      KSWORD_ARK_HVM_EPT_WRITE |
                      KSWORD_ARK_HVM_EPT_EXECUTE)) ==
              (KSWORD_ARK_HVM_EPT_READ |
               KSWORD_ARK_HVM_EPT_WRITE |
               KSWORD_ARK_HVM_EPT_EXECUTE),
          "非叶项三种权限齐备");
    check((pointer & (1ULL << 7)) == 0ULL &&
          ((pointer >> 3) & 7ULL) == 0ULL &&
          (pointer & (1ULL << 63)) == 0ULL,
          "非叶项不携带大页位、内存类型与 suppress-#VE");

    /*
     * rebase is the only operation that constructs a private path. Core invariant: The physical address
     * is swapped, while every other bit survives bitwise—including suppress-#VE and memory type.
     */
    rebased = KswordArkHvmEptRebaseEntry(kSharedLeaf, 0x00000007FEDCB000ULL);
    checkEqU64(rebased & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
               0x00000007FEDCB000ULL,
               "rebase 换掉了物理地址");
    checkEqU64(rebased & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
               kSharedLeaf & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
               "rebase 之外的每一位都逐位存活");
    check((rebased & (1ULL << 63)) != 0ULL &&
          ((rebased >> 3) & 7ULL) == 6ULL,
          "rebase 保住了 suppress-#VE 与内存类型");

    /* Generate a private EPTP using the same rebase rule: new addresses are inserted while control bits remain unchanged. */
    {
        const unsigned long long kSharedEptp =
            0x0000000200000000ULL | 6ULL | (3ULL << 3) | (1ULL << 6);
        const unsigned long long kPrivateEptp =
            KswordArkHvmEptRebaseEntry(kSharedEptp, 0x0000000300000000ULL);

        checkEqU64(kPrivateEptp & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
                   kSharedEptp & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
                   "私有 EPTP 的内存类型/walk 长度/AD 位与共享的完全一致");
        check((kPrivateEptp & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) !=
                  (kSharedEptp & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK),
              "私有 EPTP 的 EPTRTA 与共享的不同");
    }

    /* Split the entry address into 'table base + slot offset'; iterate through all 512 slots. */
    for (index = 0UL; index < 512UL; ++index) {
        const unsigned long long kBase = 0xFFFFF68000000000ULL;
        const unsigned long long kEntry = kBase + (index * 8ULL);

        if (KswordArkHvmEptEntryTableBase(kEntry) != kBase ||
            KswordArkHvmEptEntryByteOffset(kEntry) != (index * 8ULL)) {
            break;
        }
    }
    check(index == 512UL, "表内 512 个槽的基址/偏移拆分全部往返一致");

    /* 4 KiB slot index: advance one slot per page within the leaf; reset to zero at each 2MiB boundary. */
    check(KswordArkHvmEptPtIndex(0ULL) == 0UL &&
          KswordArkHvmEptPtIndex(KSWORD_ARK_HVM_PAGE_BYTES) == 1UL &&
          KswordArkHvmEptPtIndex(KSWORD_ARK_HVM_LARGE_PAGE_BYTES - 1ULL) == 511UL &&
          KswordArkHvmEptPtIndex(KSWORD_ARK_HVM_LARGE_PAGE_BYTES) == 0UL,
          "四KiB 槽索引在叶内推进、跨叶归零");

    /* Page budget: 1 root + number of PDPTs + number of PDs + number of leaves per CPU. */
    checkEqU64(KswordArkHvmEptLocalPageCost(1UL, 1UL, 1UL, 1UL),
               4ULL,
               "单核单叶最小情形是 4 页");
    checkEqU64(KswordArkHvmEptLocalPageCost(128UL, 1UL, 1UL, 8UL),
               128ULL * 11ULL,
               "128 核 8 叶共 1408 页");

    /* The upper bound criterion must be 'exactly fits' at the boundary, not 'one short'. */
    check(KswordArkHvmEptLocalFitsBudget(2048ULL, 2048ULL) == 1,
          "恰好等于上限时接受");
    check(KswordArkHvmEptLocalFitsBudget(2049ULL, 2048ULL) == 0,
          "超出上限一页即拒绝");
    check(KswordArkHvmEptLocalFitsBudget(0ULL, 2048ULL) == 0,
          "零页成本被拒绝：那说明叶集合是空的");
}

/* ------------------------------------------------------------------ */


static void
testNestedEptComposition(void)
{
    unsigned long long leaf = 0ULL;
    unsigned long p;
    unsigned long q;
    unsigned long a;
    int all = 1;

    group("Nested EPT composition");
    check(KswordArkHvmNestedEptComposeLeaf(0x2468ABCULL, 0x37ULL,
          0x80000000ABCD5037ULL, 12UL, 1UL, &leaf) == 0UL,
          "nonidentity outer mapping resolves");
    checkEqU64(leaf, 0x80000000ABCD5037ULL,
               "L2 maps the replacement frame, not the L1 frame");
    check(KswordArkHvmNestedEptComposeLeaf(0x12345ABCULL, 0x35ULL,
          0x80000000400000B7ULL, 21UL, 4UL, &leaf) == 0UL,
          "large outer mapping resolves");
    checkEqU64(leaf, 0x8000000040145035ULL,
               "2 MiB mapping retains the page offset and intersects permissions");
    check(KswordArkHvmNestedEptComposeLeaf(0x52345ABCULL, 0x37ULL,
          0x80000000800000B7ULL, 30UL, 2UL, &leaf) == 0UL,
          "1 GiB mapping resolves");
    checkEqU64(leaf, 0x8000000092345037ULL, "1 GiB offset is preserved");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0xFED00007ULL, 12UL, 2UL, &leaf) == 0UL &&
          (leaf & 0x38ULL) == 0ULL, "outer MMIO UC is never converted to WB");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x07ULL,
          0x12345037ULL, 12UL, 1UL, &leaf) == 0UL &&
          (leaf & 0x38ULL) == 0ULL, "inner MMIO UC is retained");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x77ULL,
          0x12345337ULL, 12UL, 1UL, &leaf) == 0UL &&
          (leaf & 0x340ULL) == 0x40ULL, "ignore PAT retained; A/D not preclaimed");

    for (p = 0UL; p < 8UL; ++p) {
        for (q = 0UL; q < 8UL; ++q) {
            for (a = 1UL; a < 8UL; ++a) {
                unsigned long result = KswordArkHvmNestedEptComposeLeaf(
                    0x888000ULL, 0x30ULL | p, 0x999030ULL | q, 12UL, a, &leaf);
                unsigned long expected =
                    (p & a) != a ? 1UL :
                    ((p & 3UL) == 2UL || (q & 3UL) == 2UL) ? 3UL :
                    ((p & q & a) != a) ? 2UL : 0UL;
                if (result != expected ||
                    (result == 0UL && (leaf & 7ULL) != (p & q)) ||
                    (result != 0UL && leaf != 0ULL)) { all = 0; }
            }
        }
    }
    check(all, "448 permission combinations preserve ownership and never widen access");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0x400010B7ULL, 21UL, 1UL, &leaf) == 3UL,
          "misaligned large frame refused");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0x123450B7ULL, 12UL, 1UL, &leaf) == 3UL,
          "large bit in 4 KiB leaf refused");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0x12345037ULL, 12UL, 0UL, &leaf) == 3UL, "zero access refused");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0x12345037ULL, 12UL, 8UL, &leaf) == 3UL, "unknown access refused");
    check(KswordArkHvmNestedEptComposeLeaf(0x1000ULL, 0x37ULL,
          0x12345017ULL, 12UL, 1UL, &leaf) == 3UL, "reserved memory type refused");
}

int
main(void)
{
    printf("hvm_unit_tests - KswordArkHvmControls.h\n");
    printf("================================================\n");

    testAdjustControls();
    testMsrBitmap();
    testSelfMap();
    testEptpValidation();
    testEptIndices();
    testDomainRestriction();
    testLocalEptArithmetic();
    testNestedEptComposition();

    printf("\n================================================\n");
    printf("%d 项检查，%d 项失败\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
