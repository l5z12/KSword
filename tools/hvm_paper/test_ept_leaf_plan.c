/* Test which override regions may be published as a leaf larger than 4 KiB. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../drivers/ark/src/features/hvm/hvm_nested_leaf_plan.h"

/* Source path lengths, named by the granularity their walk terminated on. */
#define SRC_4K 4U
#define SRC_2M 3U
#define SRC_1G 2U

/* 2-MiB and 1-GiB aligned backing bases used throughout. */
#define BACK_2M 0x40000000ULL
#define BACK_1G 0x80000000ULL

static KswHvmLeafPlan plan;

static unsigned int refusal(unsigned int shift, KswPlanU64 guest,
                            unsigned int entries, KswPlanU64 backing,
                            KswPlanU64 bytes) {
    int ok = kswordHvmLeafPlanCreate(shift, guest, entries, 0, backing, bytes, &plan);
    assert(ok == (plan.refusal == KSW_PLAN_OK));
    return plan.refusal;
}

static void granularity(void) {
    /* A large leaf is admissible only where the source is at least as coarse. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M,0x200000)==KSW_PLAN_OK);
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_1G,BACK_2M,0x200000)==KSW_PLAN_OK);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_1G,BACK_1G,0x40000000)==KSW_PLAN_OK);
    /* 512 separately mapped source pages must not be covered by one leaf. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_4K,BACK_2M,0x200000)
           ==KSW_PLAN_REFUSE_SOURCE_GRANULARITY);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_4K,BACK_1G,0x40000000)
           ==KSW_PLAN_REFUSE_SOURCE_GRANULARITY);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_2M,BACK_1G,0x40000000)
           ==KSW_PLAN_REFUSE_SOURCE_GRANULARITY);
    /* An ordinary page is admissible under any source granularity. */
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,0x1000,0x1000)==KSW_PLAN_OK);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_2M,0x1000,0x1000)==KSW_PLAN_OK);
    /* A capture no terminated walk can produce names no granularity. */
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,0U,0x1000,0x1000)
           ==KSW_PLAN_REFUSE_SOURCE_UNKNOWN);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,1U,0x1000,0x1000)
           ==KSW_PLAN_REFUSE_SOURCE_UNKNOWN);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,5U,0x1000,0x1000)
           ==KSW_PLAN_REFUSE_SOURCE_UNKNOWN);
    assert(kswordHvmLeafSourceShift(4U)==KSW_PLAN_SHIFT_4K);
    assert(kswordHvmLeafSourceShift(3U)==KSW_PLAN_SHIFT_2M);
    assert(kswordHvmLeafSourceShift(2U)==KSW_PLAN_SHIFT_1G);
    assert(kswordHvmLeafSourceShift(0U)==0U && kswordHvmLeafSourceShift(9U)==0U);
}

static void geometry(void) {
    unsigned int shift;
    /* Only the three architectural granularities exist. */
    for(shift=0;shift<64;shift++) {
        unsigned int r=refusal(shift,0,SRC_1G,BACK_1G,0x40000000ULL);
        int legal=shift==KSW_PLAN_SHIFT_4K||shift==KSW_PLAN_SHIFT_2M||
                  shift==KSW_PLAN_SHIFT_1G;
        assert(legal ? r!=KSW_PLAN_REFUSE_SHIFT : r==KSW_PLAN_REFUSE_SHIFT);
    }
    /* The region must start on its own granularity, not merely on a page. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x201000,SRC_2M,BACK_2M,0x200000)
           ==KSW_PLAN_REFUSE_GUEST_ALIGNMENT);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40200000,SRC_1G,BACK_1G,0x40000000)
           ==KSW_PLAN_REFUSE_GUEST_ALIGNMENT);
    /* A base outside the architectural guest-physical width is refused. */
    assert(refusal(KSW_PLAN_SHIFT_2M,KSW_PLAN_GPA_LIMIT,SRC_2M,BACK_2M,0x200000)
           ==KSW_PLAN_REFUSE_GUEST_RANGE);
    assert(refusal(KSW_PLAN_SHIFT_4K,KSW_PLAN_GPA_LIMIT,SRC_4K,0x1000,0x1000)
           ==KSW_PLAN_REFUSE_GUEST_RANGE);
    assert(refusal(KSW_PLAN_SHIFT_1G,KSW_PLAN_GPA_LIMIT,SRC_1G,BACK_1G,0x40000000)
           ==KSW_PLAN_REFUSE_GUEST_RANGE);
    /* The planner has no separate end-of-region check because it cannot be
       reached: assert the property that makes it unreachable, over the highest
       admissible base of every granularity. */
    for(shift=KSW_PLAN_SHIFT_4K;shift<=KSW_PLAN_SHIFT_1G;shift++) {
        KswPlanU64 region,top;
        if(shift!=KSW_PLAN_SHIFT_4K&&shift!=KSW_PLAN_SHIFT_2M&&
           shift!=KSW_PLAN_SHIFT_1G) { continue; }
        region=1ULL<<shift;top=KSW_PLAN_GPA_LIMIT-region;
        assert(refusal(shift,top,SRC_1G,BACK_1G,0x40000000ULL)==KSW_PLAN_OK);
        assert(plan.guestBase+plan.regionBytes==KSW_PLAN_GPA_LIMIT);
        /* One region higher is no longer a legal base at all. */
        assert(refusal(shift,top+region,SRC_1G,BACK_1G,0x40000000ULL)
               ==KSW_PLAN_REFUSE_GUEST_RANGE);
    }
    /* Sizes and page counts follow the granularity exactly. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M,0x200000)==KSW_PLAN_OK);
    assert(plan.regionBytes==0x200000ULL && plan.pageCount==512ULL);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_1G,BACK_1G,0x40000000)==KSW_PLAN_OK);
    assert(plan.regionBytes==0x40000000ULL && plan.pageCount==262144ULL);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,0x1000,0x1000)==KSW_PLAN_OK);
    assert(plan.regionBytes==0x1000ULL && plan.pageCount==1ULL);
}

static void backing(void) {
    /* Hardware ignores frame bits below the leaf granularity. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M+0x1000,0x200000)
           ==KSW_PLAN_REFUSE_BACKING_ALIGNMENT);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_1G,BACK_1G+0x200000,0x40000000)
           ==KSW_PLAN_REFUSE_BACKING_ALIGNMENT);
    /* A short allocation would publish a leaf over memory we do not own. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M,0x200000-1)
           ==KSW_PLAN_REFUSE_BACKING_SIZE);
    assert(refusal(KSW_PLAN_SHIFT_1G,0x40000000,SRC_1G,BACK_1G,0x200000)
           ==KSW_PLAN_REFUSE_BACKING_SIZE);
    /* A larger allocation than the region is accepted; only short is refused. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M,0x400000)==KSW_PLAN_OK);
    /* Physical zero and non-frame bits are never valid backing. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,0,0x200000)
           ==KSW_PLAN_REFUSE_BACKING_ADDRESS);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,0x1007,0x1000)
           ==KSW_PLAN_REFUSE_BACKING_ADDRESS);
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,1ULL<<52,0x1000)
           ==KSW_PLAN_REFUSE_BACKING_ADDRESS);
}

static void ownership(void) {
    KswHvmLeafPlan refused;
    /* A 2-MiB plan owns every page of its region and nothing outside it. */
    assert(refusal(KSW_PLAN_SHIFT_2M,0x200000,SRC_2M,BACK_2M,0x200000)==KSW_PLAN_OK);
    assert(!kswordHvmLeafPlanContains(&plan,0x1FFFFF));
    assert(kswordHvmLeafPlanContains(&plan,0x200000));
    assert(kswordHvmLeafPlanContains(&plan,0x200000+0x1FFFFF));
    assert(!kswordHvmLeafPlanContains(&plan,0x400000));
    /* The leaf carries the region base; hardware adds the offset itself. */
    assert(kswordHvmLeafPlanLeafFrame(&plan)==BACK_2M);
    /* Staging indexes the backing linearly and stops at the region edge. */
    assert(kswordHvmLeafPlanPageFrame(&plan,0)==BACK_2M);
    assert(kswordHvmLeafPlanPageFrame(&plan,1)==BACK_2M+0x1000);
    assert(kswordHvmLeafPlanPageFrame(&plan,511)==BACK_2M+0x1FF000);
    assert(kswordHvmLeafPlanPageFrame(&plan,512)==0);
    assert(kswordHvmLeafPlanPageFrame(&plan,~0ULL)==0);
    /* A refused plan owns nothing and hands out no frame. */
    assert(!kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_2M,0x200000,SRC_4K,0,
                                    BACK_2M,0x200000,&refused));
    assert(!kswordHvmLeafPlanContains(&refused,0x200000));
    assert(kswordHvmLeafPlanLeafFrame(&refused)==0);
    assert(kswordHvmLeafPlanPageFrame(&refused,0)==0);
    /* A 4-KiB plan owns exactly one page, preserving the original behaviour. */
    assert(refusal(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,0x1000,0x1000)==KSW_PLAN_OK);
    assert(kswordHvmLeafPlanContains(&plan,0x7000));
    assert(kswordHvmLeafPlanContains(&plan,0x7fff));
    assert(!kswordHvmLeafPlanContains(&plan,0x8000));
    assert(!kswordHvmLeafPlanContains(&plan,0x6fff));
    assert(kswordHvmLeafPlanPageFrame(&plan,0)==0x1000);
    assert(kswordHvmLeafPlanPageFrame(&plan,1)==0);
    /* Null arguments are refused rather than dereferenced. */
    assert(!kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_4K,0x7000,SRC_4K,0,0x1000,0x1000,0));
    assert(!kswordHvmLeafPlanContains(0,0x7000));
    assert(kswordHvmLeafPlanLeafFrame(0)==0);
    assert(kswordHvmLeafPlanPageFrame(0,0)==0);
}

/* A synthetic EPT12: four table pages at 0x1000, 0x2000, 0x3000, 0x4000. */
typedef struct { KswPlanU64 tables[4][512]; KswPlanU64 fail; } Fixture;
static int rd(void *ctx, KswPlanU64 addr, KswPlanU64 *val) {
    Fixture *f=(Fixture*)ctx;
    unsigned long t=(unsigned long)(addr/4096)-1;
    if(addr==f->fail || addr<4096 || t>=4 || (addr&7)) return 0;
    *val=f->tables[t][(addr&4095)/8];return 1;
}
/* Identity-ish hierarchy with 512 ordinary leaves under one 2-MiB region. */
static void fine(Fixture *f, KswPlanU64 bits) {
    unsigned int i;
    memset(f,0,sizeof(*f));
    f->tables[0][0]=0x2007;f->tables[1][0]=0x3007;f->tables[2][0]=0x4007;
    for(i=0;i<512;i++) { f->tables[3][i]=((KswPlanU64)(0xA00+i)<<12)|bits; }
}

static void scan(void) {
    Fixture f; KswHvmLeafSourceScan s; KswHvmLeafPlan p;
    const KswPlanU64 kEptp=0x105E;

    /* 512 uniform 4-KiB leaves: one leaf may stand for all of them. */
    fine(&f,0x37);
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(s.complete && s.uniform && s.shift==KSW_PLAN_SHIFT_4K);
    assert(s.leafCount==512 && s.sharedBits==0x37);
    /* And that proof is what admits the region a coarse source would admit. */
    assert(!kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_2M,0,SRC_4K,0,BACK_2M,0x200000,&p));
    assert(p.refusal==KSW_PLAN_REFUSE_SOURCE_GRANULARITY);
    assert(kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_2M,0,SRC_4K,1,BACK_2M,0x200000,&p));
    assert(p.refusal==KSW_PLAN_OK && p.pageCount==512);

    /* One page the VMM made read-only breaks the whole region. */
    fine(&f,0x37); f.tables[3][300]=(0xA00ULL+300)<<12 | 0x35;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(s.complete && !s.uniform);
    /* One page with a different memory type breaks it too. */
    fine(&f,0x37); f.tables[3][511]=(0xA00ULL+511)<<12 | 0x07;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(s.complete && !s.uniform);
    /* Accessed and dirty differ per page and must not count as disagreement. */
    fine(&f,0x37); f.tables[3][7]|=0x100; f.tables[3][8]|=0x300;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(s.complete && s.uniform);

    /* An absent page means the region is not covered, so not uniform-provable. */
    fine(&f,0x37); f.tables[3][42]=0;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(!s.complete);
    /* An unreadable table is the same: incomplete, never silently uniform. */
    fine(&f,0x37); f.fail=0x4000+42*8;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(!s.complete && !s.uniform);
    /* An interior entry that grants access but names frame zero leads nowhere.
       It is present, so the permission test above lets it through; only the
       frame test stops it, and reporting the region uniform on that path would
       admit a leaf over memory the source does not describe. */
    fine(&f,0x37); f.tables[2][0]=0x0007;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(!s.complete && !s.uniform);
    fine(&f,0x37); f.tables[1][0]=0x0007;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(!s.complete && !s.uniform);

    /* A single coarse source leaf ends the walk after one read. */
    memset(&f,0,sizeof(f));
    f.tables[0][0]=0x2007;f.tables[1][0]=0x3007;f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,&s));
    assert(s.complete && s.uniform && s.shift==KSW_PLAN_SHIFT_2M && s.leafCount==1);

    /* A 1-GiB region over 4-KiB sources is 262,144 leaves. It is refused from
       the first leaf's granularity alone, before any of them is read: LeafCount
       stays zero, which is what separates "refused up front" from "walked until
       something went wrong". */
    fine(&f,0x37);
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_1G,rd,&f,&s));
    assert(!s.uniform && !s.complete && s.leafCount==0 && s.shift==KSW_PLAN_SHIFT_4K);
    /* The same region is admissible the moment its source is one 1-GiB leaf. */
    memset(&f,0,sizeof(f));
    f.tables[0][0]=0x2007;f.tables[1][0]=0x800000B7;
    assert(kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_1G,rd,&f,&s));
    assert(s.uniform && s.complete && s.leafCount==1 && s.shift==KSW_PLAN_SHIFT_1G);

    /* Bad arguments are refused, not guessed. */
    assert(!kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,rd,&f,0));
    assert(!kswordHvmLeafPlanScanSource(kEptp,0,KSW_PLAN_SHIFT_2M,0,&f,&s));
    assert(!kswordHvmLeafPlanScanSource(kEptp,0,11U,rd,&f,&s));
}

/* Rechecking what the scan proved, one page at a time. */
static void recheck(void) {
    Fixture f; KswHvmLeafPlan p, refused;
    const KswPlanU64 kEptp=0x105E;
    /* The region the scan above admits: 512 ordinary pages sharing 0x37. */
    assert(kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_2M,0,SRC_4K,1,BACK_2M,0x200000,&p));

    /* Nothing has changed, so every page still agrees. */
    fine(&f,0x37);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,0,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,300,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,511,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);

    /* The cursor wraps, so a caller may hold one counter that only grows. */
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,512,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    f.tables[3][301]=(0xA00ULL+301)<<12 | 0x35;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,301,0x37,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);
    /* 813 folds to 301: the same page, reached by wrapping. */
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,813,0x37,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);
    /* A neighbour of the changed page is unaffected; this is per page. */
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,302,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);

    /* A different memory type is drift for the same reason a permission is. */
    fine(&f,0x37); f.tables[3][9]=(0xA00ULL+9)<<12 | 0x07;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,9,0x37,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);

    /* A page that went away is drift, not an unreadable source. */
    fine(&f,0x37); f.tables[3][42]=0;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,42,0x37,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);
    /* So is an interior table that went away, for every page under it. */
    fine(&f,0x37); f.tables[2][0]=0;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,7,0x37,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);

    /* Hardware sets accessed and dirty per page. Counting them as drift would
       revoke every region as soon as its guest ran, which is the whole reason
       the admitting scan masks them; the recheck must mask the same ones. */
    fine(&f,0x37); f.tables[3][11]|=0x100; f.tables[3][12]|=0x300;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,11,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,12,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);

    /* A read that failed proves nothing and must not revoke a live lease. */
    fine(&f,0x37); f.fail=0x4000+5*8;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,5,0x37,rd,&f)==KSW_PLAN_RECHECK_UNKNOWN);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,6,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    /* Neither does a malformed present entry naming frame zero. */
    fine(&f,0x37); f.tables[1][0]=0x0007;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,0,0x37,rd,&f)==KSW_PLAN_RECHECK_UNKNOWN);

    /* A coarse source leaf under the region is compared at the level it ends
       on, so a region backed by one 2-MiB leaf is rechecked against that leaf.
       The page-size bit is masked out on both sides, exactly as the admitting
       scan masks it, so the entry 0xA000B7 is rechecked against 0x37 and not
       against 0xB7 -- comparing the raw entry would revoke every coarse-source
       region on its first sample. */
    memset(&f,0,sizeof(f));
    f.tables[0][0]=0x2007;f.tables[1][0]=0x3007;f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,0,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,400,0x37,rd,&f)==KSW_PLAN_RECHECK_AGREES);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,0,0xB7,rd,&f)==KSW_PLAN_RECHECK_DRIFTED);

    /* Nothing to recheck is not the same as nothing has changed. */
    fine(&f,0x37);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,0,0,0x37,rd,&f)==KSW_PLAN_RECHECK_UNKNOWN);
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&p,0,0x37,0,&f)==KSW_PLAN_RECHECK_UNKNOWN);
    assert(kswordHvmLeafPlanRecheckPage(0,&p,0,0x37,rd,&f)==KSW_PLAN_RECHECK_UNKNOWN);
    assert(!kswordHvmLeafPlanCreate(KSW_PLAN_SHIFT_2M,0,SRC_4K,0,BACK_2M,0x200000,&refused));
    assert(kswordHvmLeafPlanRecheckPage(kEptp,&refused,0,0x37,rd,&f)==KSW_PLAN_RECHECK_UNKNOWN);
}

int main(void) {
    granularity();
    geometry();
    backing();
    ownership();
    scan();
    recheck();
    puts("EPT_LEAF_PLAN=PASS: source granularity, geometry, backing, ownership, "
         "source uniformity scan, published-region recheck");
    return 0;
}
