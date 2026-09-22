/* Test real translation identities, including reuse, large pages and read failure. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../drivers/ark/src/features/hvm/hvm_nested_lease_walk.h"

typedef struct {
    KswLeaseU64 tables[4][512];
    KswLeaseU64 failAddress;
} Fixture;
static int readEntry(void *context, KswLeaseU64 address, KswLeaseU64 *value) {
    Fixture *f=(Fixture*)context;
    unsigned int table=(unsigned int)(address/4096)-1;
    if(address==f->failAddress || address<4096 || table>=4 || (address&7)) return 0;
    *value=f->tables[table][(address&4095)/8];return 1;
}
static void reset(Fixture *f) {
    memset(f,0,sizeof(*f));
    f->tables[0][0]=0x2007;f->tables[1][0]=0x3007;
    f->tables[2][0]=0x4007;f->tables[3][7]=0xABC037;
}
/* Flip every bit of every captured entry and require the ignored set to be exact.
   Accessed is metadata at any level; dirty is defined only at the terminating
   leaf, so the leaf level tolerates one more bit than its parents.  A walk that
   stops early has fewer levels to sweep, which is why the leaf level is passed
   in rather than assumed to be the last table. */
static void sweep(Fixture *f,const KswHvmPageTranslation *t,
                  const unsigned int *slots,unsigned int leafLevel) {
    unsigned int level,bit;
    for(level=0;level<t->entryCount;level++) for(bit=0;bit<64;bit++) {
        KswLeaseU64 *entry=&f->tables[level][slots[level]];
        int ignored=bit==8 || (level==leafLevel && bit==9);
        *entry^=1ULL<<bit;
        assert(kswordHvmLeaseValidate(t,readEntry,f)==ignored);
        *entry^=1ULL<<bit;
    }
}
/* The 2-MiB and 1-GiB leaves terminate the walk early, so every property the
   ordinary path proves has to be proved again against a shorter path: a short
   EntryCount must not leave later levels unchecked, and a leaf two or three
   levels up must still expire on permission, cache-type or address drift.
   Before this the large-page cases were capture-only, which proves the walk
   reaches a leaf and nothing about whether the lease ever expires. */
static void largePages(void) {
    Fixture f;KswHvmPageTranslation t,u;
    static const unsigned int kThree[3]={0,0,0},kTwo[2]={0,0};

    /* A 2-MiB leaf: drift detection across the whole shortened path. */
    reset(&f);f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    assert(t.entryCount==3 && t.sourcePage==0xA07000 && t.permissions==7);
    assert(t.entryAddress[2]==0x3000 && t.entryAddress[3]==0);
    sweep(&f,&t,kThree,2);
    /* A read that fails at the leaf is unverifiable, not proven unchanged. */
    f.failAddress=t.entryAddress[2];
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==-1);
    f.failAddress=0;
    /* The unread levels below the leaf must not be consulted. */
    f.tables[3][7]=0xDEAD037;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);

    /* Two pages inside one 2-MiB leaf share a path but not a source frame. */
    reset(&f);f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeaseCapture(0x105E,0x9000,readEntry,&f,&u));
    assert(u.sourcePage==0xA09000 && u.sourcePage-t.sourcePage==0x2000);
    assert(u.entryCount==t.entryCount &&
           !memcmp(u.entryAddress,t.entryAddress,sizeof(u.entryAddress)));
    /* Both still validate: the lease proves path identity, never GPA identity.
       That is the documented limit, and it is asserted here so that a future
       change which silently made validation GPA-sensitive would be noticed. */
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);
    assert(kswordHvmLeaseValidate(&u,readEntry,&f)==1);

    /* A 1-GiB leaf: the shortest accepted path, previously never validated. */
    reset(&f);f.tables[1][0]=0x800000B7;
    assert(kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
    assert(t.entryCount==2 && t.sourcePage==0x87000000 && t.permissions==7);
    assert(t.entryAddress[1]==0x2000 && t.entryAddress[2]==0 && t.entryAddress[3]==0);
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);
    sweep(&f,&t,kTwo,1);
    f.failAddress=t.entryAddress[1];
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==-1);
    f.failAddress=0;
    /* Two levels of stale table state must stay outside the verification. */
    f.tables[2][0]=0xBAD037;f.tables[3][7]=0xBAD037;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);

    /* With A/D disabled, a large leaf's dirty bit is not hardware metadata. */
    reset(&f);f.tables[1][0]=0x800000B7;
    assert(kswordHvmLeaseCapture(0x101E,0x07000000,readEntry,&f,&t));
    f.tables[1][0]|=0x200;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);
    reset(&f);f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeaseCapture(0x101E,0x7000,readEntry,&f,&t));
    f.tables[2][0]|=0x100;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);

    /* Rejections that only a 1-GiB leaf can express. */
    reset(&f);f.tables[1][0]=0x800010B7; /* address bit inside the 1-GiB offset */
    assert(!kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
    reset(&f);f.tables[1][0]=0x80000087; /* 1-GiB leaf, non-WB memory type */
    assert(!kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
    reset(&f);f.tables[1][0]=0x800000B6; /* 1-GiB leaf, write without read */
    assert(!kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
    reset(&f);f.tables[3][7]=0xABC0B7;   /* large bit is illegal at the PTE level */
    assert(!kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));

    /* A parent restriction still binds a leaf that terminates above the PTE. */
    reset(&f);f.tables[0][0]=0x2005;f.tables[2][0]=0xA000B7;
    assert(kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    assert(t.permissions==5);
    /* An empty intersection is refused even though the leaf itself is readable:
       an execute-only parent over a read/write 1-GiB leaf grants nothing. */
    reset(&f);f.tables[0][0]=0x2004;f.tables[1][0]=0x800000B3;
    assert(!kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
}
int main(void) {
    Fixture f;
    KswHvmPageTranslation t;
    unsigned int level,bit;
    reset(&f);
    assert(kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    assert(t.sourcePage==0xABC000 && t.entryCount==4 && t.permissions==7);
    assert(t.entryAddress[0]==0x1000 && t.entryAddress[3]==0x4038);
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);
    /* Exhaustively distinguish semantic bits from the only allowed metadata bits. */
    for(level=0;level<4;level++) for(bit=0;bit<64;bit++) {
        KswLeaseU64 *entry=&f.tables[level][level==3?7:0];
        int ignored=bit==8 || (level==3 && bit==9);
        *entry^=1ULL<<bit;
        assert(kswordHvmLeaseValidate(&t,readEntry,&f)==ignored);
        *entry^=1ULL<<bit;
    }
    f.failAddress=t.entryAddress[2];
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==-1);
    reset(&f);
    f.tables[3][7]=0xFED037; /* same root/GPA, different backing */
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);
    reset(&f);
    f.tables[1][0]=0x4007; /* same root, changed interior path */
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);
    reset(&f);
    f.tables[2][0]=0xA000B7; /* 2-MiB leaf */
    assert(kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    assert(t.entryCount==3 && t.sourcePage==0xA07000);
    f.tables[2][0]|=0x300;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==1);
    f.tables[2][0]^=2;
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);
    reset(&f);
    f.tables[1][0]=0x800000B7; /* 1-GiB leaf */
    assert(kswordHvmLeaseCapture(0x105E,0x07000000,readEntry,&f,&t));
    assert(t.entryCount==2 && t.sourcePage==0x87000000);
    reset(&f);
    assert(kswordHvmLeaseCapture(0x101E,0x7000,readEntry,&f,&t));
    f.tables[3][7]|=0x100; /* A/D disabled: do not ignore these bits */
    assert(kswordHvmLeaseValidate(&t,readEntry,&f)==0);
    reset(&f);f.tables[3][7]=0xABC007; /* non-WB memory */
    assert(!kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    reset(&f);f.tables[2][0]=0xA010B7; /* misaligned large page */
    assert(!kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    reset(&f);f.tables[0][0]=0x2087; /* illegal PML4 large bit */
    assert(!kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    reset(&f);f.tables[3][7]=0xABC032; /* write without read */
    assert(!kswordHvmLeaseCapture(0x105E,0x7000,readEntry,&f,&t));
    reset(&f);
    assert(!kswordHvmLeaseCapture(0x105E,0x7001,readEntry,&f,&t));
    assert(!kswordHvmLeaseCapture(0x105E,1ULL<<48,readEntry,&f,&t));
    assert(!kswordHvmLeaseCapture(0x105F,0x7000,readEntry,&f,&t));
    largePages();
    puts("EPT_LEASE=PASS: identity drift, all bits, A/D, unreadable sources, invalid requests, "
         "2-MiB and 1-GiB leaves (drift, bit sweep, offset folding, short-path bounds)");
    return 0;
}
