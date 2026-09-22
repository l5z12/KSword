/* A lease identifies an EPT translation path, not merely its recyclable root. */
#pragma once

/* Keep the walker independent of Windows so adversarial tables can be tested. */
typedef unsigned long long KswLeaseU64;
/* A reader must copy one complete aligned word or report failure. */
typedef int (*KswLeaseRead)(void* context, KswLeaseU64 address, KswLeaseU64* value);
/* Architectural EPT frame bits, independent of the host's pointer size. */
#define KSW_LEASE_FRAME 0x000FFFFFFFFFF000ULL
/* A bounded four-level path includes the terminating large or ordinary leaf. */
typedef struct KswHvmPageTranslation {
    /* Retain EPT configuration bits as well as the root frame. */
    KswLeaseU64 eptPointer;
    /* Bind one page in the descendant physical-address domain. */
    KswLeaseU64 guestPage;
    /* Record the source frame in Windows 1's physical-address domain. */
    KswLeaseU64 sourcePage;
    /* Retain path addresses so table-page replacement invalidates the lease. */
    KswLeaseU64 entryAddress[4];
    /* Mask only architecturally meaningful accessed/dirty flags. */
    KswLeaseU64 entryValue[4];
    /* Count exactly the entries successfully captured. */
    unsigned int entryCount;
    /* Intersect permissions over the entire path. */
    unsigned int permissions;
} KswHvmPageTranslation;

/* Only A/D flags may change without changing the translation identity. */
static __inline KswLeaseU64 kswordHvmLeaseNormalize(
    KswLeaseU64 eptPointer, KswLeaseU64 entry, unsigned int level)
{
    /* Dirty is defined only for a leaf; an interior reserved-bit change matters. */
    const int kLeaf = level == 3U || ((level == 1U || level == 2U) && (entry & 0x80ULL) != 0ULL);
    /* With A/D disabled these bits are not hardware-maintained metadata. */
    const KswLeaseU64 kIgnored = (eptPointer & 0x40ULL) != 0ULL ? (kLeaf ? 0x300ULL : 0x100ULL) : 0ULL;
    /* Preserve every other permission, frame and configuration bit. */
    return entry & ~kIgnored;
}

/* Capture ordinary WB RAM through the supported four-level EPT format. */
static __inline int kswordHvmLeaseCapture(KswLeaseU64 eptPointer,
    KswLeaseU64 guestPage, KswLeaseRead read, void* context,
    KswHvmPageTranslation* translation)
{
    /* Hardware walk order, including 1-GiB and 2-MiB leaf offsets. */
    static const unsigned int kShifts[4] = {39U, 30U, 21U, 12U};
    /* Resolve the first source table without following a virtual pointer. */
    KswLeaseU64 table = eptPointer & KSW_LEASE_FRAME;
    /* Start with the intersection identity for RWX permissions. */
    unsigned int permissions = 7U, level;
    /* Use a constant initializer supported by both WDK C and the host tests. */
    const KswHvmPageTranslation kEmpty = {0};
    /* initialize the result before any possibly failing read. */
    *translation = kEmpty;
    /* This implementation accepts WB, four-level EPT without unknown EPTP bits. */
    if (read == 0 || table == 0ULL || (eptPointer & 0x3FULL) != 0x1EULL ||
        (eptPointer & ~(KSW_LEASE_FRAME | 0x7FULL)) != 0ULL ||
        (guestPage & ~KSW_LEASE_FRAME) != 0ULL || guestPage >= (1ULL << 48)) { return 0; }
    /* Bind the exact root configuration and target page. */
    translation->eptPointer = eptPointer;
    /* Preserve the caller's already page-aligned GPA. */
    translation->guestPage = guestPage;
    /* Follow at most four bounded, independently checked physical reads. */
    for (level = 0U; level < 4U; ++level) {
        /* Select one aligned entry from the current table. */
        const KswLeaseU64 kAddress = table + (((guestPage >> kShifts[level]) & 0x1FFULL) << 3);
        /* Never inspect uninitialized bytes after a failed read. */
        KswLeaseU64 entry = 0ULL;
        /* Inaccessible and non-present translations cannot be leased. */
        if (!read(context, kAddress, &entry) || (entry & 7ULL) == 0ULL) { return 0; }
        /* Write without read is an architectural EPT misconfiguration. */
        if ((entry & 3ULL) == 2ULL) { return 0; }
        /* Large pages are legal only at the PDPT and PD levels. */
        if ((entry & 0x80ULL) != 0ULL && (level == 0U || level == 3U)) { return 0; }
        /* Preserve the actual entry address, including all path replacements. */
        translation->entryAddress[level] = kAddress;
        /* Permit A/D maintenance without tolerating address or permission drift. */
        translation->entryValue[level] = kswordHvmLeaseNormalize(eptPointer, entry, level);
        /* Publish the number of complete source entries. */
        translation->entryCount = level + 1U;
        /* A parent permission restriction applies to every descendant leaf. */
        permissions &= (unsigned int)(entry & 7ULL);
        /* Stop at a supported large leaf or the final ordinary leaf. */
        if (level == 3U || (entry & 0x80ULL) != 0ULL) {
            /* Large-page address bits below its alignment must be zero. */
            const KswLeaseU64 kOffsetMask = (1ULL << kShifts[level]) - 1ULL;
            /* Reject non-WB memory, reserved address bits and an empty intersection. */
            if ((entry & 0x38ULL) != 0x30ULL ||
                (entry & KSW_LEASE_FRAME & kOffsetMask) != 0ULL || permissions == 0U) { return 0; }
            /* Preserve the target's offset within a large backing page. */
            translation->sourcePage = (entry & KSW_LEASE_FRAME) | (guestPage & kOffsetMask);
            /* Retain effective permissions for evidence and verification. */
            translation->permissions = permissions;
            /* A second read pass by the caller rejects an already changed capture. */
            return 1;
        }
        /* Continue only through a nonzero interior table frame. */
        table = entry & KSW_LEASE_FRAME;
        /* Never read the physical zero page as a missing child table. */
        if (table == 0ULL) { return 0; }
    }
    /* A walk that did not terminate cannot admit a page override. */
    return 0;
}

/* Returns 1 for the same path, 0 for drift, and -1 for unreadable source memory. */
static __inline int kswordHvmLeaseValidate(const KswHvmPageTranslation* translation,
    KswLeaseRead read, void* context)
{
    /* Bound every verification independently of a caller's captured count. */
    unsigned int level;
    /* Empty or malformed captures are never considered valid leases. */
    if (read == 0 || translation->entryCount == 0U || translation->entryCount > 4U) { return -1; }
    /* Revalidate parents before their children so changed paths fail immediately. */
    for (level = 0U; level < translation->entryCount; ++level) {
        /* A failed callback must not leave a usable stale word. */
        KswLeaseU64 value = 0ULL;
        /* Report inability to verify separately from a proven semantic change. */
        if (!read(context, translation->entryAddress[level], &value)) { return -1; }
        /* Address, permission, cache-type and path changes all expire this lease. */
        if (kswordHvmLeaseNormalize(translation->eptPointer, value, level) != translation->entryValue[level]) { return 0; }
    }
    /* This proves sampled translation identity, not an OS-level guest boot identity. */
    return 1;
}
