/* Pure EPT snapshot comparison, also compiled by the host-side unit test. */
#pragma once

/* Only monotonic hardware A/D updates preserve a cached translation. */
static __inline int kswordHvmEptEntryKeepsTranslation(
    unsigned long long before, unsigned long long after,
    unsigned int level, int accessedDirty)
{
    /* No change always preserves both mapping and tracking semantics. */
    unsigned long long allowed = 0ULL;
    /* Permit A only for an existing entry when EPTP enabled A/D. */
    if (accessedDirty && (before & 7ULL) != 0ULL) {
        /* A is maintained for every traversed level. */
        allowed = 1ULL << 8;
        /* D exists only in a 4-KiB, 2-MiB, or 1-GiB leaf. */
        if (level == 3U || ((level == 1U || level == 2U) &&
                               (before & (1ULL << 7)) != 0ULL)) {
            /* Accept a hardware dirty-bit set in a valid leaf. */
            allowed |= 1ULL << 9;
        }
    }
    /* Clearing A/D starts a new observation epoch and must invalidate. */
    return ((before & ~after) == 0ULL &&
            ((before ^ after) & ~allowed) == 0ULL) ? 1 : 0;
}
