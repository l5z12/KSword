#pragma once

#include <ntddk.h>

/*
 * Push locks require normal kernel APC delivery to remain disabled for the
 * complete acquire/release interval.  These helpers make that contract part
 * of every KSword-owned push-lock operation, including early-return paths.
 */
static __forceinline
VOID
kswordArkAcquirePushLockShared(
    _Inout_ PEX_PUSH_LOCK lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(lock);
}

static __forceinline
VOID
kswordArkReleasePushLockShared(
    _Inout_ PEX_PUSH_LOCK lock
    )
{
    ExReleasePushLockShared(lock);
    KeLeaveCriticalRegion();
}

static __forceinline
VOID
kswordArkAcquirePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(lock);
}

static __forceinline
VOID
kswordArkReleasePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK lock
    )
{
    ExReleasePushLockExclusive(lock);
    KeLeaveCriticalRegion();
}
