/*++

Module Name:

    system_time_counter.c

Abstract:

    Multi-core safe continuous virtual performance counter and HAL callback entry.

Third-Party Notice:

    The license and archival notes for the referenced mechanism are located at:
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_counter.h"

#include <intrin.h>

/* The HAL counter callback on current x64 Windows takes no parameters and returns a 64-bit count. */
typedef LONGLONG
(*KswSystemTimeCounterRoutine)(
    VOID
    );

/* Publishes both the command and the multiplier in a single atomic LONG to prevent hooks from reading a mixed configuration. */
#define KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK   0x0000FFFFUL
#define KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT 16UL

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(_InterlockedCompareExchange128)
#endif

/* Time pairs are 16-byte aligned, storing lastReal and virtualCounter separately. */
__declspec(align(16))
static volatile LONG64 gKswordArkSystemTimePair[2] = { 0LL, 0LL };

/* The hook only reads three atomic states and does not depend on the runtime control lock. */
static PVOID volatile gKswordArkSystemTimeOriginalCounter = NULL;
static volatile LONG gKswordArkSystemTimeControlWord = 0L;
static volatile LONG gKswordArkSystemTimeInFlight = 0L;

/* Encode the control word: Command occupies the high 16 bits, Factor occupies the low 16 bits. */
static
LONG
kswordArkSystemTimeMakeControlWord(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    const ULONG kEncoded =
        ((command & KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK)
            << KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT) |
        (factor & KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK);
    return (LONG)kEncoded;
}

/* Extract the command field and return the acceleration, deceleration, or resume value defined by the protocol. */
static
ULONG
kswordArkSystemTimeCommandFromControlWord(
    _In_ LONG controlWord
    )
{
    return ((ULONG)controlWord >>
        KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT) &
        KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK;
}

/* Extract the multiplier field; treat zero as 1 to ensure monotonic progression even in fault states. */
static
ULONG
kswordArkSystemTimeFactorFromControlWord(
    _In_ LONG controlWord
    )
{
    const ULONG kFactor =
        (ULONG)controlWord &
        KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK;
    return kFactor == 0UL ? 1UL : kFactor;
}

/* Apply saturation to virtual counter addition to prevent wraparound to negative values after extreme pauses. */
static
ULONGLONG
kswordArkSystemTimeSaturatingAdd(
    _In_ ULONGLONG left,
    _In_ ULONGLONG right
    )
{
    if (left >= (ULONGLONG)MAXLONGLONG ||
        (ULONGLONG)MAXLONGLONG - left < right) {
        return MAXLONGLONG;
    }
    return left + right;
}

/* Scales the real delta by N or 1/N; the maximum scale factor is limited by the shared protocol. */
static
ULONGLONG
kswordArkSystemTimeScaleDelta(
    _In_ ULONGLONG delta,
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    if (command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
        if (delta > (ULONGLONG)MAXLONGLONG / factor) {
            return MAXLONGLONG;
        }
        return delta * factor;
    }
    if (command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
        return delta / factor;
    }
    return delta;
}

/*
 * Atomically commit lastReal/virtualCounter using CMPXCHG16B.
 * On CAS failure, the hardware updates the comparand; the loop uses this to recalculate the current increment.
 */
static
LONGLONG
kswordArkSystemTimeAdvanceCounter(
    _In_ LONGLONG realCounter
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    LONG64 comparand[2] = { 0LL, 0LL };
    const LONG kControlWord = InterlockedCompareExchange(
        &gKswordArkSystemTimeControlWord,
        0L,
        0L);
    const ULONG kCommand =
        kswordArkSystemTimeCommandFromControlWord(kControlWord);
    const ULONG kFactor =
        kswordArkSystemTimeFactorFromControlWord(kControlWord);

    comparand[0] = gKswordArkSystemTimePair[0];
    comparand[1] = gKswordArkSystemTimePair[1];
    for (;;) {
        const ULONGLONG kLastReal =
            (ULONGLONG)comparand[0];
        const ULONGLONG kVirtualCounter =
            (ULONGLONG)comparand[1];
        const ULONGLONG kCurrentReal =
            realCounter > 0LL
            ? (ULONGLONG)realCounter
            : kLastReal;
        const ULONGLONG kRealDelta =
            kCurrentReal > kLastReal
            ? kCurrentReal - kLastReal
            : 0ULL;
        const ULONGLONG kScaledDelta =
            kswordArkSystemTimeScaleDelta(
                kRealDelta,
                kCommand,
                kFactor);
        const ULONGLONG kNextVirtual =
            kswordArkSystemTimeSaturatingAdd(
                kVirtualCounter,
                kScaledDelta);
        const CHAR kExchanged =
            _InterlockedCompareExchange128(
                gKswordArkSystemTimePair,
                (LONG64)kNextVirtual,
                (LONG64)kCurrentReal,
                comparand);
        if (kExchanged != 0) {
            return (LONGLONG)kNextVirtual;
        }
    }
#else
    return RealCounter;
#endif
}

/*
 * After entering the HAL slot, this hook only calls the saved real counter and performs atomic scaling.
 * Entry point and all dependencies are non-paged and do not acquire potentially blocking locks.
 */
static
LONGLONG
kswordArkSystemTimeCounterHook(
    VOID
    )
{
    KswSystemTimeCounterRoutine originalCounter = NULL;
    LONGLONG virtualCounter = 0LL;

    InterlockedIncrement(
        &gKswordArkSystemTimeInFlight);
    originalCounter =
        (KswSystemTimeCounterRoutine)
            InterlockedCompareExchangePointer(
                (PVOID volatile*)
                    &gKswordArkSystemTimeOriginalCounter,
                NULL,
                NULL);
    if (originalCounter != NULL &&
        (PVOID)originalCounter !=
            (PVOID)kswordArkSystemTimeCounterHook) {
        virtualCounter = kswordArkSystemTimeAdvanceCounter(
            originalCounter());
    }
    InterlockedDecrement(
        &gKswordArkSystemTimeInFlight);
    return virtualCounter;
}

VOID
kswordArkSystemTimeCounterInitialize(
    VOID
    )
{
    gKswordArkSystemTimePair[0] = 0LL;
    gKswordArkSystemTimePair[1] = 0LL;
    InterlockedExchangePointer(
        (PVOID volatile*)&gKswordArkSystemTimeOriginalCounter,
        NULL);
    InterlockedExchange(
        &gKswordArkSystemTimeInFlight,
        0L);
    InterlockedExchange(
        &gKswordArkSystemTimeControlWord,
        kswordArkSystemTimeMakeControlWord(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL));
}

VOID
kswordArkSystemTimeCounterActivate(
    _In_ PVOID originalCounter,
    _In_ LONGLONG initialCounter,
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    InterlockedExchangePointer(
        (PVOID volatile*)&gKswordArkSystemTimeOriginalCounter,
        originalCounter);
    gKswordArkSystemTimePair[0] = initialCounter;
    gKswordArkSystemTimePair[1] = initialCounter;
    KeMemoryBarrier();
    InterlockedExchange(
        &gKswordArkSystemTimeControlWord,
        kswordArkSystemTimeMakeControlWord(
            command,
            factor));
}

NTSTATUS
kswordArkSystemTimeCounterReconfigure(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    KswSystemTimeCounterRoutine originalCounter = NULL;

    originalCounter =
        (KswSystemTimeCounterRoutine)
            InterlockedCompareExchangePointer(
                (PVOID volatile*)
                    &gKswordArkSystemTimeOriginalCounter,
                NULL,
                NULL);
    if (originalCounter == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    (void)kswordArkSystemTimeAdvanceCounter(
        originalCounter());
    InterlockedExchange(
        &gKswordArkSystemTimeControlWord,
        kswordArkSystemTimeMakeControlWord(
            command,
            factor));
    return STATUS_SUCCESS;
}

VOID
kswordArkSystemTimeCounterReset(
    VOID
    )
{
    InterlockedExchange(
        &gKswordArkSystemTimeControlWord,
        kswordArkSystemTimeMakeControlWord(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL));
}

PVOID
kswordArkSystemTimeCounterHookAddress(
    VOID
    )
{
    return (PVOID)kswordArkSystemTimeCounterHook;
}

LONG
kswordArkSystemTimeCounterInFlight(
    VOID
    )
{
    return InterlockedCompareExchange(
        &gKswordArkSystemTimeInFlight,
        0L,
        0L);
}
