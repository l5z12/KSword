#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_guard.c

Abstract:

    Explicitly-confirmed KeBugCheckEx guard with persistent ignore mode.

--*/

#if !defined(_WIN64)
#error The bugcheck delay guard only supports x64 builds.
#endif

#define KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED 0L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED   1L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING   2L
#define KSWORD_ARK_BUGCHECK_GUARD_SYSTEM_CODEINTEGRITY_INFORMATION 103UL

typedef VOID
(NTAPI* KswordArkKeBugcheckExFn)(
    _In_ ULONG bugCheckCode,
    _In_ ULONG_PTR parameter1,
    _In_ ULONG_PTR parameter2,
    _In_ ULONG_PTR parameter3,
    _In_ ULONG_PTR parameter4
    );

typedef struct KswordArkBugcheckGuardCodeintegrityInformation
{
    ULONG length;
    ULONG codeIntegrityOptions;
} KswordArkBugcheckGuardCodeintegrityInformation;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef struct KswordArkBugcheckGuardState
{
    FAST_MUTEX controlLock;
    volatile LONG hookState;
    volatile LONG enabled;
    volatile LONG fired;
    volatile LONG tryIgnoreError;
    volatile LONG errorIgnored;
    volatile LONG hookExecutions;
    volatile LONG hvciEnabled;
    volatile LONG callbackRegistered;
    ULONG delaySeconds;
    PVOID target;
    PMDL targetMdl;
    PVOID writableAlias;
    KBUGCHECK_CALLBACK_RECORD callbackRecord;
    ULONG callbackBuffer;
    UCHAR originalBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    UCHAR hookBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    NTSTATUS lastStatus;
} KswordArkBugcheckGuardState;

static KswordArkBugcheckGuardState gKswordArkBugcheckGuard;
static UCHAR gKswordArkBugcheckGuardComponent[] = "KswordBugcheckGuard";

static VOID
NTAPI
kswordArkBugcheckGuardHook(
    _In_ ULONG bugCheckCode,
    _In_ ULONG_PTR parameter1,
    _In_ ULONG_PTR parameter2,
    _In_ ULONG_PTR parameter3,
    _In_ ULONG_PTR parameter4
    );

static VOID
kswordArkBugcheckGuardCallback(
    _In_ PVOID buffer,
    _In_ ULONG length
    );

static BOOLEAN
kswordArkBugcheckGuardLooksHooked(
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* bytes
    )
{
    if (bytes[0] == 0xE9U || bytes[0] == 0xEBU || bytes[0] == 0xCCU) {
        return TRUE;
    }

    if ((bytes[0] == 0xFFU && bytes[1] == 0x25U) ||
        (bytes[0] == 0x48U && bytes[1] == 0xB8U &&
         bytes[10] == 0xFFU && bytes[11] == 0xE0U)) {
        return TRUE;
    }

    return FALSE;
}

static VOID
kswordArkBugcheckGuardBuildHook(
    _Out_writes_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) UCHAR* patch
    )
{
    PVOID hookTarget = (PVOID)(ULONG_PTR)kswordArkBugcheckGuardHook;
    RtlZeroMemory(patch, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    patch[0] = 0x48U;
    patch[1] = 0xB8U;
    RtlCopyMemory(patch + 2U, &hookTarget, sizeof(hookTarget));
    patch[10] = 0xFFU;
    patch[11] = 0xE0U;
}

static BOOLEAN
kswordArkBugcheckGuardHvciEnabled(VOID)
{
    KswordArkBugcheckGuardCodeintegrityInformation information;
    NTSTATUS status;

    RtlZeroMemory(&information, sizeof(information));
    information.length = sizeof(information);
    status = ZwQuerySystemInformation(
        KSWORD_ARK_BUGCHECK_GUARD_SYSTEM_CODEINTEGRITY_INFORMATION,
        &information,
        sizeof(information),
        NULL);
    return NT_SUCCESS(status) &&
        (information.codeIntegrityOptions &
            KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0UL;
}

static NTSTATUS
kswordArkBugcheckGuardTryWriteBytes(
    _Out_writes_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) PVOID destination,
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* source
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        RtlCopyMemory(
            destination,
            source,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
kswordArkBugcheckGuardVerifyBytes(
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const VOID* address,
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* expected
    )
{
    SIZE_T matchingBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        matchingBytes = RtlCompareMemory(
            address,
            expected,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status) &&
        matchingBytes != KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) {
        status = STATUS_DATA_ERROR;
    }
    return status;
}

static ULONG
kswordArkBugcheckGuardStateFlags(VOID)
{
    ULONG flags = 0UL;

    if (gKswordArkBugcheckGuard.target != NULL) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TARGET_RESOLVED;
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE;
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.hookState, 1L, 1L) == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_PATCH_INSTALLED;
    }

    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.fired, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED;
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.tryIgnoreError, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR;
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.errorIgnored, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED;
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.hookExecutions, 0L, 0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hvciEnabled,
            1L,
            1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.callbackRegistered,
            1L,
            1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED;
    }
    return flags;
}
static NTSTATUS
kswordArkBugcheckGuardRestoreFromCrashPath(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    LONG state = InterlockedCompareExchange(
        &gKswordArkBugcheckGuard.hookState,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);

    if (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        if (gKswordArkBugcheckGuard.writableAlias == NULL ||
            gKswordArkBugcheckGuard.target == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
        }
        else {
            status = kswordArkBugcheckGuardVerifyBytes(
                gKswordArkBugcheckGuard.writableAlias,
                gKswordArkBugcheckGuard.originalBytes);
            if (!NT_SUCCESS(status)) {
                status = kswordArkBugcheckGuardTryWriteBytes(
                    gKswordArkBugcheckGuard.writableAlias,
                    gKswordArkBugcheckGuard.originalBytes);
                if (NT_SUCCESS(status)) {
                    status = kswordArkBugcheckGuardVerifyBytes(
                        gKswordArkBugcheckGuard.writableAlias,
                        gKswordArkBugcheckGuard.originalBytes);
                }
            }
        }
        if (NT_SUCCESS(status)) {
            KeInvalidateRangeAllCaches(
                gKswordArkBugcheckGuard.target,
                KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
            InterlockedExchange(
                &gKswordArkBugcheckGuard.hookState,
                KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED);
            return STATUS_SUCCESS;
        }
        gKswordArkBugcheckGuard.lastStatus = status;
        InterlockedExchange(
            &gKswordArkBugcheckGuard.hookState,
            KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);
        return status;
    }

    while (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING) {
        KeStallExecutionProcessor(10UL);
        state = InterlockedCompareExchange(&gKswordArkBugcheckGuard.hookState, 0L, 0L);
    }
    return state == KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ?
        STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

static NTSTATUS
kswordArkBugcheckGuardReleaseMappingLocked(VOID)
{
    NTSTATUS status;

    InterlockedExchange(&gKswordArkBugcheckGuard.enabled, 0L);
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.callbackRegistered,
            0L,
            0L) != 0L) {
        if (InterlockedCompareExchange(
                &gKswordArkBugcheckGuard.hookExecutions,
                0L,
                0L) != 0L ||
            !KeDeregisterBugCheckCallback(
                &gKswordArkBugcheckGuard.callbackRecord)) {
            return STATUS_DEVICE_BUSY;
        }
        InterlockedExchange(
            &gKswordArkBugcheckGuard.callbackRegistered,
            0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.fired, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.tryIgnoreError, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 0L);
        gKswordArkBugcheckGuard.delaySeconds = 0UL;
        return STATUS_SUCCESS;
    }

    status = kswordArkBugcheckGuardRestoreFromCrashPath();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hookExecutions,
            0L,
            0L) != 0L) {
        // A triggering CPU is still executing this driver. A later disable
        // request can release the mapping after the return attempt completes.
        return STATUS_DEVICE_BUSY;
    }
    InterlockedExchange(&gKswordArkBugcheckGuard.fired, 0L);
    InterlockedExchange(&gKswordArkBugcheckGuard.tryIgnoreError, 0L);
    InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 0L);
    if (gKswordArkBugcheckGuard.writableAlias != NULL) {
        MmUnmapLockedPages(gKswordArkBugcheckGuard.writableAlias, gKswordArkBugcheckGuard.targetMdl);
        gKswordArkBugcheckGuard.writableAlias = NULL;
    }
    if (gKswordArkBugcheckGuard.targetMdl != NULL) {
        MmUnlockPages(gKswordArkBugcheckGuard.targetMdl);
        IoFreeMdl(gKswordArkBugcheckGuard.targetMdl);
        gKswordArkBugcheckGuard.targetMdl = NULL;
    }
    gKswordArkBugcheckGuard.target = NULL;
    RtlZeroMemory(gKswordArkBugcheckGuard.originalBytes, sizeof(gKswordArkBugcheckGuard.originalBytes));
    RtlZeroMemory(gKswordArkBugcheckGuard.hookBytes, sizeof(gKswordArkBugcheckGuard.hookBytes));
    gKswordArkBugcheckGuard.delaySeconds = 0UL;
    return STATUS_SUCCESS;
}

static VOID
kswordArkBugcheckGuardDelay(
    _In_ ULONG delaySeconds
    )
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    ULONG remainingSeconds;

    (void)KeQueryPerformanceCounter(&frequency);
    if (frequency.QuadPart <= 0) {
        for (remainingSeconds = delaySeconds;
             remainingSeconds != 0UL;
             --remainingSeconds) {
            ULONG sliceIndex;

            for (sliceIndex = 0UL; sliceIndex < 20000UL; ++sliceIndex) {
                if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) == 0L) { /* Let an explicit off request cancel the remaining delay. */
                    return; /* Leave crash forwarding or return handling to the caller. */
                }
                KeStallExecutionProcessor(50UL);
            }
        }
        return;
    }
    for (remainingSeconds = delaySeconds;
         remainingSeconds != 0UL;
         --remainingSeconds) {
        start = KeQueryPerformanceCounter(NULL);
        while ((ULONGLONG)(
                KeQueryPerformanceCounter(NULL).QuadPart -
                start.QuadPart) < (ULONGLONG)frequency.QuadPart) {
            if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) == 0L) { /* Observe switch-off without waiting for the full configured delay. */
                return; /* Do not acquire control locks in the crash path. */
            }
            KeStallExecutionProcessor(50UL);
        }
    }
}

static VOID
kswordArkBugcheckGuardCallback(
    _In_ PVOID buffer,
    _In_ ULONG length
    )
{
    BOOLEAN enabled; /* Snapshot the switch without consuming an activation. */

    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(length);

    InterlockedIncrement(&gKswordArkBugcheckGuard.hookExecutions);
    enabled = InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) != 0L; /* Read the persistent switch. */
    if (enabled) { /* Each callback keeps the registration active until disable. */
        InterlockedExchange(&gKswordArkBugcheckGuard.fired, 1L); /* Record history without disarming the guard. */
        kswordArkBugcheckGuardDelay(
            gKswordArkBugcheckGuard.delaySeconds);
    }
    InterlockedDecrement(&gKswordArkBugcheckGuard.hookExecutions);
}

static VOID
NTAPI
kswordArkBugcheckGuardHook(
    _In_ ULONG bugCheckCode,
    _In_ ULONG_PTR parameter1,
    _In_ ULONG_PTR parameter2,
    _In_ ULONG_PTR parameter3,
    _In_ ULONG_PTR parameter4
    )
{
    KswordArkKeBugcheckExFn target;
    BOOLEAN enabled; /* Preserve whether this invocation entered an enabled guard. */
    BOOLEAN tryIgnoreError;
    NTSTATUS restoreStatus;

    InterlockedIncrement(&gKswordArkBugcheckGuard.hookExecutions);
    target =
        (KswordArkKeBugcheckExFn)gKswordArkBugcheckGuard.target;
    enabled = InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) != 0L; /* Read the switch without clearing it. */
    tryIgnoreError = InterlockedCompareExchange(
        &gKswordArkBugcheckGuard.tryIgnoreError,
        1L,
        1L) != 0L;

    if (enabled) { /* Apply the configured delay on every intercepted call. */
        InterlockedExchange(&gKswordArkBugcheckGuard.fired, 1L); /* Fired is history, not an automatic off switch. */
        kswordArkBugcheckGuardDelay(gKswordArkBugcheckGuard.delaySeconds); /* Keep the entry installed throughout the delay. */
    }
    if (enabled && tryIgnoreError &&
        InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) != 0L) { /* An explicit disable takes precedence over persistent interception. */
        // The entry remains installed for subsequent calls. A forced return still
        // does not repair the fault or supply a valid continuation for no-return callers.
        InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 1L); /* Report a return attempt, not system recovery. */
        InterlockedDecrement(&gKswordArkBugcheckGuard.hookExecutions); /* Release this invocation before returning. */
        return; /* Only explicit disable or the normal forwarding mode restores the entry. */
    }
    InterlockedExchange(&gKswordArkBugcheckGuard.enabled, 0L); /* Normal forwarding leaves interception before entering Windows bugcheck. */
    restoreStatus = kswordArkBugcheckGuardRestoreFromCrashPath(); /* Restore only when forwarding, never on a persistent ignore hit. */
    if (!NT_SUCCESS(restoreStatus)) {
        gKswordArkBugcheckGuard.lastStatus = restoreStatus;
        InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 1L);
        InterlockedDecrement(&gKswordArkBugcheckGuard.hookExecutions);
        return;
    }
    InterlockedDecrement(&gKswordArkBugcheckGuard.hookExecutions);
    if (target != NULL) {
        target(bugCheckCode, parameter1, parameter2, parameter3, parameter4);
    }
    KeBugCheckEx(bugCheckCode, parameter1, parameter2, parameter3, parameter4);
}

static NTSTATUS
kswordArkBugcheckGuardEnableCallbackLocked(
    _In_ ULONG delaySeconds
    )
{
    BOOLEAN registered;

    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hookState,
            0L,
            0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ||
        InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.callbackRegistered,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hookExecutions,
            0L,
            0L) != 0L ||
        gKswordArkBugcheckGuard.target != NULL ||
        gKswordArkBugcheckGuard.targetMdl != NULL ||
        gKswordArkBugcheckGuard.writableAlias != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    gKswordArkBugcheckGuard.delaySeconds = delaySeconds;
    gKswordArkBugcheckGuard.callbackBuffer = 0UL;
    InterlockedExchange(&gKswordArkBugcheckGuard.fired, 0L);
    InterlockedExchange(&gKswordArkBugcheckGuard.tryIgnoreError, 0L);
    InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 0L);
    InterlockedExchange(&gKswordArkBugcheckGuard.hookExecutions, 0L);
    KeInitializeCallbackRecord(&gKswordArkBugcheckGuard.callbackRecord);
    registered = KeRegisterBugCheckCallback(
        &gKswordArkBugcheckGuard.callbackRecord,
        kswordArkBugcheckGuardCallback,
        &gKswordArkBugcheckGuard.callbackBuffer,
        sizeof(gKswordArkBugcheckGuard.callbackBuffer),
        gKswordArkBugcheckGuardComponent);
    if (!registered) {
        gKswordArkBugcheckGuard.delaySeconds = 0UL;
        return STATUS_UNSUCCESSFUL;
    }
    InterlockedExchange(
        &gKswordArkBugcheckGuard.callbackRegistered,
        1L);
    InterlockedExchange(&gKswordArkBugcheckGuard.enabled, 1L);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckGuardEnableLocked(
    _In_ ULONG delaySeconds,
    _In_ BOOLEAN tryIgnoreError
    )
{
    UNICODE_STRING routineName;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID target = NULL;
    PMDL mdl = NULL;
    PVOID writableAlias = NULL;
    BOOLEAN pagesLocked = FALSE;
    BOOLEAN canReleaseMapping = TRUE;

    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hvciEnabled,
            1L,
            1L) != 0L) {
        return kswordArkBugcheckGuardEnableCallbackLocked(delaySeconds);
    }
    if (InterlockedCompareExchange(&gKswordArkBugcheckGuard.hookState, 0L, 0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED) {
        return InterlockedCompareExchange(&gKswordArkBugcheckGuard.enabled, 0L, 0L) != 0L
            ? STATUS_ALREADY_REGISTERED : STATUS_DEVICE_BUSY; /* A pending disable is not an active installation. */
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckGuard.hookExecutions,
            0L,
            0L) != 0L ||
        gKswordArkBugcheckGuard.target != NULL ||
        gKswordArkBugcheckGuard.targetMdl != NULL ||
        gKswordArkBugcheckGuard.writableAlias != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    RtlInitUnicodeString(&routineName, L"KeBugCheckEx");
    target = MmGetSystemRoutineAddress(&routineName);
    if (target == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    mdl = IoAllocateMdl(target, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // The original executable mapping is intentionally read-only. Probe
        // for read access, then apply PAGE_READWRITE only to the MDL alias.
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        writableAlias = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        if (writableAlias == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        RtlCopyMemory(gKswordArkBugcheckGuard.originalBytes, writableAlias, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        if (kswordArkBugcheckGuardLooksHooked(gKswordArkBugcheckGuard.originalBytes)) {
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }
        kswordArkBugcheckGuardBuildHook(gKswordArkBugcheckGuard.hookBytes);
        gKswordArkBugcheckGuard.target = target;
        gKswordArkBugcheckGuard.targetMdl = mdl;
        gKswordArkBugcheckGuard.writableAlias = writableAlias;
        gKswordArkBugcheckGuard.delaySeconds = delaySeconds;
        InterlockedExchange(&gKswordArkBugcheckGuard.fired, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.tryIgnoreError, tryIgnoreError ? 1L : 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.hookExecutions, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.hookState, KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);
        status = kswordArkBugcheckGuardTryWriteBytes(
            writableAlias,
            gKswordArkBugcheckGuard.hookBytes);
        if (NT_SUCCESS(status)) {
            status = kswordArkBugcheckGuardVerifyBytes(
                writableAlias,
                gKswordArkBugcheckGuard.hookBytes);
        }
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        KeInvalidateRangeAllCaches(
            target,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        InterlockedExchange(&gKswordArkBugcheckGuard.enabled, 1L);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        if (InterlockedCompareExchange(
                &gKswordArkBugcheckGuard.hookState,
                0L,
                0L) == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
            NTSTATUS restoreStatus =
                kswordArkBugcheckGuardRestoreFromCrashPath();
            if (!NT_SUCCESS(restoreStatus)) {
                canReleaseMapping = FALSE;
            }
        }
        InterlockedExchange(&gKswordArkBugcheckGuard.enabled, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.tryIgnoreError, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.errorIgnored, 0L);
        InterlockedExchange(&gKswordArkBugcheckGuard.hookExecutions, 0L);
        if (canReleaseMapping) {
            if (writableAlias != NULL) {
                MmUnmapLockedPages(writableAlias, mdl);
            }
            if (pagesLocked) {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);
            gKswordArkBugcheckGuard.target = NULL;
            gKswordArkBugcheckGuard.targetMdl = NULL;
            gKswordArkBugcheckGuard.writableAlias = NULL;
            gKswordArkBugcheckGuard.delaySeconds = 0UL;
            RtlZeroMemory(gKswordArkBugcheckGuard.originalBytes, sizeof(gKswordArkBugcheckGuard.originalBytes));
            RtlZeroMemory(gKswordArkBugcheckGuard.hookBytes, sizeof(gKswordArkBugcheckGuard.hookBytes));
        }
    }
    return status;
}

static VOID
kswordArkBugcheckGuardFillResponse(
    _Out_ KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* response,
    _In_ ULONG status
    )
{
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
    response->status = status;
    response->stateFlags = kswordArkBugcheckGuardStateFlags();
    response->delaySeconds = gKswordArkBugcheckGuard.delaySeconds;
    response->lastStatus = gKswordArkBugcheckGuard.lastStatus;
    response->targetAddress = (ULONGLONG)(ULONG_PTR)gKswordArkBugcheckGuard.target;
    RtlCopyMemory(response->originalBytes, gKswordArkBugcheckGuard.originalBytes, sizeof(response->originalBytes));
    RtlCopyMemory(response->hookBytes, gKswordArkBugcheckGuard.hookBytes, sizeof(response->hookBytes));
}

VOID
kswordArkBugcheckGuardInitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    RtlZeroMemory(&gKswordArkBugcheckGuard, sizeof(gKswordArkBugcheckGuard));
    ExInitializeFastMutex(&gKswordArkBugcheckGuard.controlLock);
    InterlockedExchange(
        &gKswordArkBugcheckGuard.hvciEnabled,
        kswordArkBugcheckGuardHvciEnabled() ? 1L : 0L);
    gKswordArkBugcheckGuard.lastStatus = STATUS_SUCCESS;
#endif
}

VOID
kswordArkBugcheckGuardUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    NTSTATUS status;

    ExAcquireFastMutex(&gKswordArkBugcheckGuard.controlLock);
    status = kswordArkBugcheckGuardReleaseMappingLocked();
    gKswordArkBugcheckGuard.lastStatus = status;
    ExReleaseFastMutex(&gKswordArkBugcheckGuard.controlLock);
#endif
}

NTSTATUS
kswordArkBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_GUARD_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;

    UNREFERENCED_PARAMETER(device);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    ExAcquireFastMutex(&gKswordArkBugcheckGuard.controlLock);
    if (input->size != sizeof(*input) ||
        input->version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION ||
        input->reserved0 != 0UL ||
        input->reserved1 != 0UL ||
        (input->flags & ~(KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED | KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR)) != 0UL) {
        gKswordArkBugcheckGuard.lastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY) {
        if (InterlockedCompareExchange(
                &gKswordArkBugcheckGuard.enabled,
                0L,
                0L) != 0L) {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
        }
        else if (InterlockedCompareExchange(
                    &gKswordArkBugcheckGuard.hookState,
                    0L,
                    0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ||
                 InterlockedCompareExchange(
                    &gKswordArkBugcheckGuard.hookExecutions,
                    0L,
                    0L) != 0L) {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
        }
        else {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE;
        }
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE) {
        status = kswordArkBugcheckGuardReleaseMappingLocked();
        gKswordArkBugcheckGuard.lastStatus = status;
        protocolStatus = NT_SUCCESS(status)
            ? KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE
            : KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE) {
        if ((input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken != KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN) {
            gKswordArkBugcheckGuard.lastStatus = STATUS_ACCESS_DENIED;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED;
        }
        else if (input->delaySeconds <
                    KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS) {
            gKswordArkBugcheckGuard.lastStatus = STATUS_INVALID_PARAMETER;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
        }
        else {
            status = kswordArkBugcheckGuardEnableLocked(
                input->delaySeconds,
                (input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR) != 0UL);
            gKswordArkBugcheckGuard.lastStatus = status;
            if (status == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED;
            }
            else if (status == STATUS_OBJECT_NAME_COLLISION) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT;
            }
            else if (status == STATUS_DEVICE_BUSY) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
            }
            else {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED;
            }
        }
    }
    else {
        gKswordArkBugcheckGuard.lastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }

    kswordArkBugcheckGuardFillResponse(output, protocolStatus);
    ExReleaseFastMutex(&gKswordArkBugcheckGuard.controlLock);
    *bytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
#endif
}
