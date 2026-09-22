/*++

Module Name:

    process_protect_runtime.c

Abstract:

    Handle-callback based process protection runtime. The object manager
    pre-operation callback funnels every process/thread handle create and
    duplicate through this module; matching targets get the dangerous access
    bits stripped from DesiredAccess before the handle is granted.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_protect_internal.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

static EX_PUSH_LOCK gKswordArkProcessProtectPublishLock;
static KswordArkProcessProtectState* gKswordArkProcessProtectState = NULL;

KswordArkProcessProtectState*
kswordArkProcessProtectGetState(
    VOID
    )
{
    return gKswordArkProcessProtectState;
}

VOID
kswordArkProcessProtectLogFormat(
    _In_ KswordArkProcessProtectState* state,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argumentList;

    if (state == NULL || state->device == WDF_NO_HANDLE) {
        return;
    }

    va_start(argumentList, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, argumentList))) {
        (VOID)kswordArkDriverEnqueueLogFrame(state->device, levelText, logBuffer);
    }
    va_end(argumentList);
}

VOID
kswordArkProcessProtectCopyFixedWideText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
{
    size_t sourceChars = 0;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(source, destinationChars, &sourceChars))) {
        sourceChars = (size_t)destinationChars - 1U;
    }
    if (sourceChars >= (size_t)destinationChars) {
        sourceChars = (size_t)destinationChars - 1U;
    }
    if (sourceChars != 0U) {
        RtlCopyMemory(destination, source, sourceChars * sizeof(WCHAR));
    }
    destination[sourceChars] = L'\0';
}

static SIZE_T
kswordArkProcessProtectTextLength(
    _In_opt_z_ PCWSTR text,
    _In_ SIZE_T maxChars
    )
{
    size_t textChars = 0;

    if (text == NULL || maxChars == 0U) {
        return 0U;
    }
    if (!NT_SUCCESS(RtlStringCchLengthW(text, maxChars, &textChars))) {
        return maxChars;
    }
    return (SIZE_T)textChars;
}

static BOOLEAN
kswordArkProcessProtectCharEquals(
    _In_ WCHAR leftChar,
    _In_ WCHAR rightChar
    )
{
    return (RtlUpcaseUnicodeChar(leftChar) == RtlUpcaseUnicodeChar(rightChar)) ? TRUE : FALSE;
}

static PCWSTR
kswordArkProcessProtectFindFileName(
    _In_opt_z_ PCWSTR pathText,
    _In_ SIZE_T pathChars
    )
/*++

Routine Description:

    Return the trailing file-name component of a path. Both NT paths
    (\Device\HarddiskVolume3\Windows\notepad.exe) and Win32 paths
    (C:\Windows\notepad.exe) use backslash, so one scan covers both.

--*/
{
    SIZE_T scanIndex = 0;
    PCWSTR fileNameText = pathText;

    if (pathText == NULL) {
        return NULL;
    }

    for (scanIndex = 0; scanIndex < pathChars; ++scanIndex) {
        if (pathText[scanIndex] == L'\\' || pathText[scanIndex] == L'/') {
            fileNameText = &pathText[scanIndex + 1U];
        }
    }
    return fileNameText;
}

static BOOLEAN
kswordArkProcessProtectImageNameMatch(
    _In_opt_z_ PCWSTR patternText,
    _In_opt_z_ PCWSTR imagePathText
    )
{
    SIZE_T patternChars = kswordArkProcessProtectTextLength(patternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T imageChars = kswordArkProcessProtectTextLength(imagePathText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    PCWSTR imageFileName = NULL;
    SIZE_T fileNameChars = 0;
    SIZE_T compareIndex = 0;

    if (patternChars == 0U || imageChars == 0U) {
        return FALSE;
    }

    // Rules may also specify full paths; only the final filename segment is compared.
    patternText = kswordArkProcessProtectFindFileName(patternText, patternChars);
    patternChars = kswordArkProcessProtectTextLength(patternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);

    imageFileName = kswordArkProcessProtectFindFileName(imagePathText, imageChars);
    fileNameChars = kswordArkProcessProtectTextLength(imageFileName, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);

    if (patternChars == 0U || patternChars != fileNameChars) {
        return FALSE;
    }

    for (compareIndex = 0; compareIndex < patternChars; ++compareIndex) {
        if (!kswordArkProcessProtectCharEquals(patternText[compareIndex], imageFileName[compareIndex])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
kswordArkProcessProtectImagePathMatch(
    _In_opt_z_ PCWSTR patternText,
    _In_opt_z_ PCWSTR imagePathText
    )
/*++

Routine Description:

    Case-insensitive suffix match between a configured path and the resolved
    image path. R0 sees NT paths while R3 usually stores Win32 paths, so a
    leading drive specifier is dropped from the pattern first; the remainder
    (\Windows\notepad.exe) is then matched against the tail of the NT path.

--*/
{
    SIZE_T patternChars = kswordArkProcessProtectTextLength(patternText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T imageChars = kswordArkProcessProtectTextLength(imagePathText, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
    SIZE_T suffixStart = 0;
    SIZE_T compareIndex = 0;

    if (patternChars == 0U || imageChars == 0U) {
        return FALSE;
    }

    // Remove the 'C:' drive letter prefix so that Win32 paths can also match the end of NT paths.
    if (patternChars > 2U && patternText[1] == L':') {
        patternText += 2;
        patternChars -= 2U;
    }

    if (patternChars == 0U || patternChars > imageChars) {
        return FALSE;
    }

    suffixStart = imageChars - patternChars;
    for (compareIndex = 0; compareIndex < patternChars; ++compareIndex) {
        if (!kswordArkProcessProtectCharEquals(
                patternText[compareIndex],
                imagePathText[suffixStart + compareIndex])) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN
kswordArkProcessProtectIdentityMatchPublic(
    _In_ ULONG targetKind,
    _In_ ULONG configuredProcessId,
    _In_opt_z_ PCWSTR configuredImage,
    _In_ ULONG candidateProcessId,
    _In_opt_z_ PCWSTR candidateImagePath
    )
{
    switch (targetKind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (configuredProcessId != 0UL && configuredProcessId == candidateProcessId) ? TRUE : FALSE;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
        return kswordArkProcessProtectImageNameMatch(configuredImage, candidateImagePath);

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return kswordArkProcessProtectImagePathMatch(configuredImage, candidateImagePath);

    default:
        return FALSE;
    }
}

static ACCESS_MASK
kswordArkProcessProtectBuildProcessStripMask(
    _In_ ULONG protectAccessMask
    )
{
    ACCESS_MASK stripMask = 0U;

    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0UL) {
        stripMask |= PROCESS_TERMINATE;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0UL) {
        stripMask |= PROCESS_VM_READ;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0UL) {
        stripMask |= (PROCESS_VM_OPERATION | PROCESS_VM_WRITE);
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD) != 0UL) {
        stripMask |= PROCESS_CREATE_THREAD;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0UL) {
        stripMask |= PROCESS_SUSPEND_RESUME;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0UL) {
        stripMask |= (PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | WRITE_DAC | WRITE_OWNER);
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE) != 0UL) {
        stripMask |= PROCESS_DUP_HANDLE;
    }
    return stripMask;
}

static ACCESS_MASK
kswordArkProcessProtectBuildThreadStripMask(
    _In_ ULONG protectAccessMask
    )
/*++

Routine Description:

    Project the same protection switches onto thread handles. CREATE_THREAD and
    DUP_HANDLE have no thread-object counterpart and are intentionally dropped;
    direct impersonation is grouped with VM_WRITE because both let the caller
    take over thread execution.

--*/
{
    ACCESS_MASK stripMask = 0U;

    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0UL) {
        stripMask |= THREAD_TERMINATE;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0UL) {
        stripMask |= THREAD_GET_CONTEXT;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0UL) {
        stripMask |= (THREAD_SET_CONTEXT | THREAD_DIRECT_IMPERSONATION);
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0UL) {
        stripMask |= THREAD_SUSPEND_RESUME;
    }
    if ((protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0UL) {
        stripMask |= (THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | WRITE_DAC | WRITE_OWNER);
    }
    return stripMask;
}

static VOID
kswordArkProcessProtectRecordLastBlocked(
    _Inout_ KswordArkProcessProtectState* state,
    _In_ BOOLEAN targetIsThreadObject,
    _In_ ULONG initiatorProcessId,
    _In_ ULONG targetProcessId,
    _In_ ULONG ruleId,
    _In_ ACCESS_MASK originalAccess,
    _In_ ACCESS_MASK grantedAccess,
    _In_opt_z_ PCWSTR initiatorImagePath,
    _In_opt_z_ PCWSTR targetImagePath
    )
{
    LARGE_INTEGER nowUtc = { 0 };

    KeQuerySystemTimePrecise(&nowUtc);

    kswordArkAcquirePushLockExclusive(&state->lastBlockedLock);
    state->lastBlockedUtc100ns = nowUtc;
    state->lastBlockedInitiatorPid = initiatorProcessId;
    state->lastBlockedTargetPid = targetProcessId;
    state->lastBlockedRuleId = ruleId;
    state->lastBlockedOriginalAccess = (ULONG)originalAccess;
    state->lastBlockedGrantedAccess = (ULONG)grantedAccess;
    state->lastBlockedIsThreadObject = targetIsThreadObject ? 1UL : 0UL;
    kswordArkProcessProtectCopyFixedWideText(
        state->lastBlockedInitiatorImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        initiatorImagePath);
    kswordArkProcessProtectCopyFixedWideText(
        state->lastBlockedTargetImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        targetImagePath);
    kswordArkReleasePushLockExclusive(&state->lastBlockedLock);
}

BOOLEAN
kswordArkProcessProtectFilterHandleOperation(
    _In_ BOOLEAN targetIsThreadObject,
    _In_opt_ PEPROCESS targetProcess,
    _In_opt_z_ PCWSTR targetImagePath,
    _In_opt_z_ PCWSTR initiatorImagePath,
    _Inout_ ACCESS_MASK* desiredAccess
    )
/*++

Routine Description:

    Evaluate one process/thread handle operation against the protection config
    and strip the configured access bits in place.

Arguments:

    TargetIsThreadObject - TRUE when the opened object is a thread.
    TargetProcess - Target process, or the thread's host process. May be NULL.
    TargetImagePath - Caller-resolved target image path. May be NULL or empty.
    InitiatorImagePath - Caller-resolved requestor image path.
    DesiredAccess - Object manager access mask, modified in place on a hit.

Return Value:

    TRUE when at least one access bit was removed.

--*/
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();
    PEPROCESS initiatorProcess = PsGetCurrentProcess();
    ULONG initiatorProcessId = HandleToULong(PsGetCurrentProcessId());
    ULONG targetProcessId = 0UL;
    ULONG globalFlags = 0UL;
    ULONG matchedRuleId = 0UL;
    ULONG matchedRuleIndex = 0UL;
    ULONG ruleIndex = 0UL;
    ACCESS_MASK stripMask = 0U;
    ACCESS_MASK originalAccess = 0U;
    ACCESS_MASK grantedAccess = 0U;
    BOOLEAN trustedInitiator = FALSE;
    BOOLEAN matched = FALSE;
    BOOLEAN logBlocked = FALSE;

    if (state == NULL || desiredAccess == NULL) {
        return FALSE;
    }

    // A protected process opening itself must always be allowed; otherwise, the protected process cannot even obtain its own handle.
    if (targetProcess != NULL && targetProcess == initiatorProcess) {
        return FALSE;
    }

    if (targetProcess != NULL) {
        targetProcessId = HandleToULong(PsGetProcessId(targetProcess));
    }

    kswordArkAcquirePushLockShared(&state->configLock);

    globalFlags = state->globalFlags;
    if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) == 0UL ||
        state->ruleCount == 0UL) {
        kswordArkReleasePushLockShared(&state->configLock);
        return FALSE;
    }

    (VOID)InterlockedIncrement64(&state->evaluatedCount);

    // System and Idle processes handle process creation and exit cleanup; they are trusted by default. Disabling this switch is a high-risk configuration.
    if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM) != 0UL &&
        initiatorProcessId <= 4UL) {
        trustedInitiator = TRUE;
    }

    for (ruleIndex = 0UL; !trustedInitiator && ruleIndex < state->trustedCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_TRUSTED* trustedEntry = &state->trusted[ruleIndex];
        if ((trustedEntry->flags & KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED) == 0UL) {
            continue;
        }
        if (kswordArkProcessProtectIdentityMatchPublic(
                trustedEntry->kind,
                trustedEntry->processId,
                trustedEntry->image,
                initiatorProcessId,
                initiatorImagePath)) {
            trustedInitiator = TRUE;
        }
    }

    for (ruleIndex = 0UL; ruleIndex < state->ruleCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_RULE* protectRule = &state->rules[ruleIndex];

        if ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }

        // Protected process mutual trust: if the initiator is also on this list, the entire request is allowed without checking which rule the target matches.
        if ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) != 0UL &&
            kswordArkProcessProtectIdentityMatchPublic(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                initiatorProcessId,
                initiatorImagePath)) {
            trustedInitiator = TRUE;
            break;
        }

        if (!matched &&
            (!targetIsThreadObject ||
                (protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS) != 0UL) &&
            kswordArkProcessProtectIdentityMatchPublic(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                targetProcessId,
                targetImagePath)) {
            matched = TRUE;
            matchedRuleId = protectRule->ruleId;
            matchedRuleIndex = ruleIndex;
            stripMask = targetIsThreadObject
                ? kswordArkProcessProtectBuildThreadStripMask(protectRule->protectAccessMask)
                : kswordArkProcessProtectBuildProcessStripMask(protectRule->protectAccessMask);
        }

        // Handle creation is a hot path: terminate immediately when the target is matched and there is no need to continue searching for trusted initiators.
        if (matched &&
            (globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) == 0UL) {
            break;
        }
    }

    logBlocked = ((globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED) != 0UL) ? TRUE : FALSE;
    kswordArkReleasePushLockShared(&state->configLock);

    if (trustedInitiator) {
        (VOID)InterlockedIncrement64(&state->trustedBypassCount);
        return FALSE;
    }

    if (!matched || stripMask == 0U) {
        return FALSE;
    }

    originalAccess = *desiredAccess;
    grantedAccess = originalAccess & (~stripMask);
    if (grantedAccess == originalAccess) {
        return FALSE;
    }

    *desiredAccess = grantedAccess;
    (VOID)InterlockedIncrement64(&state->strippedCount);
    (VOID)InterlockedIncrement64(&state->ruleHitCounts[matchedRuleIndex]);
    kswordArkProcessProtectRecordLastBlocked(
        state,
        targetIsThreadObject,
        initiatorProcessId,
        targetProcessId,
        matchedRuleId,
        originalAccess,
        grantedAccess,
        initiatorImagePath,
        targetImagePath);

    if (logBlocked) {
        kswordArkProcessProtectLogFormat(
            state,
            "Warn",
            "Process protection stripped access, object=%s, initiatorPid=%lu, targetPid=%lu, "
            "ruleId=%lu, desired=0x%08lX->0x%08lX.",
            targetIsThreadObject ? "Thread" : "Process",
            (unsigned long)initiatorProcessId,
            (unsigned long)targetProcessId,
            (unsigned long)matchedRuleId,
            (unsigned long)originalAccess,
            (unsigned long)grantedAccess);
    }
    return TRUE;
}

VOID
kswordArkProcessProtectNoteObjectCallbackState(
    _In_ BOOLEAN registered,
    _In_ NTSTATUS registerStatus
    )
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();

    if (state == NULL) {
        return;
    }

    (VOID)InterlockedExchange(&state->objectCallbackRegistered, registered ? 1L : 0L);
    (VOID)InterlockedExchange(&state->objectCallbackStatus, (LONG)registerStatus);
}

NTSTATUS
kswordArkProcessProtectInitialize(
    _In_ WDFDEVICE device
    )
{
    KswordArkProcessProtectState* state = NULL;

    if (device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkAcquirePushLockExclusive(&gKswordArkProcessProtectPublishLock);
    if (gKswordArkProcessProtectState != NULL) {
        kswordArkReleasePushLockExclusive(&gKswordArkProcessProtectPublishLock);
        return STATUS_SUCCESS;
    }

    state = (KswordArkProcessProtectState*)kswordArkAllocateNonPaged(
        sizeof(KswordArkProcessProtectState),
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    if (state == NULL) {
        kswordArkReleasePushLockExclusive(&gKswordArkProcessProtectPublishLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(state, sizeof(*state));
    state->device = device;
    ExInitializePushLock(&state->configLock);
    ExInitializePushLock(&state->lastBlockedLock);
    ExInitializePushLock(&state->trackedLock);
    ExInitializePushLock(&state->lastTamperLock);
    KeInitializeEvent(&state->scanWakeEvent, NotificationEvent, FALSE);
    // Trust System by default to avoid revoking permissions on system cleanup paths before the user configures the whitelist.
    state->globalFlags = KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM;
    state->scanIntervalMs = KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;
    state->objectCallbackStatus = (LONG)STATUS_NOT_SUPPORTED;

    gKswordArkProcessProtectState = state;
    kswordArkReleasePushLockExclusive(&gKswordArkProcessProtectPublishLock);

    // The inspection thread is resident but idles according to configuration; this avoids restarting the thread when R3 enables self-healing.
    // If the scan fails, only disable self-healing; handle handle privilege reduction and creation-time enforcement as usual.
    {
        const NTSTATUS kScanStatus = kswordArkProcessProtectKernelStart(state);
        if (!NT_SUCCESS(kScanStatus)) {
            kswordArkProcessProtectLogFormat(
                state,
                "Warn",
                "Process protection self-heal scan thread unavailable, status=0x%08lX.",
                (unsigned long)kScanStatus);
        }
    }
    return STATUS_SUCCESS;
}

VOID
kswordArkProcessProtectUninitialize(
    VOID
    )
{
    KswordArkProcessProtectState* state = NULL;

    kswordArkAcquirePushLockExclusive(&gKswordArkProcessProtectPublishLock);
    state = gKswordArkProcessProtectState;
    gKswordArkProcessProtectState = NULL;
    kswordArkReleasePushLockExclusive(&gKswordArkProcessProtectPublishLock);

    if (state != NULL) {
        // Must wait for the inspection thread to exit first: it holds the state pointer, and a global abort cannot stop a round already in progress.
        kswordArkProcessProtectKernelStop(state);
        ExFreePoolWithTag(state, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
}

static NTSTATUS
kswordArkProcessProtectValidateRule(
    _In_ const KSWORD_ARK_PROCESS_PROTECT_RULE* rule
    )
{
    if ((rule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL) {
        // Disabled rules are R3 draft entries; only length trimming is performed, with no semantic validation.
        return STATUS_SUCCESS;
    }

    // An enabled rule must perform at least one action: privilege reduction, or applying kernel PP/PPL.
    if ((rule->protectAccessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL) == 0UL &&
        rule->kernelProtection == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (rule->kernelProtection != 0UL) {
        const ULONG kProtectionType = rule->kernelProtection & 0x07UL;
        const ULONG kSignerType = (rule->kernelProtection & 0xF0UL) >> 4U;
        if (rule->kernelProtection > 0xFFUL ||
            (kProtectionType != KSWORD_PS_PROTECTED_TYPE_LIGHT &&
             kProtectionType != KSWORD_PS_PROTECTED_TYPE_FULL) ||
            kSignerType == 0UL ||
            kSignerType > KSWORD_PS_PROTECTED_SIGNER_APP_VALUE) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    switch (rule->targetKind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (rule->targetProcessId != 0UL) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return (rule->targetImage[0] != L'\0') ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS
kswordArkProcessProtectValidateTrusted(
    _In_ const KSWORD_ARK_PROCESS_PROTECT_TRUSTED* trusted
    )
{
    if ((trusted->flags & KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }

    switch (trusted->kind) {
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
        return (trusted->processId != 0UL) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
    case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
        return (trusted->image[0] != L'\0') ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS
kswordArkProcessProtectIoctlSetConfig(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    )
/*++

Routine Description:

    Validate and install one complete protection configuration. The packet is a
    full replacement: whatever is absent from it stops being protected.

--*/
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();
    const KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0U;
    LARGE_INTEGER nowUtc = { 0 };
    ULONG64 appliedConfigVersion = 0ULL;
    ULONG entryIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (state == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (inputBufferLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacket = (const KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST*)inputBuffer;
    if (requestPacket->size < sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST) ||
        requestPacket->version != KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION ||
        requestPacket->ruleCount > KSWORD_ARK_PROCESS_PROTECT_MAX_RULES ||
        requestPacket->trustedCount > KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkAcquirePushLockExclusive(&state->configLock);

    RtlZeroMemory(state->rules, sizeof(state->rules));
    RtlZeroMemory(state->trusted, sizeof(state->trusted));

    for (entryIndex = 0UL; entryIndex < requestPacket->ruleCount; ++entryIndex) {
        KSWORD_ARK_PROCESS_PROTECT_RULE* targetRule = &state->rules[entryIndex];

        *targetRule = requestPacket->rules[entryIndex];
        // Strings from R3 may lack a terminator; truncate first, then validate. All subsequent comparisons assume NUL termination.
        targetRule->targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
        targetRule->ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U] = L'\0';
        targetRule->protectAccessMask &= KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL;
        targetRule->hardenFlags &= KSWORD_ARK_PROCESS_PROTECT_HARDEN_ALL;
        if (targetRule->targetKind != KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) {
            targetRule->targetProcessId = 0UL;
        }

        status = kswordArkProcessProtectValidateRule(targetRule);
        if (!NT_SUCCESS(status)) {
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        for (entryIndex = 0UL; entryIndex < requestPacket->trustedCount; ++entryIndex) {
            KSWORD_ARK_PROCESS_PROTECT_TRUSTED* targetTrusted = &state->trusted[entryIndex];

            *targetTrusted = requestPacket->trusted[entryIndex];
            targetTrusted->image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
            if (targetTrusted->kind != KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) {
                targetTrusted->processId = 0UL;
            }

            status = kswordArkProcessProtectValidateTrusted(targetTrusted);
            if (!NT_SUCCESS(status)) {
                break;
            }
        }
    }

    if (!NT_SUCCESS(status)) {
        // On validation failure, do not retain a partial table: roll back entirely to "no rules" for safety rather than leaving a corrupted configuration.
        RtlZeroMemory(state->rules, sizeof(state->rules));
        RtlZeroMemory(state->trusted, sizeof(state->trusted));
        state->ruleCount = 0UL;
        state->trustedCount = 0UL;
        kswordArkReleasePushLockExclusive(&state->configLock);
        kswordArkProcessProtectLogFormat(
            state,
            "Warn",
            "Process protection config rejected, status=0x%08lX.",
            (unsigned long)status);
        return status;
    }

    KeQuerySystemTimePrecise(&nowUtc);
    state->globalFlags = requestPacket->globalFlags;
    state->ruleCount = requestPacket->ruleCount;
    state->trustedCount = requestPacket->trustedCount;
    state->scanIntervalMs =
        (requestPacket->scanIntervalMs >= KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS &&
         requestPacket->scanIntervalMs <= KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS)
        ? requestPacket->scanIntervalMs
        : KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;
    state->configVersion += 1ULL;
    state->appliedAtUtc100ns = nowUtc;
    // The rule table has been completely replaced; old hit counts no longer correspond to any row. Clear them individually rather than using a bulk memset:
    // RuleHitCounts is a volatile array; clearing it in one block requires discarding the volatile qualifier.
    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++entryIndex) {
        state->ruleHitCounts[entryIndex] = 0LL;
    }
    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++entryIndex) {
        state->ruleKernelApplyCounts[entryIndex] = 0LL;
    }
    appliedConfigVersion = state->configVersion;

    kswordArkReleasePushLockExclusive(&state->configLock);

    // The expected values in the ledger come from the old rule table; after switching tables, they must be invalidated to prevent self-healing based on deleted rules.
    kswordArkProcessProtectKernelResetTracking(state);
    // Immediately wake the inspection thread so that new configurations take effect in the current cycle, rather than waiting for the next one.
    KeSetEvent(&state->scanWakeEvent, IO_NO_INCREMENT, FALSE);
    KeClearEvent(&state->scanWakeEvent);

    kswordArkProcessProtectLogFormat(
        state,
        "Info",
        "Process protection config applied, enabled=%lu, rules=%lu, trusted=%lu, version=%I64u.",
        (unsigned long)((requestPacket->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0UL ? 1UL : 0UL),
        (unsigned long)requestPacket->ruleCount,
        (unsigned long)requestPacket->trustedCount,
        (unsigned long long)appliedConfigVersion);

    *completeBytesOut = sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessProtectIoctlQueryState(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();
    KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE* responsePacket = NULL;
    size_t outputLength = 0U;
    ULONG entryIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (state == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (outputBufferLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE),
        (PVOID*)&responsePacket,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outputLength < sizeof(KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(responsePacket, sizeof(*responsePacket));
    responsePacket->size = sizeof(*responsePacket);
    responsePacket->version = KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION;

    kswordArkAcquirePushLockShared(&state->configLock);
    responsePacket->globalFlags = state->globalFlags;
    responsePacket->ruleCount = state->ruleCount;
    responsePacket->trustedCount = state->trustedCount;
    responsePacket->scanIntervalMs = state->scanIntervalMs;
    responsePacket->configVersion = (unsigned long long)state->configVersion;
    responsePacket->appliedAtUtc100ns = (unsigned long long)state->appliedAtUtc100ns.QuadPart;
    RtlCopyMemory(responsePacket->rules, state->rules, sizeof(responsePacket->rules));
    RtlCopyMemory(responsePacket->trusted, state->trusted, sizeof(responsePacket->trusted));
    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++entryIndex) {
        responsePacket->ruleHitCounts[entryIndex] =
            (unsigned long long)state->ruleHitCounts[entryIndex];
        responsePacket->ruleKernelApplyCounts[entryIndex] =
            (unsigned long long)state->ruleKernelApplyCounts[entryIndex];
    }
    kswordArkReleasePushLockShared(&state->configLock);

    kswordArkAcquirePushLockShared(&state->trackedLock);
    responsePacket->trackedProcessCount = state->trackedCount;
    kswordArkReleasePushLockShared(&state->trackedLock);

    responsePacket->objectCallbackStatus = (long)InterlockedCompareExchange(&state->objectCallbackStatus, 0L, 0L);
    responsePacket->capabilityStatus =
        (InterlockedCompareExchange(&state->objectCallbackRegistered, 0L, 0L) != 0L)
        ? KSWORD_ARK_PROCESS_PROTECT_STATUS_ACTIVE
        : KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE;

    responsePacket->evaluatedCount = (unsigned long long)InterlockedCompareExchange64(&state->evaluatedCount, 0LL, 0LL);
    responsePacket->strippedCount = (unsigned long long)InterlockedCompareExchange64(&state->strippedCount, 0LL, 0LL);
    responsePacket->trustedBypassCount = (unsigned long long)InterlockedCompareExchange64(&state->trustedBypassCount, 0LL, 0LL);

    kswordArkAcquirePushLockShared(&state->lastBlockedLock);
    responsePacket->lastBlockedUtc100ns = (unsigned long long)state->lastBlockedUtc100ns.QuadPart;
    responsePacket->lastBlockedInitiatorPid = state->lastBlockedInitiatorPid;
    responsePacket->lastBlockedTargetPid = state->lastBlockedTargetPid;
    responsePacket->lastBlockedRuleId = state->lastBlockedRuleId;
    responsePacket->lastBlockedOriginalAccess = state->lastBlockedOriginalAccess;
    responsePacket->lastBlockedGrantedAccess = state->lastBlockedGrantedAccess;
    responsePacket->lastBlockedIsThreadObject = state->lastBlockedIsThreadObject;
    kswordArkProcessProtectCopyFixedWideText(
        responsePacket->lastBlockedInitiatorImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        state->lastBlockedInitiatorImage);
    kswordArkProcessProtectCopyFixedWideText(
        responsePacket->lastBlockedTargetImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        state->lastBlockedTargetImage);
    kswordArkReleasePushLockShared(&state->lastBlockedLock);

    responsePacket->kernelApplyCount =
        (unsigned long long)InterlockedCompareExchange64(&state->kernelApplyCount, 0LL, 0LL);
    responsePacket->selfHealCount =
        (unsigned long long)InterlockedCompareExchange64(&state->selfHealCount, 0LL, 0LL);
    responsePacket->kernelApplyFailureCount =
        (unsigned long long)InterlockedCompareExchange64(&state->kernelApplyFailureCount, 0LL, 0LL);
    responsePacket->hardenApplyCount =
        (unsigned long long)InterlockedCompareExchange64(&state->hardenApplyCount, 0LL, 0LL);
    responsePacket->lastKernelApplyStatus =
        (long)InterlockedCompareExchange(&state->lastKernelApplyStatus, 0L, 0L);

    kswordArkAcquirePushLockShared(&state->lastTamperLock);
    responsePacket->lastTamperUtc100ns = (unsigned long long)state->lastTamperUtc100ns.QuadPart;
    responsePacket->lastTamperProcessId = state->lastTamperProcessId;
    responsePacket->lastTamperObservedProtection = state->lastTamperObservedProtection;
    responsePacket->lastTamperExpectedProtection = state->lastTamperExpectedProtection;
    responsePacket->lastTamperRuleId = state->lastTamperRuleId;
    kswordArkProcessProtectCopyFixedWideText(
        responsePacket->lastTamperImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        state->lastTamperImage);
    kswordArkReleasePushLockShared(&state->lastTamperLock);

    *completeBytesOut = sizeof(*responsePacket);
    return STATUS_SUCCESS;
}
