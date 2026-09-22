/*++

Module Name:

    redirect_runtime.c

Abstract:

    Shared runtime for KswordARK file and registry redirection rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "redirect_internal.h"
#include "ark/ark_push_lock.h"

#include <stdarg.h>

static KswordArkRedirectRuntime gKswordArkRedirectRuntime;

KswordArkRedirectRuntime*
kswordArkRedirectGetRuntime(
    VOID
    )
/*++

Routine Description:

    Returns the global redirect runtime. Note: This pointer is only valid during the
    driver's lifetime; callers must still use Runtime->Lock to protect rule snapshot access.

Arguments:

    None.

Return Value:

    Pointer to the global KswordArkRedirectRuntime.

--*/
{
    return &gKswordArkRedirectRuntime;
}

VOID
kswordArkRedirectLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Write to the redirect module log. Note: Log failures do not alter redirect logic to
    avoid impacting I/O behavior due to log channel congestion in high-frequency paths.

Arguments:

    levelText - Log level string.
    FormatText: printf-style format string.
    ... - Format arguments.

Return Value:

    None. This function has no return value.

--*/
{
    KswordArkRedirectRuntime* runtime = kswordArkRedirectGetRuntime();
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    if (runtime == NULL || runtime->device == WDF_NO_HANDLE || formatText == NULL) {
        return;
    }

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(
            runtime->device,
            levelText != NULL ? levelText : "Info",
            logBuffer);
    }
    va_end(arguments);
}

ULONG
kswordArkRedirectCountRulesByTypeLocked(
    _In_ const KswordArkRedirectRuntime* runtime,
    _In_ ULONG type
    )
/*++

Routine Description:

    Count the number of enabled rules of the specified type. Note: The caller must hold Runtime->Lock; the function
    only iterates a fixed-size array and does not acquire locks itself to avoid redundant overhead on the hot path.

Arguments:

    Runtime - Redirect runtime.
    Type: KSWORD_ARK_REDIRECT_TYPE_* type.

Return Value:

    Count of rules matching the type and enabled.

--*/
{
    ULONG ruleIndex = 0UL;
    ULONG count = 0UL;

    if (runtime == NULL) {
        return 0UL;
    }

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_REDIRECT_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_REDIRECT_RULE* rule = &runtime->rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) != 0UL &&
            rule->type == type) {
            count += 1UL;
        }
    }

    return count;
}

BOOLEAN
kswordArkRedirectIsRulePathValid(
    _In_ const WCHAR* text,
    _In_ ULONG maxChars,
    _Out_ USHORT* lengthCharsOut
    )
/*++

Routine Description:

    Validate fixed-width character paths in the shared protocol. Note: Paths must be non-empty, NUL-terminated,
    and start with an NT namespace backslash to avoid ambiguity caused by R3 passing UI-style paths.

Arguments:

    Text: Base address of a fixed array.
    MaxChars - fixed array capacity.
    LengthCharsOut: Returns the character count excluding the NUL terminator.

Return Value:

    TRUE indicates the path is usable; FALSE indicates the path is invalid.

--*/
{
    ULONG charIndex = 0UL;

    if (lengthCharsOut == NULL) {
        return FALSE;
    }
    *lengthCharsOut = 0U;

    if (text == NULL || maxChars == 0UL || text[0] != L'\\') {
        return FALSE;
    }

    for (charIndex = 0UL; charIndex < maxChars; ++charIndex) {
        if (text[charIndex] == L'\0') {
            if (charIndex == 0UL || charIndex > 0x7FFFUL) {
                return FALSE;
            }
            *lengthCharsOut = (USHORT)charIndex;
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS
kswordArkRedirectCopyUnicodeToAllocatedString(
    _In_ const UNICODE_STRING* source,
    _Out_ UNICODE_STRING* destination,
    _In_ ULONG poolTag
    )
/*++

Routine Description:

    Copy UNICODE_STRING to non-paged pool. Note: Both file pre-create and registry pre-callbacks may need to
    temporarily store the target path; append an extra NUL during copy to facilitate debugging and logging.

Arguments:

    Source - Source string.
    Destination: target string; caller must free Buffer on success.
    PoolTag: Non-paged pool tag.

Return Value:

    STATUS_SUCCESS or parameter/memory error.

--*/
{
    SIZE_T allocateBytes = 0U;

    if (destination == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(destination, sizeof(*destination));

    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if (source->Length > (USHORT)(0xFFFEU - sizeof(WCHAR))) {
        return STATUS_NAME_TOO_LONG;
    }

    allocateBytes = (SIZE_T)source->Length + sizeof(WCHAR);
#pragma warning(push)
#pragma warning(disable:4996)
    destination->Buffer = (PWSTR)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        allocateBytes,
        poolTag);
#pragma warning(pop)
    if (destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(destination->Buffer, allocateBytes);
    RtlCopyMemory(destination->Buffer, source->Buffer, source->Length);
    destination->Length = source->Length;
    destination->MaximumLength = (USHORT)allocateBytes;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkRedirectPathMatchesRule(
    _In_ const KSWORD_ARK_REDIRECT_RULE* rule,
    _In_ const UNICODE_STRING* sourcePath
    )
/*++

Routine Description:

    Check if the path matches the rule. Note: EXACT uses case-insensitive equality; PREFIX
    uses RtlPrefixUnicodeString to maintain consistency with Windows path case semantics.

Arguments:

    Rule - Rule snapshot item.
    SourcePath - Current source path.

Return Value:

    TRUE indicates a match; FALSE indicates no match.

--*/
{
    UNICODE_STRING rulePath;
    USHORT ruleChars = 0U;

    if (rule == NULL || sourcePath == NULL || sourcePath->Buffer == NULL) {
        return FALSE;
    }
    if (!kswordArkRedirectIsRulePathValid(
        rule->sourcePath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &ruleChars)) {
        return FALSE;
    }

    rulePath.Buffer = (PWSTR)rule->sourcePath;
    rulePath.Length = (USHORT)(ruleChars * sizeof(WCHAR));
    rulePath.MaximumLength = rulePath.Length;

    if (rule->matchMode == KSWORD_ARK_REDIRECT_MATCH_EXACT) {
        return RtlEqualUnicodeString(&rulePath, sourcePath, TRUE) ? TRUE : FALSE;
    }
    if (rule->matchMode == KSWORD_ARK_REDIRECT_MATCH_PREFIX) {
        return RtlPrefixUnicodeString(&rulePath, sourcePath, TRUE) ? TRUE : FALSE;
    }

    return FALSE;
}

NTSTATUS
kswordArkRedirectFindMatchLocked(
    _In_ KswordArkRedirectRuntime* runtime,
    _In_ ULONG type,
    _In_ ULONG processId,
    _In_ const UNICODE_STRING* sourcePath,
    _Out_ KSWORD_ARK_REDIRECT_RULE* matchedRuleOut
    )
/*++

Routine Description:

    Find the first matching entry in the rule snapshot. Note: The caller must hold a shared or
    exclusive lock; rules are matched in R3 submission order to facilitate UI priority control.

Arguments:

    Runtime - Redirect runtime.
    Type - File or registry type.
    ProcessId: Current requesting process ID; 0 indicates an unknown system process.
    SourcePath - Current source path.
    MatchedRuleOut: Returns a copy of the matched rule.

Return Value:

    STATUS_SUCCESS indicates a match; STATUS_NOT_FOUND indicates no matching rule.

--*/
{
    ULONG ruleIndex = 0UL;

    if (runtime == NULL || sourcePath == NULL || matchedRuleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(matchedRuleOut, sizeof(*matchedRuleOut));

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_REDIRECT_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_REDIRECT_RULE* rule = &runtime->rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }
        if (rule->type != type || rule->action != KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
            continue;
        }
        if (rule->processId != 0UL && rule->processId != processId) {
            continue;
        }
        if (!kswordArkRedirectPathMatchesRule(rule, sourcePath)) {
            continue;
        }

        RtlCopyMemory(matchedRuleOut, rule, sizeof(*matchedRuleOut));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
kswordArkRedirectValidateRule(
    _In_ const KSWORD_ARK_REDIRECT_RULE* rule
    )
/*++

Routine Description:

    Validate a redirection rule. Note: Only file/registry replacement rules are accepted. Both source
    and target paths must be NT namespace paths, and the match mode must be 'exact' or 'prefix'.

Arguments:

    Rule - Rule to validate.

Return Value:

    STATUS_SUCCESS indicates the rule is allowed; a failure status indicates the rule is denied.

--*/
{
    USHORT sourceChars = 0U;
    USHORT targetChars = 0U;

    if (rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (rule->type != KSWORD_ARK_REDIRECT_TYPE_FILE &&
        rule->type != KSWORD_ARK_REDIRECT_TYPE_REGISTRY) {
        return STATUS_NOT_SUPPORTED;
    }
    if (rule->action != KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (rule->matchMode != KSWORD_ARK_REDIRECT_MATCH_EXACT &&
        rule->matchMode != KSWORD_ARK_REDIRECT_MATCH_PREFIX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkRedirectIsRulePathValid(
        rule->sourcePath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &sourceChars)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkRedirectIsRulePathValid(
        rule->targetPath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &targetChars)) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
kswordArkRedirectRefreshFlagsLocked(
    _Inout_ KswordArkRedirectRuntime* runtime
    )
/*++

Routine Description:

    Refresh runtime flags based on the number of rules. Note: The registry callback registration flag is
    retained; the enabled state for files and the registry is dynamically determined by the count of valid rules.

Arguments:

    Runtime - Redirect runtime.

Return Value:

    None. This function has no return value.

--*/
{
    ULONG registryHooked = 0UL;

    if (runtime == NULL) {
        return;
    }

    registryHooked = runtime->runtimeFlags & KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
    runtime->runtimeFlags = registryHooked;
    runtime->fileRuleCount = kswordArkRedirectCountRulesByTypeLocked(
        runtime,
        KSWORD_ARK_REDIRECT_TYPE_FILE);
    runtime->registryRuleCount = kswordArkRedirectCountRulesByTypeLocked(
        runtime,
        KSWORD_ARK_REDIRECT_TYPE_REGISTRY);

    if (runtime->fileRuleCount != 0UL) {
        runtime->runtimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_FILE_ACTIVE;
    }
    if (runtime->registryRuleCount != 0UL) {
        runtime->runtimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_ACTIVE;
    }
}

NTSTATUS
kswordArkRedirectInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ WDFDEVICE device
    )
/*++

Routine Description:

    initialize the redirect runtime. Note: The rule table is empty by default, and registry
    callbacks only take effect upon rule hits, so loading the driver does not alter system behavior.

Arguments:

    DriverObject - Driver object, used to register Cm callbacks.
    Device: WDF control device, used for logging.

Return Value:

    STATUS_SUCCESS or the status indicating failure to register the registry callback.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&gKswordArkRedirectRuntime, sizeof(gKswordArkRedirectRuntime));
    ExInitializePushLock(&gKswordArkRedirectRuntime.lock);
    gKswordArkRedirectRuntime.device = device;
    gKswordArkRedirectRuntime.registryRegisterStatus = STATUS_NOT_SUPPORTED;

    status = kswordArkRedirectRegistryRegister(
        &gKswordArkRedirectRuntime,
        driverObject);
    gKswordArkRedirectRuntime.registryRegisterStatus = status;
    if (NT_SUCCESS(status)) {
        gKswordArkRedirectRuntime.runtimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
        kswordArkRedirectLogFormat("Info", "Redirect registry callback registered.");
        return STATUS_SUCCESS;
    }

    kswordArkRedirectLogFormat(
        "Warn",
        "Redirect registry callback registration failed, status=0x%08X.",
        (unsigned int)status);
    return status;
}

VOID
kswordArkRedirectUninitialize(
    VOID
    )
/*++

Routine Description:

    Unload the redirect runtime. Note: Clear the rule table first, then unregister the
    Cm callback to prevent path substitution from occurring during the unloading window.

Arguments:

    None.

Return Value:

    None. This function has no return value.

--*/
{
    KswordArkRedirectRuntime* runtime = kswordArkRedirectGetRuntime();

    if (runtime == NULL) {
        return;
    }

    kswordArkAcquirePushLockExclusive(&runtime->lock);
    RtlZeroMemory(runtime->rules, sizeof(runtime->rules));
    runtime->fileRuleCount = 0UL;
    runtime->registryRuleCount = 0UL;
    runtime->runtimeFlags &= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
    runtime->generation += 1UL;
    kswordArkReleasePushLockExclusive(&runtime->lock);

    kswordArkRedirectRegistryUnregister(runtime);
    runtime->runtimeFlags = 0UL;
    runtime->registryRegisterStatus = STATUS_NOT_SUPPORTED;
}

NTSTATUS
kswordArkRedirectSetRules(
    _In_ const KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Replace or clear the redirect rule snapshot. Note: The function fully validates input first, then
    atomically switches the rule table to avoid callback paths observing a partially updated state.

Arguments:

    Request: R3 rule request.
    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates the response has been written; buffer errors return failure directly.

--*/
{
    KswordArkRedirectRuntime* runtime = kswordArkRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE* response = NULL;
    KSWORD_ARK_REDIRECT_RULE newRules[KSWORD_ARK_REDIRECT_MAX_RULES] = { 0 };
    ULONG ruleIndex = 0UL;
    ULONG appliedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_REDIRECT_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REDIRECT_STATUS_UNKNOWN;
    response->rejectedIndex = 0xFFFFFFFFUL;
    response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REDIRECT_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_OPERATION_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    if (request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        if (request->ruleCount > KSWORD_ARK_REDIRECT_MAX_RULES) {
            response->status = KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }

        for (ruleIndex = 0UL; ruleIndex < request->ruleCount; ++ruleIndex) {
            status = kswordArkRedirectValidateRule(&request->rules[ruleIndex]);
            if (!NT_SUCCESS(status)) {
                response->status = (status == STATUS_NOT_SUPPORTED) ?
                    KSWORD_ARK_REDIRECT_STATUS_UNSUPPORTED_TYPE :
                    KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
                response->rejectedIndex = ruleIndex;
                response->lastStatus = status;
                return STATUS_SUCCESS;
            }
            RtlCopyMemory(&newRules[ruleIndex], &request->rules[ruleIndex], sizeof(newRules[ruleIndex]));
            if ((newRules[ruleIndex].flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) != 0UL) {
                appliedCount += 1UL;
            }
        }
    }
    else if (request->action != KSWORD_ARK_REDIRECT_ACTION_CLEAR &&
        request->action != KSWORD_ARK_REDIRECT_ACTION_DISABLE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    kswordArkAcquirePushLockExclusive(&runtime->lock);
    RtlZeroMemory(runtime->rules, sizeof(runtime->rules));
    if (request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE && appliedCount != 0UL) {
        RtlCopyMemory(runtime->rules, newRules, sizeof(newRules));
    }
    runtime->generation += 1UL;
    kswordArkRedirectRefreshFlagsLocked(runtime);
    response->runtimeFlags = runtime->runtimeFlags;
    response->fileRuleCount = runtime->fileRuleCount;
    response->registryRuleCount = runtime->registryRuleCount;
    response->generation = runtime->generation;
    kswordArkReleasePushLockExclusive(&runtime->lock);

    response->appliedCount = appliedCount;
    if (request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_APPLIED;
    }
    else if (request->action == KSWORD_ARK_REDIRECT_ACTION_DISABLE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_DISABLED;
    }
    else {
        response->status = KSWORD_ARK_REDIRECT_STATUS_CLEARED;
    }
    response->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkRedirectQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the redirect runtime status. Note: Returns the current rule snapshot,
    hit count, and Cm callback registration status for subsequent R3 UI display.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS or buffer error.

--*/
{
    KswordArkRedirectRuntime* runtime = kswordArkRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_STATUS_RESPONSE* response = NULL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_REDIRECT_STATUS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_REDIRECT_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REDIRECT_STATUS_APPLIED;

    kswordArkAcquirePushLockShared(&runtime->lock);
    response->runtimeFlags = runtime->runtimeFlags;
    response->fileRuleCount = runtime->fileRuleCount;
    response->registryRuleCount = runtime->registryRuleCount;
    response->generation = runtime->generation;
    response->fileRedirectHits = (ULONG64)runtime->fileRedirectHits;
    response->registryRedirectHits = (ULONG64)runtime->registryRedirectHits;
    response->registryRegisterStatus = runtime->registryRegisterStatus;
    RtlCopyMemory(response->rules, runtime->rules, sizeof(response->rules));
    kswordArkReleasePushLockShared(&runtime->lock);

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
