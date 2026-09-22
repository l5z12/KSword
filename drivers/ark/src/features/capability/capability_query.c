/*++

Module Name:

    capability_query.c

Abstract:

    Unified Phase 1 driver capability and status query implementation.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_capability.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_dyndata.h"
#include "ark/ark_safety.h"

#include <ntstrsafe.h>

#define KSW_CAPABILITY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) - sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY))

typedef struct KswCapLastError
{
    NTSTATUS status;
    CHAR source[KSWORD_ARK_CAPABILITY_ERROR_SOURCE_CHARS];
    CHAR summary[KSWORD_ARK_CAPABILITY_ERROR_SUMMARY_CHARS];
} KswCapLastError, *PkswCapLastError;

typedef struct KswCapFeatureTemplate
{
    ULONG featureId;
    PCSTR featureName;
    ULONG flags;
    ULONG requiredPolicyFlags;
    ULONG64 requiredDynDataMask;
    PCSTR dependencyText;
} KswCapFeatureTemplate, *PkswCapFeatureTemplate;

static EX_PUSH_LOCK gKswordArkCapabilityErrorLock;
static KswCapLastError gKswordArkLastCapabilityError;

static const KswCapFeatureTemplate kGKswordArkFeatureTemplates[] = {
    { KSWORD_ARK_FEATURE_ID_DRIVER_HEALTH, "Driver health", KSWORD_ARK_FEATURE_FLAG_READ_ONLY, 0UL, 0ULL, "Driver loaded + protocol response" },
    { KSWORD_ARK_FEATURE_ID_PROCESS_BASIC_ACTIONS, "Process basic actions", KSWORD_ARK_FEATURE_FLAG_MUTATING | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS, 0ULL, "Policy allows mutating process actions" },
    { KSWORD_ARK_FEATURE_ID_FILE_DELETE, "File delete", KSWORD_ARK_FEATURE_FLAG_MUTATING | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_ALLOW_FILE_DELETE, 0ULL, "Policy allows file delete" },
    { KSWORD_ARK_FEATURE_ID_SSDT_SNAPSHOT, "SSDT snapshot", KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY | KSWORD_ARK_FEATURE_FLAG_READ_ONLY | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS, 0ULL, "Policy allows kernel snapshots" },
    { KSWORD_ARK_FEATURE_ID_CALLBACK_CONTROL, "Callback control", KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY | KSWORD_ARK_FEATURE_FLAG_MUTATING | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL, 0ULL, "Policy allows callback control" },
    { KSWORD_ARK_FEATURE_ID_DYNDATA_STATUS, "DynData status", KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY | KSWORD_ARK_FEATURE_FLAG_READ_ONLY, 0UL, 0ULL, "DynData query IOCTLs available" },
    { KSWORD_ARK_FEATURE_ID_PROCESS_PROTECTION_PATCH, "Process protection patch", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_MUTATING | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION, KSW_CAP_PROCESS_PROTECTION_PATCH, "EpProtection + EpSignatureLevel + EpSectionSignatureLevel" },
    { KSWORD_ARK_FEATURE_ID_PROCESS_HANDLE_TABLE, "Process handle table", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_PROCESS_OBJECT_TABLE | KSW_CAP_HANDLE_TABLE_DECODE, "DynData direct table decode; SystemExtendedHandleInformation fallback" },
    { KSWORD_ARK_FEATURE_ID_OBJECT_TYPE_FIELDS, "Object type fields", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_OBJECT_TYPE_FIELDS, "DynData private fields; Object Manager namespace and signature-located table fallback" },
    { KSWORD_ARK_FEATURE_ID_THREAD_STACK_FIELDS, "Thread stack fields", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_THREAD_STACK_FIELDS, "DynData full stack; exported accessor-signature fallback for initial/base/limit" },
    { KSWORD_ARK_FEATURE_ID_THREAD_IO_COUNTERS, "Thread I/O counters", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_THREAD_IO_COUNTERS, "KTHREAD counters; omitted fail-closed when no validated runtime oracle exists" },
    { KSWORD_ARK_FEATURE_ID_ALPC_FIELDS, "ALPC fields", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_ALPC_FIELDS, "DynData communication fields; ZwAlpcQueryInformation basic fallback" },
    { KSWORD_ARK_FEATURE_ID_SECTION_CONTROL_AREA, "Section ControlArea", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_SECTION_CONTROL_AREA, "DynData mapping walk; PsReferenceProcessFilePointer image fallback" },
    { KSWORD_ARK_FEATURE_ID_WSL_LXCORE_FIELDS, "WSL lxcore fields", KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA | KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, 0UL, KSW_CAP_WSL_LXCORE_FIELDS, "DynData Linux IDs; public subsystem and silo evidence fallback" },
    { KSWORD_ARK_FEATURE_ID_IMAGE_TRUST_CI, "Image trust CI", KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY | KSWORD_ARK_FEATURE_FLAG_READ_ONLY, 0UL, 0ULL, "SystemCodeIntegrityInformation + cached file signing level" },
    { KSWORD_ARK_FEATURE_ID_DANGEROUS_ACTION_GOVERNANCE, "Dangerous action governance", KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY | KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, KSWORD_ARK_SECURITY_POLICY_REQUIRE_CONFIRMATION | KSWORD_ARK_SECURITY_POLICY_DENY_CRITICAL_PROCESS | KSWORD_ARK_SECURITY_POLICY_ADVANCED_MODE, 0ULL, "Central safety policy + audit for mutating IOCTLs" }
};

VOID
kswordArkCapabilityInitialize(
    VOID
    )
/*++

Routine Description:

    initialize global Phase 1 capability diagnostics state before the control
    device accepts IOCTL traffic.

Arguments:

    None.

Return Value:

    None.

--*/
{
    ExInitializePushLock(&gKswordArkCapabilityErrorLock);
    RtlZeroMemory(&gKswordArkLastCapabilityError, sizeof(gKswordArkLastCapabilityError));
}

static VOID
kswordArkCapabilityCopyAnsi(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes,
    _In_opt_z_ PCSTR source
    )
/*++

Routine Description:

    Copy a bounded ANSI diagnostic string into a shared response field.

Arguments:

    Destination - Output character buffer.
    DestinationBytes - Output buffer capacity in bytes.
    Source - Optional NUL-terminated source string.

Return Value:

    None.

--*/
{
    if (destination == NULL || destinationBytes == 0U) {
        return;
    }

    destination[0] = '\0';
    if (source == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyNA(destination, destinationBytes, source, destinationBytes - 1U);
    destination[destinationBytes - 1U] = '\0';
}

static ULONG
kswordArkCapabilityDynStatusFlags(
    _In_ const KswDynState* state
    )
/*++

Routine Description:

    Convert a DynData state snapshot into public status flags.

Arguments:

    State - DynData snapshot.

Return Value:

    KSW_DYN_STATUS_FLAG_* bit mask.

--*/
{
    ULONG flags = 0UL;

    if (state == NULL) {
        return 0UL;
    }

    if (state->initialized) {
        flags |= KSW_DYN_STATUS_FLAG_INITIALIZED;
    }
    if (state->ntosActive) {
        flags |= KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
    }
    if (state->lxcoreActive) {
        flags |= KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE;
    }
    if (state->extraActive) {
        flags |= KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE;
    }
    if (state->pdbProfileActive) {
        flags |= KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE;
    }

    return flags;
}

static ULONG
kswordArkCapabilityCurrentSecurityPolicy(
    VOID
    )
/*++

Routine Description:

    Return the current conservative security policy. Phase 1 exposes the policy
    explicitly so R3 can display policy-denied features without guessing.

Arguments:

    None.

Return Value:

    KSWORD_ARK_SECURITY_POLICY_* bit mask.

--*/
{
    ULONG policyFlags = KSWORD_ARK_SECURITY_POLICY_FLAG_ACTIVE;
    KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE safetyResponse;
    size_t bytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&safetyResponse, sizeof(safetyResponse));
    status = kswordArkSafetyQueryPolicy(
        &safetyResponse,
        sizeof(safetyResponse),
        &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten < sizeof(safetyResponse)) {
        return policyFlags;
    }

    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_TERMINATE) != 0UL ||
        (safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_SUSPEND) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_FILE_DELETE) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_ALLOW_FILE_DELETE;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_CALLBACK_CONTROL) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_PROTECTION) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_REQUIRE_CONFIRMATION_HIGH_RISK) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_REQUIRE_CONFIRMATION;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_DENY_CRITICAL_PROCESS) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_DENY_CRITICAL_PROCESS;
    }
    if ((safetyResponse.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ADVANCED_MODE) != 0UL) {
        policyFlags |= KSWORD_ARK_SECURITY_POLICY_ADVANCED_MODE;
    }

    policyFlags |= KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS;
    return policyFlags;
}

static PCSTR
kswordArkCapabilityStateName(
    _In_ ULONG state
    )
/*++

Routine Description:

    Convert a feature state enum into a stable short label.

Arguments:

    State - KSWORD_ARK_FEATURE_STATE_* value.

Return Value:

    Static ANSI state label.

--*/
{
    switch (state) {
    case KSWORD_ARK_FEATURE_STATE_AVAILABLE:
        return "Available";
    case KSWORD_ARK_FEATURE_STATE_UNAVAILABLE:
        return "Unavailable";
    case KSWORD_ARK_FEATURE_STATE_DEGRADED:
        return "Degraded";
    case KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY:
        return "Denied by policy";
    default:
        return "Unknown";
    }
}

static BOOLEAN
kswordArkCapabilityHasValidatedRuntimeFallback(
    _In_ ULONG featureId
    )
/*++

Routine Description:

    Identify read-only feature groups that remain callable through a bounded,
    validated runtime fallback when their full private DynData layout is absent.

Return Value:

    TRUE for a feature with a real fallback path; otherwise FALSE.

--*/
{
    switch (featureId) {
    case KSWORD_ARK_FEATURE_ID_PROCESS_HANDLE_TABLE:
    case KSWORD_ARK_FEATURE_ID_OBJECT_TYPE_FIELDS:
    case KSWORD_ARK_FEATURE_ID_THREAD_STACK_FIELDS:
    case KSWORD_ARK_FEATURE_ID_ALPC_FIELDS:
    case KSWORD_ARK_FEATURE_ID_SECTION_CONTROL_AREA:
    case KSWORD_ARK_FEATURE_ID_WSL_LXCORE_FIELDS:
        return TRUE;

    default:
        return FALSE;
    }
}

static ULONG
kswordArkCapabilityEvaluateFeatureState(
    _In_ const KswCapFeatureTemplate* feature,
    _In_ ULONG securityPolicyFlags,
    _In_ ULONG64 dynDataCapabilityMask,
    _Out_ ULONG* deniedPolicyFlagsOut,
    _Out_ ULONG64* presentDynDataMaskOut,
    _Out_ PCSTR* reasonTextOut
    )
/*++

Routine Description:

    Evaluate one feature against security policy and DynData capability bits.

Arguments:

    Feature - Static feature template.
    SecurityPolicyFlags - Current policy bit mask.
    DynDataCapabilityMask - Current DynData capability bit mask.
    DeniedPolicyFlagsOut - Receives missing policy bits.
    PresentDynDataMaskOut - Receives present DynData dependency bits.
    ReasonTextOut - Receives a static diagnostic reason string.

Return Value:

    KSWORD_ARK_FEATURE_STATE_* value.

--*/
{
    ULONG deniedPolicyFlags = 0UL;
    ULONG64 presentDynDataMask = 0ULL;
    PCSTR reasonText = "Feature is available.";
    ULONG state = KSWORD_ARK_FEATURE_STATE_AVAILABLE;

    if (feature == NULL || deniedPolicyFlagsOut == NULL || presentDynDataMaskOut == NULL || reasonTextOut == NULL) {
        return KSWORD_ARK_FEATURE_STATE_UNKNOWN;
    }

    if (feature->requiredPolicyFlags != 0UL) {
        deniedPolicyFlags = feature->requiredPolicyFlags & (~securityPolicyFlags);
    }
    if (feature->requiredDynDataMask != 0ULL) {
        presentDynDataMask = dynDataCapabilityMask & feature->requiredDynDataMask;
    }

    if (deniedPolicyFlags != 0UL) {
        state = KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY;
        reasonText = "Security policy denied one or more required operations.";
    }
    else if (feature->requiredDynDataMask != 0ULL && presentDynDataMask == 0ULL) {
        if (kswordArkCapabilityHasValidatedRuntimeFallback(feature->featureId)) {
            state = KSWORD_ARK_FEATURE_STATE_DEGRADED;
            reasonText = "Private DynData is absent; validated runtime fallback remains available.";
        }
        else {
            state = KSWORD_ARK_FEATURE_STATE_UNAVAILABLE;
            reasonText = "Required DynData capability bits are absent.";
        }
    }
    else if (feature->requiredDynDataMask != 0ULL && presentDynDataMask != feature->requiredDynDataMask) {
        state = KSWORD_ARK_FEATURE_STATE_DEGRADED;
        reasonText = "Only part of the required DynData capability bits are present.";
    }

    *deniedPolicyFlagsOut = deniedPolicyFlags;
    *presentDynDataMaskOut = presentDynDataMask;
    *reasonTextOut = reasonText;
    return state;
}

static ULONG
kswordArkCapabilityBuildFeatureEntries(
    _Out_writes_opt_(entryCapacity) KSWORD_ARK_FEATURE_CAPABILITY_ENTRY* entries,
    _In_ ULONG entryCapacity,
    _In_ ULONG securityPolicyFlags,
    _In_ ULONG64 dynDataCapabilityMask
    )
/*++

Routine Description:

    Build public feature capability entries from the static matrix and current
    runtime state.

Arguments:

    Entries - Optional output array.
    EntryCapacity - Output array capacity in entries.
    SecurityPolicyFlags - Current security policy bits.
    DynDataCapabilityMask - Current DynData capability bits.

Return Value:

    Number of entries copied when Entries is present; otherwise total entries.

--*/
{
    ULONG index = 0UL;
    ULONG copied = 0UL;
    const ULONG kTotalCount = (ULONG)(sizeof(kGKswordArkFeatureTemplates) / sizeof(kGKswordArkFeatureTemplates[0]));

    if (entries == NULL || entryCapacity == 0UL) {
        return kTotalCount;
    }

    for (index = 0UL; index < kTotalCount && copied < entryCapacity; ++index) {
        const KswCapFeatureTemplate* feature = &kGKswordArkFeatureTemplates[index];
        KSWORD_ARK_FEATURE_CAPABILITY_ENTRY* entry = &entries[copied];
        ULONG deniedPolicyFlags = 0UL;
        ULONG64 presentDynDataMask = 0ULL;
        PCSTR reasonText = NULL;
        ULONG state = KSWORD_ARK_FEATURE_STATE_UNKNOWN;

        state = kswordArkCapabilityEvaluateFeatureState(
            feature,
            securityPolicyFlags,
            dynDataCapabilityMask,
            &deniedPolicyFlags,
            &presentDynDataMask,
            &reasonText);

        RtlZeroMemory(entry, sizeof(*entry));
        entry->featureId = feature->featureId;
        entry->state = state;
        entry->flags = feature->flags;
        entry->requiredPolicyFlags = feature->requiredPolicyFlags;
        entry->deniedPolicyFlags = deniedPolicyFlags;
        entry->requiredDynDataMask = feature->requiredDynDataMask;
        entry->presentDynDataMask = presentDynDataMask;
        kswordArkCapabilityCopyAnsi(entry->featureName, sizeof(entry->featureName), feature->featureName);
        kswordArkCapabilityCopyAnsi(entry->stateName, sizeof(entry->stateName), kswordArkCapabilityStateName(state));
        kswordArkCapabilityCopyAnsi(entry->dependencyText, sizeof(entry->dependencyText), feature->dependencyText);
        kswordArkCapabilityCopyAnsi(entry->reasonText, sizeof(entry->reasonText), reasonText);
        copied += 1UL;
    }

    return copied;
}

VOID
kswordArkCapabilityRecordLastError(
    _In_ NTSTATUS status,
    _In_z_ PCSTR sourceText,
    _In_z_ PCSTR summaryText
    )
/*++

Routine Description:

    Record the latest driver error summary for Phase 1 diagnostics.

Arguments:

    Status - Failing NTSTATUS.
    sourceText - Short subsystem name.
    summaryText - Human-readable summary.

Return Value:

    None.

--*/
{
    kswordArkAcquirePushLockExclusive(&gKswordArkCapabilityErrorLock);
    gKswordArkLastCapabilityError.status = status;
    kswordArkCapabilityCopyAnsi(gKswordArkLastCapabilityError.source, sizeof(gKswordArkLastCapabilityError.source), sourceText);
    kswordArkCapabilityCopyAnsi(gKswordArkLastCapabilityError.summary, sizeof(gKswordArkLastCapabilityError.summary), summaryText);
    kswordArkReleasePushLockExclusive(&gKswordArkCapabilityErrorLock);
}

BOOLEAN
kswordArkCapabilityIsIoctlAllowed(
    _In_ ULONG64 requiredCapability,
    _Out_opt_ NTSTATUS* deniedStatusOut
    )
/*++

Routine Description:

    Fail closed for IOCTLs that require private DynData capabilities.

Arguments:

    RequiredCapability - Required KSW_CAP_* dependency mask.
    DeniedStatusOut - Optional denied status output.

Return Value:

    TRUE when allowed; FALSE when the required capability is unavailable.

--*/
{
    KswDynState dynState;

    if (deniedStatusOut != NULL) {
        *deniedStatusOut = STATUS_SUCCESS;
    }
    if (requiredCapability == 0ULL) {
        return TRUE;
    }

    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & requiredCapability) == requiredCapability) {
        return TRUE;
    }

    if (deniedStatusOut != NULL) {
        *deniedStatusOut = STATUS_NOT_SUPPORTED;
    }
    return FALSE;
}

NTSTATUS
kswordArkCapabilityQuery(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write the unified driver capability response for R3 state and matrix UI.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable output byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the response header is written; otherwise validation
    status.

--*/
{
    KswDynState dynState;
    KswCapLastError lastError;
    KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE* response = NULL;
    ULONG securityPolicyFlags = 0UL;
    ULONG totalCount = 0UL;
    ULONG entryCapacity = 0UL;
    ULONG returnedCount = 0UL;
    ULONG statusFlags = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_CAPABILITY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    kswordArkDynDataSnapshot(&dynState);
    securityPolicyFlags = kswordArkCapabilityCurrentSecurityPolicy();
    totalCount = kswordArkCapabilityBuildFeatureEntries(NULL, 0UL, securityPolicyFlags, dynState.capabilityMask);

    RtlZeroMemory(&lastError, sizeof(lastError));
    kswordArkAcquirePushLockShared(&gKswordArkCapabilityErrorLock);
    RtlCopyMemory(&lastError, &gKswordArkLastCapabilityError, sizeof(lastError));
    kswordArkReleasePushLockShared(&gKswordArkCapabilityErrorLock);

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*)outputBuffer;
    response->size = (ULONG)KSW_CAPABILITY_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_DRIVER_CAPABILITY_PROTOCOL_VERSION;
    response->driverProtocolVersion = KSWORD_ARK_DRIVER_PROTOCOL_VERSION;
    response->securityPolicyFlags = securityPolicyFlags;
    response->dynDataStatusFlags = kswordArkCapabilityDynStatusFlags(&dynState);
    response->lastErrorStatus = (LONG)lastError.status;
    response->totalFeatureCount = totalCount;
    response->entrySize = sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
    response->dynDataCapabilityMask = dynState.capabilityMask;

    statusFlags = KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED |
        KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK |
        KSWORD_ARK_DRIVER_STATUS_FLAG_SECURITY_POLICY_ON;
    if (dynState.initialized) {
        statusFlags |= KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_INITIALIZED;
    }
    if (dynState.ntosActive) {
        statusFlags |= KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_ACTIVE;
    }
    else {
        statusFlags |= KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_MISSING | KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED;
    }
    if (!NT_SUCCESS(lastError.status) && lastError.status != 0) {
        statusFlags |= KSWORD_ARK_DRIVER_STATUS_FLAG_LAST_ERROR_PRESENT;
    }
    response->statusFlags = statusFlags;

    kswordArkCapabilityCopyAnsi(response->lastErrorSource, sizeof(response->lastErrorSource), lastError.source);
    kswordArkCapabilityCopyAnsi(response->lastErrorSummary, sizeof(response->lastErrorSummary), lastError.summary);

    entryCapacity = (ULONG)((outputBufferLength - KSW_CAPABILITY_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY));
    if (entryCapacity > 0UL) {
        returnedCount = kswordArkCapabilityBuildFeatureEntries(
            response->entries,
            entryCapacity,
            securityPolicyFlags,
            dynState.capabilityMask);
    }

    response->returnedFeatureCount = returnedCount;
    response->size = (ULONG)(KSW_CAPABILITY_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}
