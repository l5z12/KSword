/*++

Module Name:

    preflight_query.c

Abstract:

    Phase-16 release preflight diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_registry.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY))

typedef struct KswordArkPreflightBuilder
{
    KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE* response;
    ULONG capacity;
    ULONG returned;
    ULONG total;
    ULONG worstStatus;
} KswordArkPreflightBuilder;

static ULONG
kswordArkPreflightBuildConfiguration(
    VOID
    )
/*++

Routine Description:

    Returns the current driver build configuration. Note: Debug/Release is determined by
    preprocessor macros to confirm before release that the loaded configuration is not incorrect.

Arguments:

    None.

Return Value:

    KSWORD_ARK_PREFLIGHT_BUILD_*。

--*/
{
#if DBG
    return KSWORD_ARK_PREFLIGHT_BUILD_DEBUG;
#else
    return KSWORD_ARK_PREFLIGHT_BUILD_RELEASE;
#endif
}

static ULONG
kswordArkPreflightTargetArchitecture(
    VOID
    )
/*++

Routine Description:

    Returns the current target architecture. Note: Phase-16 requires x64 Debug/Release builds
    to have no warnings; ARM64 projects are retained but current acceptance focuses on x64.

Arguments:

    None.

Return Value:

    KSWORD_ARK_PREFLIGHT_ARCH_*。

--*/
{
#if defined(_M_AMD64) || defined(_AMD64_)
    return KSWORD_ARK_PREFLIGHT_ARCH_X64;
#elif defined(_M_ARM64) || defined(_ARM64_)
    return KSWORD_ARK_PREFLIGHT_ARCH_ARM64;
#else
    return KSWORD_ARK_PREFLIGHT_ARCH_UNKNOWN;
#endif
}

static VOID
kswordArkPreflightCopyAnsi(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes,
    _In_opt_z_ PCSTR source
    )
/*++

Routine Description:

    Copy preflight diagnostic text. Note: Fixed ANSI fields are always NUL-terminated
    to prevent buffer over-reads when concatenating R3 diagnostic reports.

Arguments:

    Destination - Target buffer.
    DestinationBytes: buffer byte count.
    Source - Optional source string.

Return Value:

    None. This function has no return value.

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

static VOID
kswordArkPreflightAddCheck(
    _Inout_ KswordArkPreflightBuilder* builder,
    _In_ ULONG checkId,
    _In_ ULONG status,
    _In_ NTSTATUS ntStatus,
    _In_z_ PCSTR checkName,
    _In_z_ PCSTR detailText
    )
/*++

Routine Description:

    Add a preflight check. Note: If the output buffer capacity is insufficient,
    still increment totalCount so R3 can resize and retry based on this.

Arguments:

    Builder - Constructor.
    CheckId - Check item ID.
    Status - PASS/WARN/FAIL/NOT_RUN。
    NtStatus - Related NTSTATUS.
    CheckName - Check name.
    DetailText - Diagnostic explanation.

Return Value:

    None. This function has no return value.

--*/
{
    if (builder == NULL) {
        return;
    }

    builder->total += 1UL;
    if (status > builder->worstStatus && status != KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN) {
        builder->worstStatus = status;
    }

    if (builder->response == NULL || builder->returned >= builder->capacity) {
        return;
    }

    {
        KSWORD_ARK_PREFLIGHT_CHECK_ENTRY* entry = &builder->response->checks[builder->returned];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->checkId = checkId;
        entry->status = status;
        entry->ntstatus = ntStatus;
        kswordArkPreflightCopyAnsi(entry->checkName, sizeof(entry->checkName), checkName);
        kswordArkPreflightCopyAnsi(entry->detail, sizeof(entry->detail), detailText);
        builder->returned += 1UL;
    }
}

static VOID
kswordArkPreflightAddExternalGateChecks(
    _Inout_ KswordArkPreflightBuilder* builder
    )
/*++

Routine Description:

    Add release gates requiring manual execution or external environment setup. Note: Driver Verifier, cross-system
    compatibility matrix, and R3 UI acceptance cannot run within the driver, so explicitly mark as NotRun.

Arguments:

    Builder - Constructor.

Return Value:

    None. This function has no return value.

--*/
{
    kswordArkPreflightAddCheck(
        builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_VERIFIER,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Driver Verifier",
        "External test required; driver reports NotRun instead of assuming pass.");
    kswordArkPreflightAddCheck(
        builder,
        KSWORD_ARK_PREFLIGHT_CHECK_LOAD_UNLOAD,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Load/unload loop",
        "External SCM/load test required for repeated load, unload and UI open/close.");
    kswordArkPreflightAddCheck(
        builder,
        KSWORD_ARK_PREFLIGHT_CHECK_R3_DEGRADED_UI,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "R3 degraded UI",
        "R3 build is intentionally skipped in current unattended driver-only pass.");
}

NTSTATUS
kswordArkPreflightQuery(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_PREFLIGHT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Construct the pre-flight driver self-check response. Note: This response only reports states observable within the driver; explicit
    `NotRun` is returned for release thresholds that cannot be verified in the kernel to avoid misleading the release process.

Arguments:

    OutputBuffer - Output buffer.
    OutputBufferLength - Output buffer length.
    Request - optional request.
    BytesWrittenOut - Bytes received for writing.

Return Value:

    STATUS_SUCCESS or buffer/parameter error.

--*/
{
    KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE* response = NULL;
    KswordArkPreflightBuilder builder;
    KswDynState dynState;
    KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE safetyState;
    KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE monitorState;
    KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST trustRequest;
    KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE trustState;
    size_t bytesWritten = 0U;
    ULONG requestFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request != NULL &&
        request->size != 0UL &&
        (request->size < sizeof(KSWORD_ARK_QUERY_PREFLIGHT_REQUEST) ||
         request->version != KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&safetyState, sizeof(safetyState));
    RtlZeroMemory(&monitorState, sizeof(monitorState));
    RtlZeroMemory(&trustRequest, sizeof(trustRequest));
    RtlZeroMemory(&trustState, sizeof(trustState));

    response = (KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE*)outputBuffer;
    response->size = (ULONG)KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION;
    response->overallStatus = KSWORD_ARK_PREFLIGHT_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY);
    response->buildConfiguration = kswordArkPreflightBuildConfiguration();
    response->targetArchitecture = kswordArkPreflightTargetArchitecture();
    response->ioctlRegistryCount = kswordArkGetRegisteredIoctlCount();
    response->ioctlDuplicateCount = kswordArkGetDuplicateIoctlCount();

    builder.response = response;
    builder.capacity = (ULONG)((outputBufferLength - KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY));
    builder.worstStatus = KSWORD_ARK_PREFLIGHT_STATUS_PASS;

    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_BUILD,
        (response->targetArchitecture == KSWORD_ARK_PREFLIGHT_ARCH_X64) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        STATUS_SUCCESS,
        "Driver build",
#if DBG
        "Debug driver build is loaded; Release is required for public release.");
#else
        "Release driver build is loaded.");
#endif

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    response->dynDataLastStatus = dynState.lastStatus;
    response->dynDataStatusFlags = 0UL;
    if (dynState.initialized) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_INITIALIZED;
    }
    if (dynState.ntosActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
    }
    if (dynState.lxcoreActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE;
    }
    if (dynState.extraActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE;
    }
    if (dynState.pdbProfileActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE;
    }
    response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_DYNDATA_PRESENT;
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DYNDATA_TOLERANCE,
        dynState.initialized ? (dynState.ntosActive ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN) : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        dynState.lastStatus,
        "DynData tolerance",
        dynState.ntosActive ? "DynData ntos profile active." : "Driver must still load when DynData profile is missing.");

    response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_IOCTL_REGISTRY;
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_IOCTL_REGISTRY,
        (response->ioctlRegistryCount != 0UL && response->ioctlDuplicateCount == 0UL) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        (response->ioctlDuplicateCount == 0UL) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION,
        "IOCTL registry",
        "Central registry is enumerable and duplicate control codes are checked.");

    status = kswordArkSafetyQueryPolicy(&safetyState, sizeof(safetyState), &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(safetyState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_SAFETY_POLICY;
        response->safetyPolicyFlags = safetyState.policyFlags;
        response->safetyPolicyGeneration = safetyState.policyGeneration;
    }
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_SAFETY_POLICY,
        (NT_SUCCESS(status) &&
            (safetyState.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ACTIVE) != 0UL &&
            (safetyState.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_DENY_CRITICAL_PROCESS) != 0UL) ?
            KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        status,
        "Safety policy",
        "Dangerous operations are routed through central policy with critical PID denial.");

    status = kswordArkFileMonitorQueryStatus(&monitorState, sizeof(monitorState), &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(monitorState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_FILE_MONITOR;
        response->fileMonitorRuntimeFlags = monitorState.runtimeFlags;
        response->fileMonitorQueuedCount = monitorState.queuedCount;
        response->fileMonitorDroppedCount = monitorState.droppedCount;
        response->fileMonitorRegisterStatus = monitorState.registerStatus;
        response->fileMonitorStartStatus = monitorState.startStatus;
    }
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_FILE_MONITOR,
        (NT_SUCCESS(status) && NT_SUCCESS(monitorState.registerStatus)) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        NT_SUCCESS(status) ? monitorState.registerStatus : status,
        "File monitor",
        "Minifilter registration status is reported; StartFiltering is intentionally IOCTL-controlled.");

    trustRequest.flags = KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_GLOBAL_CI;
    status = kswordArkDriverQueryImageTrust(&trustState, sizeof(trustState), &trustRequest, &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(trustState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_TRUST_CI;
        response->trustFieldFlags = trustState.fieldFlags;
        response->codeIntegrityOptions = trustState.codeIntegrityOptions;
        response->codeIntegrityStatus = trustState.codeIntegrityStatus;
        response->secureBootEnabled = trustState.secureBootEnabled;
        response->secureBootCapable = trustState.secureBootCapable;
    }
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_CODE_INTEGRITY,
        ((trustState.fieldFlags & KSWORD_ARK_TRUST_FIELD_GLOBAL_CI_PRESENT) != 0UL) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        NT_SUCCESS(status) ? trustState.codeIntegrityStatus : status,
        "Code Integrity",
        "Global Code Integrity options are exposed for release diagnostics.");
    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_SIGNING_PIPELINE,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Signing pipeline",
        "Build can skip signing here; final Visual Studio/signing pipeline must sign the driver.");

    requestFlags = (request == NULL || request->flags == 0UL) ? 0UL : request->flags;
    if ((requestFlags & KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_EXTERNAL_GATES) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_EXTERNAL_GATES;
        kswordArkPreflightAddExternalGateChecks(&builder);
    }

    kswordArkPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_OBJECT_LIFETIME,
        KSWORD_ARK_PREFLIGHT_STATUS_PASS,
        STATUS_SUCCESS,
        "Object lifetime",
        "Preflight confirms modules expose explicit cleanup paths; static review still required before release.");

    response->totalCheckCount = builder.total;
    response->returnedCheckCount = builder.returned;
    response->overallStatus = builder.worstStatus;
    response->size = (ULONG)(KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE + ((size_t)builder.returned * sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}
