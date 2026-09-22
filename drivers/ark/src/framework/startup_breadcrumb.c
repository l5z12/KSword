/*++

Module Name:

    startup_breadcrumb.c

Abstract:

    Persists the DriverEntry startup stage and the raw NTSTATUS of a failed
    load into the driver service Parameters key. Without this record the only
    user-visible evidence of a failed load is the SCM Win32 code (31), which
    cannot distinguish a WDF queue failure from a kernel callback registration
    failure.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_startup.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, kswordArkStartupBreadcrumbInitialize)
#pragma alloc_text (PAGE, kswordArkStartupStage)
#pragma alloc_text (PAGE, kswordArkStartupFailure)
#pragma alloc_text (PAGE, kswordArkStartupNoteCallbackMask)
#pragma alloc_text (PAGE, kswordArkStartupReady)
#pragma alloc_text (PAGE, kswordArkStartupGetOsBuildNumber)
#endif

// Build identity to confirm the user actually loaded the binary distributed this time. Driver builds are
// deterministic; __DATE__/__TIME__ are unavailable, so instead use the PE link timestamp and checksum of
// the image itself: these two values can be directly compared against the distributed .sys file.
static WCHAR gKswordArkStartupBuildText[64] = { 0 };

// Kernel object path for the service Parameters key, constructed once at the DriverEntry entry point.
static WCHAR gKswordArkStartupParametersPath[512] = { 0 };

// All persistent calls are silently skipped when the path is unavailable, without affecting the actual startup return value.
static BOOLEAN gKswordArkStartupPathReady = FALSE;

// Currently registered stage number; serves as a fallback when the stage is not explicitly passed in failure paths.
static ULONG gKswordArkStartupCurrentStage = 0UL;

// Callback capability mask available after a downgrade boot.
static ULONG gKswordArkStartupCallbackMask = 0UL;

// Internal OS build number observed during this boot.
static ULONG gKswordArkStartupOsBuildNumber = 0UL;

static VOID
kswordArkStartupCaptureBuildIdentity(
    _In_opt_ PDRIVER_OBJECT driverObject
    )
/*++

Routine Description:

    Derive the build identity from the loaded image headers. Persisting this
    lets a user report be matched against the exact .sys that was shipped, which
    is the only way to rule out "the running binary is not the one we built".

Arguments:

    DriverObject - Driver object supplied to DriverEntry.

Return Value:

    VOID

--*/
{
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    PAGED_CODE();

    // Retain an explicit placeholder value instead of leaving it empty when the image header cannot be read.
    (VOID)RtlStringCchCopyW(
        gKswordArkStartupBuildText,
        RTL_NUMBER_OF(gKswordArkStartupBuildText),
        L"unknown");

    if (driverObject == NULL ||
        driverObject->DriverStart == NULL ||
        driverObject->DriverSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))) {
        return;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)driverObject->DriverStart;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return;
        }
        if (dosHeader->e_lfanew <= 0 ||
            (ULONG)dosHeader->e_lfanew > (driverObject->DriverSize - sizeof(IMAGE_NT_HEADERS))) {
            return;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)driverObject->DriverStart + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return;
        }

        // Link timestamp and checksum together uniquely identify this build artifact.
        (VOID)RtlStringCchPrintfW(
            gKswordArkStartupBuildText,
            RTL_NUMBER_OF(gKswordArkStartupBuildText),
            L"pe:%08lX/%08lX",
            (ULONG)ntHeaders->FileHeader.TimeDateStamp,
            (ULONG)ntHeaders->OptionalHeader.CheckSum);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Reading the own image header should not fail; if it does, retain the placeholder value.
        NOTHING;
    }
}

static VOID
kswordArkStartupWriteDwordValue(
    _In_ HANDLE parametersKey,
    _In_z_ PCWSTR valueName,
    _In_ ULONG valueData
    )
/*++

Routine Description:

    Write one REG_DWORD breadcrumb value. Failures are swallowed because the
    breadcrumb must never change the startup result it is describing.

Arguments:

    ParametersKey - Open handle to the service Parameters key.
    ValueName - Registry value name from the shared startup protocol.
    ValueData - Value payload.

Return Value:

    VOID

--*/
{
    UNICODE_STRING valueNameText;

    PAGED_CODE();

    // Kernel registry APIs only accept value names in UNICODE_STRING format.
    RtlInitUnicodeString(&valueNameText, valueName);
    (VOID)ZwSetValueKey(
        parametersKey,
        &valueNameText,
        0UL,
        REG_DWORD,
        &valueData,
        (ULONG)sizeof(valueData));
}

static VOID
kswordArkStartupWriteStringValue(
    _In_ HANDLE parametersKey,
    _In_z_ PCWSTR valueName,
    _In_z_ PCWSTR valueText
    )
/*++

Routine Description:

    Write one REG_SZ breadcrumb value, including the terminating NUL so the
    R3 reader can consume it directly.

Arguments:

    ParametersKey - Open handle to the service Parameters key.
    ValueName - Registry value name from the shared startup protocol.
    ValueText - NUL terminated payload.

Return Value:

    VOID

--*/
{
    UNICODE_STRING valueNameText;
    size_t textChars = 0U;

    PAGED_CODE();

    // On length anomaly, discard this breadcrumb directly without any truncation guessing.
    if (!NT_SUCCESS(RtlStringCchLengthW(valueText, NTSTRSAFE_MAX_CCH, &textChars))) {
        return;
    }

    RtlInitUnicodeString(&valueNameText, valueName);
    (VOID)ZwSetValueKey(
        parametersKey,
        &valueNameText,
        0UL,
        REG_SZ,
        (PVOID)valueText,
        (ULONG)((textChars + 1U) * sizeof(WCHAR)));
}

static VOID
kswordArkStartupPersist(
    _In_ ULONG stage,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Create (or open) the service Parameters key and publish the full startup
    record: stage, raw NTSTATUS, build identity, OS build and the callback
    capability mask that survived a degraded start.

Arguments:

    Stage - KswordArkStartStage value reached by this attempt.
    Status - Raw NTSTATUS to persist. STATUS_PENDING marks a start still in
        progress; STATUS_SUCCESS marks a completed start.

Return Value:

    VOID

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING parametersPath;
    HANDLE parametersKey = NULL;
    ULONG dispositionValue = 0UL;
    NTSTATUS createStatus = STATUS_SUCCESS;

    PAGED_CODE();

    // Do not access the registry if the service path cannot be resolved.
    if (!gKswordArkStartupPathReady) {
        return;
    }

    RtlInitUnicodeString(&parametersPath, gKswordArkStartupParametersPath);
    InitializeObjectAttributes(
        &objectAttributes,
        &parametersPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // The Parameters subkey does not exist during the first startup, so the create semantics are used.
    createStatus = ZwCreateKey(
        &parametersKey,
        KEY_SET_VALUE,
        &objectAttributes,
        0UL,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &dispositionValue);
    if (!NT_SUCCESS(createStatus)) {
        return;
    }

    kswordArkStartupWriteDwordValue(parametersKey, KSWORD_ARK_STARTUP_VALUE_STAGE, stage);
    kswordArkStartupWriteDwordValue(parametersKey, KSWORD_ARK_STARTUP_VALUE_STATUS, (ULONG)status);
    kswordArkStartupWriteStringValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_BUILD,
        gKswordArkStartupBuildText);
    kswordArkStartupWriteDwordValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_OS_BUILD,
        gKswordArkStartupOsBuildNumber);
    kswordArkStartupWriteDwordValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_CALLBACK_MASK,
        gKswordArkStartupCallbackMask);

    (VOID)ZwClose(parametersKey);
}

ULONG
kswordArkStartupGetOsBuildNumber(
    VOID
    )
/*++

Routine Description:

    Return the running OS build number, caching the first successful query.

Arguments:

    None.

Return Value:

    OS build number, or zero when the version could not be queried.

--*/
{
    RTL_OSVERSIONINFOW versionInfo;

    PAGED_CODE();

    // The version number remains unchanged during a single load; reuse the cached value after a successful query.
    if (gKswordArkStartupOsBuildNumber != 0UL) {
        return gKswordArkStartupOsBuildNumber;
    }

    RtlZeroMemory(&versionInfo, sizeof(versionInfo));
    versionInfo.dwOSVersionInfoSize = (ULONG)sizeof(versionInfo);
    if (!NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        return 0UL;
    }

    gKswordArkStartupOsBuildNumber = versionInfo.dwBuildNumber;
    return gKswordArkStartupOsBuildNumber;
}

VOID
kswordArkStartupBreadcrumbInitialize(
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_opt_ PCUNICODE_STRING registryPath
    )
/*++

Routine Description:

    Capture the service registry path handed to DriverEntry, then publish the
    first breadcrumb. A machine whose service key holds no LastStartStage after
    a failed start never reached DriverEntry at all, which separates signing /
    Code Integrity / import failures from in-driver initialization failures.

Arguments:

    DriverObject - Driver object used to read the loaded image identity.
    RegistryPath - Service key path supplied by the I/O manager.

Return Value:

    VOID

--*/
{
    NTSTATUS copyStatus = STATUS_SUCCESS;

    PAGED_CODE();

    // On re-initialization, reset the state first to avoid reusing the path from the previous load.
    gKswordArkStartupPathReady = FALSE;
    gKswordArkStartupCurrentStage = (ULONG)kKswordArkStartStageEnteredDriverEntry;
    gKswordArkStartupCallbackMask = 0UL;
    gKswordArkStartupParametersPath[0] = L'\0';

    // First capture the image identity; every subsequent breadcrumb includes it.
    kswordArkStartupCaptureBuildIdentity(driverObject);

    // Read the system version once in advance; all subsequent breadcrumbs include it.
    (VOID)kswordArkStartupGetOsBuildNumber();

    if (registryPath == NULL || registryPath->Buffer == NULL || registryPath->Length == 0U) {
        return;
    }

    // RegistryPath may not be NUL-terminated; copy precisely by Length.
    copyStatus = RtlStringCchCopyNW(
        gKswordArkStartupParametersPath,
        RTL_NUMBER_OF(gKswordArkStartupParametersPath),
        registryPath->Buffer,
        registryPath->Length / sizeof(WCHAR));
    if (!NT_SUCCESS(copyStatus)) {
        return;
    }

    // The service key is owned by the SCM; breadcrumbs are consistently written under its Parameters subkey.
    copyStatus = RtlStringCchCatW(
        gKswordArkStartupParametersPath,
        RTL_NUMBER_OF(gKswordArkStartupParametersPath),
        L"\\" KSWORD_ARK_STARTUP_PARAMETERS_SUBKEY);
    if (!NT_SUCCESS(copyStatus)) {
        return;
    }

    gKswordArkStartupPathReady = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup stage=%lu build=%ws osBuild=%lu\n",
        gKswordArkStartupCurrentStage,
        gKswordArkStartupBuildText,
        gKswordArkStartupOsBuildNumber);

    // Entry record uses STATUS_PENDING to indicate 'entered DriverEntry but not yet concluded'.
    kswordArkStartupPersist(gKswordArkStartupCurrentStage, STATUS_PENDING);
}

VOID
kswordArkStartupStage(
    _In_ KSWORD_ARK_START_STAGE stage
    )
/*++

Routine Description:

    Record the stage that is about to run. Only memory state and the debugger
    trace are updated here; the registry is written on failure or on success so
    a normal start does not pay for seventeen registry transactions.

Arguments:

    Stage - Stage about to be attempted.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    gKswordArkStartupCurrentStage = (ULONG)stage;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup stage=%lu\n",
        gKswordArkStartupCurrentStage);
}

NTSTATUS
kswordArkStartupFailure(
    _In_ KSWORD_ARK_START_STAGE stage,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Persist a fatal startup failure and return the original NTSTATUS unchanged
    so the caller can hand it straight back to the I/O manager.

Arguments:

    Stage - Stage that failed.
    Status - Raw NTSTATUS returned by the failing API.

Return Value:

    The Status argument, unmodified.

--*/
{
    PAGED_CODE();

    gKswordArkStartupCurrentStage = (ULONG)stage;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[KswordARK] startup failure: stage=%lu status=0x%08lX\n",
        gKswordArkStartupCurrentStage,
        (ULONG)status);

    // Persistence failure must not alter the return value, so ignore its result.
    kswordArkStartupPersist(gKswordArkStartupCurrentStage, status);
    return status;
}

VOID
kswordArkStartupNoteCallbackMask(
    _In_ ULONG callbackMask
    )
/*++

Routine Description:

    Remember which callback capabilities survived a degraded start so the final
    breadcrumb explains why some features are missing on this machine.

Arguments:

    CallbackMask - KSWORD_ARK_CALLBACK_REGISTERED_* bitmask.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    gKswordArkStartupCallbackMask = callbackMask;
}

VOID
kswordArkStartupReady(
    VOID
    )
/*++

Routine Description:

    Publish the terminal success record. A stale failure record from a previous
    boot is therefore always overwritten by the next successful start.

Arguments:

    None.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    gKswordArkStartupCurrentStage = (ULONG)kKswordArkStartStageReady;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup ready, callbackMask=0x%08lX\n",
        gKswordArkStartupCallbackMask);

    kswordArkStartupPersist(gKswordArkStartupCurrentStage, STATUS_SUCCESS);
}
