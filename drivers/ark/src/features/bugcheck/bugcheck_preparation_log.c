/*++

Module Name:

    bugcheck_preparation_log.c

Abstract:

    PASSIVE_LEVEL text reporting for BGP preparation. The report is written
    while the driver loads and is never touched by a bugcheck callback.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"
#include "bugcheck_preparation_log.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_BGP_PREPARATION_LOG_PATH \
    L"\\SystemRoot\\Temp\\KswordARK-bgp-preparation.log"
#define KSWORD_ARK_BGP_PREPARATION_LOG_CAPACITY 2048UL

static PCSTR
kswordArkBugcheckPreparationStageText(
    _In_ ULONG stage
    )
{
    // Convert the stable preparation value to a label that can be read
    // without consulting symbols or source code.
    switch ((KswordArkBgpPreparationStage)stage) {
    case kKswordArkBgpPreparationIdle: return "idle";
    case kKswordArkBgpPreparationResolveFunctions: return "resolve-functions";
    case kKswordArkBgpPreparationReadScreen: return "read-screen";
    case kKswordArkBgpPreparationBackendReady: return "backend-ready";
    case kKswordArkBgpPreparationValidatePanelScreen: return "validate-panel-screen";
    case kKswordArkBgpPreparationPrepareLogo: return "prepare-logo";
    case kKswordArkBgpPreparationPrepareGlyphs: return "prepare-glyphs";
    case kKswordArkBgpPreparationArm: return "arm";
    case kKswordArkBgpPreparationComplete: return "complete";
    default: return "unknown";
    }
}

static PCSTR
kswordArkBugcheckBgpStateText(
    _In_ ULONG state
    )
{
    // Convert the BGP state machine value to a stable report label.
    switch ((KswordArkBgpState)state) {
    case kKswordArkBgpStateUninitialized: return "uninitialized";
    case kKswordArkBgpStateQueryOnly: return "query-only";
    case kKswordArkBgpStateReady: return "ready";
    case kKswordArkBgpStateArmed: return "armed";
    case kKswordArkBgpStateDrawn: return "drawn";
    case kKswordArkBgpStateRejected: return "rejected";
    case kKswordArkBgpStateUnloading: return "unloading";
    default: return "unknown";
    }
}

static NTSTATUS
kswordArkBugcheckWritePreparationText(
    _In_reads_bytes_(textLength) PCSTR text,
    _In_ ULONG textLength
    )
{
    UNICODE_STRING reportPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle;
    NTSTATUS status;

    // Reject invalid input before creating or replacing the report file.
    if (text == NULL || textLength == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use a kernel handle and a synchronous write-through file so the report
    // remains available even when the later test immediately crashes Windows.
    RtlInitUnicodeString(
        &reportPath,
        KSWORD_ARK_BGP_PREPARATION_LOG_PATH);
    InitializeObjectAttributes(
        &objectAttributes,
        &reportPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    fileHandle = NULL;
    status = ZwCreateFile(
        &fileHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_WRITE_THROUGH,
        NULL,
        0UL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Write the report in one operation. FILE_WRITE_THROUGH and synchronous
    // close complete the write before initialization returns to the framework.
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwWriteFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        (PVOID)text,
        textLength,
        NULL,
        NULL);
    if (NT_SUCCESS(status) && ioStatus.Information != textLength) {
        status = STATUS_DEVICE_DATA_ERROR;
    }
    // Close the private kernel handle on every post-create path.
    ZwClose(fileHandle);
    return status;
}

NTSTATUS
kswordArkBugcheckWritePreparationLog(
    _In_ NTSTATUS bgpInitializeStatus,
    _In_ NTSTATUS panelInitializeStatus,
    _In_ NTSTATUS callbackRegistrationStatus
    )
{
    KswordArkBgpDumpState snapshot;
    CHAR report[KSWORD_ARK_BGP_PREPARATION_LOG_CAPACITY];
    SIZE_T reportLength;
    ULONG osMajor;
    ULONG osMinor;
    ULONG osBuild;
    NTSTATUS status;

    // Snapshot only the preallocated nonpaged state after all preparation and
    // callback registration attempts have completed.
    RtlZeroMemory(&snapshot, sizeof(snapshot));
    kswordArkBugcheckBgpSnapshot(&snapshot);
    osMajor = 0UL;
    osMinor = 0UL;
    osBuild = 0UL;
    (VOID)PsGetVersion(&osMajor, &osMinor, &osBuild, NULL);

    // Format a self-contained ASCII report that PowerShell or Notepad can read
    // directly after the driver is loaded on the target machine.
    RtlZeroMemory(report, sizeof(report));
    status = RtlStringCbPrintfA(
        report,
        sizeof(report),
        "KswordARK BGP preparation report v1\r\n"
        "secondary_dump_data_version=3\r\n"
        "os_version=%lu.%lu.%lu\r\n"
        "bgp_initialize_status=0x%08lX\r\n"
        "panel_initialize_status=0x%08lX\r\n"
        "callback_registration_status=0x%08lX\r\n"
        "state=%lu (%s)\r\n"
        "preparation_stage=%lu (%s)\r\n"
        "preparation_status=0x%08lX\r\n"
        "crash_stage=0x%08lX\r\n"
        "last_status=0x%08lX\r\n"
        "feature_mask=0x%08lX\r\n"
        "screen=%lux%lux%lu\r\n"
        "last_probe=%lux%lux%lu\r\n"
        "required=%lux%lu\r\n"
        "signature_family_clear=%lu\r\n"
        "signature_family_draw=%lu\r\n"
        "signature_family_acquire=%lu\r\n"
        "signature_family_release=%lu\r\n"
        "signature_family_resolution=%lu\r\n"
        "signature_family_bpp=%lu\r\n"
        "signature_family_parse=%lu\r\n"
        "signature_family_destroy=%lu\r\n"
        "callback_classic=%lu\r\n"
        "callback_secondary=%lu\r\n"
        "callback_dump_io=%lu\r\n"
        "callback_triage=%lu\r\n"
        "logo_source=qrc KswordHome-En.png -> embedded main_logo_bitmap.h\r\n"
        "runtime_bmp_file_dependency=none\r\n",
        osMajor,
        osMinor,
        osBuild,
        (ULONG)bgpInitializeStatus,
        (ULONG)panelInitializeStatus,
        (ULONG)callbackRegistrationStatus,
        snapshot.state,
        kswordArkBugcheckBgpStateText(snapshot.state),
        snapshot.preparationStage,
        kswordArkBugcheckPreparationStageText(snapshot.preparationStage),
        snapshot.preparationStatus,
        snapshot.stage,
        snapshot.lastStatus,
        snapshot.featureMask,
        snapshot.screenWidth,
        snapshot.screenHeight,
        snapshot.screenBpp,
        gKswordArkBgp.probeWidth,
        gKswordArkBgp.probeHeight,
        gKswordArkBgp.probeBpp,
        snapshot.requiredWidth,
        snapshot.requiredHeight,
        snapshot.signatureFamily[0],
        snapshot.signatureFamily[1],
        snapshot.signatureFamily[2],
        snapshot.signatureFamily[3],
        snapshot.signatureFamily[4],
        snapshot.signatureFamily[5],
        snapshot.signatureFamily[6],
        snapshot.signatureFamily[7],
        gKswordArkBugcheckState.classicRegistered ? 1UL : 0UL,
        gKswordArkBugcheckState.secondaryRegistered ? 1UL : 0UL,
        gKswordArkBugcheckState.dumpIoRegistered ? 1UL : 0UL,
        gKswordArkBugcheckState.triageRegistered ? 1UL : 0UL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Measure the completed report and narrow the known 2 KiB bound to the
    // ULONG byte count accepted by ZwWriteFile.
    reportLength = 0U;
    status = RtlStringCbLengthA(report, sizeof(report), &reportLength);
    if (!NT_SUCCESS(status) || reportLength == 0U || reportLength > MAXULONG) {
        return NT_SUCCESS(status) ? STATUS_INVALID_BUFFER_SIZE : status;
    }

    return kswordArkBugcheckWritePreparationText(
        report,
        (ULONG)reportLength);
}
