/*++

Module Name:

    injection_ioctl.c

Abstract:

    IOCTL handlers for the injection-trace scan backend.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkInjectionIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format injection scan IOCTL logs. Note: Logs are for diagnostics only and do not affect the IOCTL completion status.

Return Value:

    None.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkInjectionIoctlEnumerateProcessVad(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD.

Return Value:

    NTSTATUS indicates the result of buffer validation or query execution.

--*/
{
    KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 enum-vad ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED uses the same SystemBuffer for input and output. The backend zeroes the entire output buffer first, which erases the pid and range
     * from the request at that moment — a snapshot must be taken beforehand. A bug in the repository caused a BSOD (0x50) due to missing this step.
     */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 enum-vad ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateProcessVad(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(
            device,
            "Error",
            "R0 enum-vad failed: pid=%lu, status=0x%08X.",
            (unsigned long)requestSnapshot.processId,
            (unsigned int)status);
        return status;
    }

    kswordArkInjectionIoctlLog(
        device,
        "Info",
        "R0 enum-vad completed: pid=%lu, bytes=%llu.",
        (unsigned long)requestSnapshot.processId,
        (unsigned long long)*bytesReturned);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkInjectionIoctlScanExecutablePte(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE.

Return Value:

    NTSTATUS indicates the result of buffer validation or scan execution.

--*/
{
    KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 scan-exec-pte ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 scan-exec-pte ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverScanProcessExecutablePte(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(
            device,
            "Error",
            "R0 scan-exec-pte failed: pid=%lu, status=0x%08X.",
            (unsigned long)requestSnapshot.processId,
            (unsigned int)status);
        return status;
    }

    kswordArkInjectionIoctlLog(
        device,
        "Info",
        "R0 scan-exec-pte completed: pid=%lu, bytes=%llu.",
        (unsigned long)requestSnapshot.processId,
        (unsigned long long)*bytesReturned);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkInjectionIoctlReadImageSectionPages(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES.

    METHOD_BUFFERED input and output share the same SystemBuffer, so **the request must be snapshot
    first** before accessing the output buffer — the input may be overwritten at the moment the
    output is accessed. This rule was learned at the cost of a single 0x50 BSOD in this repository.

Return Value:

    NTSTATUS indicates the result of buffer validation or read execution.

--*/
{
    KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 read-section-pages ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(device, "Error", "R0 read-section-pages ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverReadImageSectionPages(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkInjectionIoctlLog(
            device,
            "Error",
            "R0 read-section-pages failed: pid=%lu, status=0x%08X.",
            (unsigned long)requestSnapshot.processId,
            (unsigned int)status);
        return status;
    }

    kswordArkInjectionIoctlLog(
        device,
        "Info",
        "R0 read-section-pages completed: pid=%lu, bytes=%llu.",
        (unsigned long)requestSnapshot.processId,
        (unsigned long long)*bytesReturned);
    return STATUS_SUCCESS;
}
