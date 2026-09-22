/*++

Module Name:

    image_callback.c

Abstract:

    Image load callback registration and log-only dispatch.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_bugcheck.h"

VOID
kswordArkLoadImageNotify(
    _In_opt_ PUNICODE_STRING fullImageName,
    _In_ HANDLE processId,
    _In_ PIMAGE_INFO imageInfo
    )
{
    KswordArkCallbackMatchResult matchResult;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    NTSTATUS matchStatus = STATUS_SUCCESS;

    kswordArkBugcheckTrackLoadedImage(fullImageName, processId, imageInfo);

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        NULL);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    if (fullImageName != NULL && fullImageName->Buffer != NULL && fullImageName->Length > 0U) {
        targetPath = *fullImageName;
    }
    else {
        (VOID)RtlStringCbPrintfW(
            targetPathBuffer,
            sizeof(targetPathBuffer),
            L"ProcessId=%lu,ImagePathUnavailable=1",
            (unsigned long)HandleToULong(processId));
        RtlInitUnicodeString(&targetPath, targetPathBuffer);
    }

    // Image telemetry carries load address and size, without waiting for or querying additional user-mode information.
    if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE)) {
        KswordArkCallbackMonitorEventInput monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
        monitorInput.operation = KSWORD_ARK_IMAGE_OP_LOAD;
        monitorInput.originatingProcessId = HandleToULong(PsGetCurrentProcessId());
        monitorInput.originatingThreadId = HandleToULong(PsGetCurrentThreadId());
        monitorInput.targetProcessId = HandleToULong(processId);
        monitorInput.sessionId = kswordArkGetProcessSessionIdSafe(PsGetCurrentProcess());
        monitorInput.detailCode = imageInfo->SystemModeImage != 0U ? 1UL : 0UL;
        monitorInput.address = (ULONG64)(ULONG_PTR)imageInfo->ImageBase;
        monitorInput.regionSize = (ULONG64)imageInfo->ImageSize;
        monitorInput.processName = &initiatorPath;
        monitorInput.path = &targetPath;
        kswordArkCallbackMonitorPublish(&monitorInput);
    }

    matchStatus = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD,
        KSWORD_ARK_IMAGE_OP_LOAD,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.matched) {
        return;
    }

    kswordArkCallbackLogFormat(
        "Info",
        "Image callback log rule hit, processId=%lu, groupId=%lu, ruleId=%lu.",
        (unsigned long)HandleToULong(processId),
        (unsigned long)matchResult.groupId,
        (unsigned long)matchResult.ruleId);
}

NTSTATUS
kswordArkImageCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    status = PsSetLoadImageNotifyRoutine(kswordArkLoadImageNotify);
    if (NT_SUCCESS(status)) {
        // The global runtime is not yet published during registration; logs must explicitly use the runtime version.
        kswordArkCallbackLogFrameForRuntime(runtime, "Info", "Image load callback registered.");
    }
    return status;
}

VOID
kswordArkImageCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(runtime);

    status = PsRemoveLoadImageNotifyRoutine(kswordArkLoadImageNotify);
    if (NT_SUCCESS(status)) {
        kswordArkCallbackLogFrame("Info", "Image load callback unregistered.");
    }
}
