/*++

Module Name:

    hwid_dispatch_ioctl.c

Abstract:

    IOCTL handlers for the dispatch-function HWID integration page.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_safety.h"
#include "../../dispatch/ioctl_validation.h"
#include "driver/KswordArkHwidIoctl.h"
#include "hwid_dispatch_hooks.h"

#include <ntstrsafe.h>
#include <stdarg.h>

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING objectName,
    _In_ ULONG attributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Inout_opt_ PVOID parseContext,
    _Out_ PVOID* object
    );

extern POBJECT_TYPE* IoDriverObjectType;

typedef struct KswHwidDispatchSlot
{
    ULONG targetFlag;
    PCWSTR driverName;
    PDRIVER_OBJECT driverObject;
    PDRIVER_DISPATCH originalDispatch;
    NTSTATUS lastStatus;
    BOOLEAN active;
} KswHwidDispatchSlot, *PkswHwidDispatchSlot;

static FAST_MUTEX gKswordHwidDispatchLock;
static volatile LONG gKswordHwidDispatchInitialized = 0;
static ULONG gKswordHwidDispatchGeneration = 1UL;
static KSWORD_ARK_HWID_DISPATCH_PROFILE gKswordHwidActiveProfile;
static KswHwidDispatchSlot gKswordHwidSlots[KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT] = {
    { KSWORD_ARK_HWID_DISPATCH_TARGET_DISK, L"\\Driver\\Disk", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR, L"\\Driver\\partmgr", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR, L"\\Driver\\mountmgr", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA, L"\\Driver\\nvlddmkm", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY, L"\\Driver\\nsiproxy", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE }
};

static VOID
kswordArkHwidLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static VOID
kswordArkHwidEnsureInitialized(
    VOID
    )
{
    if (InterlockedCompareExchange(&gKswordHwidDispatchInitialized, 1L, 0L) == 0L) {
        ExInitializeFastMutex(&gKswordHwidDispatchLock);
        RtlZeroMemory(&gKswordHwidActiveProfile, sizeof(gKswordHwidActiveProfile));
        gKswordHwidActiveProfile.size = sizeof(gKswordHwidActiveProfile);
        gKswordHwidActiveProfile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
        InterlockedExchange(&gKswordHwidDispatchInitialized, 2L);
    }
    else {
        while (gKswordHwidDispatchInitialized != 2L) {
            YieldProcessor();
        }
    }
}

static VOID
kswordArkHwidNormalizeProfile(
    _Out_ KSWORD_ARK_HWID_DISPATCH_PROFILE* destination,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* source
    );

static KswHwidDispatchSlot*
kswordArkHwidFindSlotNoLock(
    _In_opt_ PDRIVER_OBJECT driverObject
    )
{
    ULONG slotIndex = 0UL;

    if (driverObject == NULL) {
        return NULL;
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        if (gKswordHwidSlots[slotIndex].driverObject == driverObject &&
            gKswordHwidSlots[slotIndex].originalDispatch != NULL) {
            return &gKswordHwidSlots[slotIndex];
        }
    }

    return NULL;
}

static NTSTATUS
kswordArkHwidDispatchPassthrough(
    _In_ PDEVICE_OBJECT device,
    _Inout_ PIRP irp
    )
{
    PDRIVER_DISPATCH originalDispatch = NULL;
    KswHwidDispatchSlot* targetSlot = NULL;
    PIO_STACK_LOCATION ioStack = NULL;
    KSWORD_ARK_HWID_DISPATCH_PROFILE activeProfile;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;

    RtlZeroMemory(&activeProfile, sizeof(activeProfile));
    if (device != NULL) {
        targetSlot = kswordArkHwidFindSlotNoLock(device->DriverObject);
        if (targetSlot != NULL) {
            originalDispatch = targetSlot->originalDispatch;
        }
    }

    if (originalDispatch != NULL) {
        if (irp != NULL && targetSlot != NULL) {
            ioStack = IoGetCurrentIrpStackLocation(irp);
            kswordArkHwidNormalizeProfile(&activeProfile, &gKswordHwidActiveProfile);
            (VOID)kswordArkHwidPrepareDispatchCompletion(
                irp,
                ioStack,
                targetSlot->targetFlag,
                &activeProfile);
        }
        return originalDispatch(device, irp);
    }

    if (irp != NULL) {
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = 0U;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    return status;
}

static NTSTATUS
kswordArkHwidReferenceDriverObject(
    _In_z_ PCWSTR driverName,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )
{
    UNICODE_STRING objectName;

    if (driverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    if (driverName == NULL || IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&objectName, driverName);
    return ObReferenceObjectByName(
        &objectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)driverObjectOut);
}

static VOID
kswordArkHwidCopyBoundedText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyW(destination, (SIZE_T)destinationChars * sizeof(WCHAR), source);
    destination[destinationChars - 1UL] = L'\0';
}

static VOID
kswordArkHwidNormalizeProfile(
    _Out_ KSWORD_ARK_HWID_DISPATCH_PROFILE* destination,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* source
    )
{
    if (destination == NULL || source == NULL) {
        return;
    }

    RtlCopyMemory(destination, source, sizeof(*destination));
    destination->size = sizeof(*destination);
    destination->version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    destination->diskSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    destination->diskProduct[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    destination->diskRevision[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    destination->gpuSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    destination->permanentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    destination->currentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
}

static NTSTATUS
kswordArkHwidInstallSlot(
    _Inout_ KswHwidDispatchSlot* slot,
    _In_ BOOLEAN dryRun
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (slot->active != FALSE) {
        slot->lastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    status = kswordArkHwidReferenceDriverObject(slot->driverName, &driverObject);
    slot->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (dryRun != FALSE) {
        ObDereferenceObject(driverObject);
        slot->lastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    slot->originalDispatch = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    if (slot->originalDispatch == NULL) {
        ObDereferenceObject(driverObject);
        slot->originalDispatch = NULL;
        slot->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = kswordArkHwidDispatchPassthrough;
    slot->driverObject = driverObject;
    slot->active = TRUE;
    slot->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkHwidRemoveSlot(
    _Inout_ KswHwidDispatchSlot* slot,
    _Inout_ ULONG* responseFlags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT driverObject = NULL;

    if (slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (slot->active == FALSE) {
        slot->lastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    driverObject = slot->driverObject;
    if (driverObject == NULL || slot->originalDispatch == NULL) {
        slot->driverObject = NULL;
        slot->originalDispatch = NULL;
        slot->active = FALSE;
        slot->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == kswordArkHwidDispatchPassthrough) {
        driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = slot->originalDispatch;
    }
    else {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        if (responseFlags != NULL) {
            *responseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
    }

    ObDereferenceObject(driverObject);
    slot->driverObject = NULL;
    slot->originalDispatch = NULL;
    slot->active = FALSE;
    slot->lastStatus = status;
    return status;
}

static VOID
kswordArkHwidFillResponseLocked(
    _Out_ KSWORD_ARK_HWID_DISPATCH_RESPONSE* response,
    _In_ ULONG requestedTargetFlags,
    _In_ ULONG failedTargetFlags,
    _In_ ULONG extraResponseFlags,
    _In_ NTSTATUS lastStatus
    )
{
    ULONG slotIndex = 0UL;
    ULONG activeFlags = 0UL;

    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    response->supportedTargetFlags = KSWORD_ARK_HWID_DISPATCH_TARGET_ALL;
    response->requestedTargetFlags = requestedTargetFlags;
    response->failedTargetFlags = failedTargetFlags;
    response->generation = gKswordHwidDispatchGeneration;
    response->lastStatus = lastStatus;
    response->responseFlags = extraResponseFlags;
    kswordArkHwidNormalizeProfile(&response->activeProfile, &gKswordHwidActiveProfile);

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KSWORD_ARK_HWID_DISPATCH_ENTRY* entry = &response->entries[slotIndex];
        KswHwidDispatchSlot* slot = &gKswordHwidSlots[slotIndex];
        entry->size = sizeof(*entry);
        entry->targetFlag = slot->targetFlag;
        entry->active = slot->active != FALSE ? 1UL : 0UL;
        entry->lastStatus = slot->lastStatus;
        entry->driverObjectAddress = (ULONGLONG)(ULONG_PTR)slot->driverObject;
        entry->originalDispatchAddress = (ULONGLONG)(ULONG_PTR)slot->originalDispatch;
        entry->currentDispatchAddress = slot->driverObject != NULL ?
            (ULONGLONG)(ULONG_PTR)slot->driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] : 0ULL;
        kswordArkHwidCopyBoundedText(entry->driverName, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS, slot->driverName);
        if (slot->active != FALSE) {
            activeFlags |= slot->targetFlag;
        }
    }

    response->activeTargetFlags = activeFlags;
    if (failedTargetFlags != 0UL && activeFlags != 0UL) {
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_PARTIAL;
        response->responseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_PARTIAL;
    }
    else if (failedTargetFlags != 0UL) {
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_FAILED;
    }
    else if (activeFlags != 0UL) {
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_ACTIVE;
    }
    else {
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_READY;
    }
}

static NTSTATUS
kswordArkHwidControlLocked(
    _In_ const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_HWID_DISPATCH_RESPONSE* response
    )
{
    ULONG slotIndex = 0UL;
    ULONG targetFlags = 0UL;
    ULONG failedFlags = 0UL;
    ULONG responseFlags = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    BOOLEAN dryRun = FALSE;

    targetFlags = request->profile.targetFlags & KSWORD_ARK_HWID_DISPATCH_TARGET_ALL;
    dryRun = ((request->requestFlags & KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN) != 0UL) ? TRUE : FALSE;
    if (dryRun != FALSE) {
        responseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_DRY_RUN;
    }

    if (targetFlags == 0UL && request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL) {
        kswordArkHwidFillResponseLocked(response, request->profile.targetFlags, request->profile.targetFlags, responseFlags, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE && dryRun == FALSE) {
        kswordArkHwidNormalizeProfile(&gKswordHwidActiveProfile, &request->profile);
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KswHwidDispatchSlot* slot = &gKswordHwidSlots[slotIndex];
        if (request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL &&
            (slot->targetFlag & targetFlags) == 0UL) {
            continue;
        }
        if (request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE) {
            lastStatus = kswordArkHwidInstallSlot(slot, dryRun);
        }
        else if (request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE ||
            request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL) {
            lastStatus = dryRun != FALSE ? STATUS_SUCCESS : kswordArkHwidRemoveSlot(slot, &responseFlags);
        }
        else if (request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY) {
            lastStatus = STATUS_SUCCESS;
        }
        else {
            lastStatus = STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(lastStatus)) {
            failedFlags |= slot->targetFlag;
        }
    }

    if (dryRun == FALSE && request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY) {
        ++gKswordHwidDispatchGeneration;
    }

    kswordArkHwidFillResponseLocked(response, targetFlags, failedFlags, responseFlags, lastStatus);
    return failedFlags == 0UL ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
kswordArkHwidIoctlQueryDispatch(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_HWID_DISPATCH_RESPONSE* response = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    size_t actualOutputLength = 0U;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    kswordArkHwidEnsureInitialized();

    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(*response), (PVOID*)&response, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquireFastMutex(&gKswordHwidDispatchLock);
    kswordArkHwidFillResponseLocked(response, 0UL, 0UL, 0UL, STATUS_SUCCESS);
    ExReleaseFastMutex(&gKswordHwidDispatchLock);

    *bytesReturned = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHwidIoctlControlDispatch(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST* controlRequest = NULL;
    // requestSnapshot: Save the complete request before writing the response; the response and request share the same SystemBuffer.
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST requestSnapshot;
    KSWORD_ARK_HWID_DISPATCH_RESPONSE* response = NULL;
    KswordArkSafetyContext safetyContext;
    NTSTATUS status = STATUS_SUCCESS;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    static const WCHAR kTargetText[] = L"HWID dispatch MajorFunction hook";

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    kswordArkHwidEnsureInitialized();

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(*controlRequest), (PVOID*)&controlRequest, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. After kswordArkHwidFillResponseLocked writes the response,
     * this function must read the action for logging; without a snapshot, the logs would contain only response header bytes.
     */
    RtlCopyMemory(&requestSnapshot, controlRequest, sizeof(requestSnapshot));
    controlRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(*response), (PVOID*)&response, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (controlRequest->size < sizeof(*controlRequest) ||
        controlRequest->version != KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION ||
        controlRequest->profile.size < sizeof(controlRequest->profile) ||
        controlRequest->profile.version != KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION) {
        ExAcquireFastMutex(&gKswordHwidDispatchLock);
        kswordArkHwidFillResponseLocked(response, 0UL, 0UL, 0UL, STATUS_INVALID_PARAMETER);
        ExReleaseFastMutex(&gKswordHwidDispatchLock);
        *bytesReturned = sizeof(*response);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.contextFlags =
        ((controlRequest->requestFlags & KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED) != 0UL) ?
        KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED : 0UL;
    safetyContext.targetText = kTargetText;
    safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(kTargetText) - 1U);
    status = kswordArkSafetyEvaluate(device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        ExAcquireFastMutex(&gKswordHwidDispatchLock);
        kswordArkHwidFillResponseLocked(response, controlRequest->profile.targetFlags, controlRequest->profile.targetFlags, 0UL, status);
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_DENIED;
        ExReleaseFastMutex(&gKswordHwidDispatchLock);
        *bytesReturned = sizeof(*response);
        kswordArkHwidLog(device, "Warn", "R0 HWID dispatch denied by safety policy, status=0x%08X.", (unsigned int)status);
        return status;
    }

    ExAcquireFastMutex(&gKswordHwidDispatchLock);
    status = kswordArkHwidControlLocked(controlRequest, response);
    ExReleaseFastMutex(&gKswordHwidDispatchLock);

    *bytesReturned = sizeof(*response);
    kswordArkHwidLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 HWID dispatch action=%lu status=0x%08X active=0x%08X failed=0x%08X.",
        (unsigned long)controlRequest->action,
        (unsigned int)status,
        (unsigned int)response->activeTargetFlags,
        (unsigned int)response->failedTargetFlags);
    return status;
}
