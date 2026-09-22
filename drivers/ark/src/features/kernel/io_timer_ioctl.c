/*++

Module Name:

    io_timer_ioctl.c

Abstract:

    User-confirmed IoTimer start/stop control with exact object identity checks.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* Note: The device object array is allocated from non-paged pool and uses a dedicated tag for pool leak detection. */
#define KSW_IO_TIMER_DEVICE_LIST_TAG 'rTIK'
/* Note: Complexity limit prevents unbounded growth of single-control allocations due to anomalous DriverObject. */
#define KSW_IO_TIMER_DEVICE_LIMIT 1024UL
/* Note: Device creation races are retried only a limited number of times; exceeding this limit rejects modifications due to unstable identity. */
#define KSW_IO_TIMER_ENUM_RETRY_LIMIT 3UL

/* Note: Retrieve the DriverObject by name to avoid directly dereferencing kernel addresses provided by R3. */
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

/* Note: DriverObject object type exported by the I/O manager. */
extern POBJECT_TYPE* IoDriverObjectType;

/* Note: Release the references added by IoEnumerateDeviceObjectList for each returned object. */
static VOID
kswordArkIoTimerReleaseDeviceList(
    _Inout_updates_(capacity) PDEVICE_OBJECT* deviceObjects,
    _In_ ULONG capacity
    )
{
    ULONG deviceIndex = 0UL;

    /* Note: The failure cleanup path allows passing a null array. */
    if (deviceObjects == NULL) {
        /* Note: Empty arrays contain no object references. */
        return;
    }
    /* Note: Traversing the capacity covers partial results for both success and BUFFER_TOO_SMALL. */
    for (deviceIndex = 0UL; deviceIndex < capacity; ++deviceIndex) {
        /* Note: Null slots after zero-initialization have no references. */
        if (deviceObjects[deviceIndex] == NULL) {
            /* Note: Skip slots not populated by the enumeration API. */
            continue;
        }
        /* Note: Release the reference added by IoEnumerateDeviceObjectList. */
        ObDereferenceObject(deviceObjects[deviceIndex]);
        /* Note: Clear the slot to keep cleanup idempotent. */
        deviceObjects[deviceIndex] = NULL;
    }
}

/* Note: Use the official reference-counted snapshot lookup to find the precise DeviceObject without chasing unstable NextDevice pointers. */
static NTSTATUS
kswordArkIoTimerReferenceExpectedDevice(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONGLONG expectedDeviceObjectAddress,
    _Outptr_ PDEVICE_OBJECT* deviceObjectOut
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attemptIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Output is always zeroed first; the caller obtains an object reference only on success. */
    if (driverObject == NULL || deviceObjectOut == NULL ||
        expectedDeviceObjectAddress == 0ULL) {
        /* Note: Reject enumeration if any identity parameter is missing. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: The default failure path does not leak dangling pointers to the caller. */
    *deviceObjectOut = NULL;

    /* Note: The first call only queries the number of devices currently owned by the DriverObject. */
    status = IoEnumerateDeviceObjectList(
        driverObject,
        NULL,
        0UL,
        &requestedCount);
    /* Note: Zero-capacity probing typically returns BUFFER_TOO_SMALL; other failures are reported directly. */
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        /* Note: Preserve the I/O manager's original failure status. */
        return status;
    }
    /* Note: Target snapshot is invalid when no device object exists. */
    if (requestedCount == 0UL) {
        /* Note: Use NOT_FOUND to distinguish between 'driver exists but device has disappeared'. */
        return STATUS_NOT_FOUND;
    }

    /* Note: Device creation races can cause capacity to grow between calls, so limit retries. */
    for (attemptIndex = 0UL;
        attemptIndex < KSW_IO_TIMER_ENUM_RETRY_LIMIT;
        ++attemptIndex) {
        ULONG deviceIndex = 0UL;

        /* Note: Reject overly complex objects to prevent unbounded allocation in a single IOCTL. */
        if (requestedCount > KSW_IO_TIMER_DEVICE_LIMIT) {
            /* Note: The UI can refresh to narrow the scope, but R0 does not perform incomplete control. */
            return STATUS_BUFFER_OVERFLOW;
        }

        /* Note: Official API requires DeviceObject pointer array to reside in non-paged memory. */
        deviceObjects = (PDEVICE_OBJECT*)kswordArkAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_IO_TIMER_DEVICE_LIST_TAG);
        /* Note: Do not trigger any target callbacks on allocation failure. */
        if (deviceObjects == NULL) {
            /* Note: Report explicit insufficient resources to R3. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Note: Zeroing ensures safe scanning by capacity after partial fill and reference release. */
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        /* Note: The I/O manager fills in the actual object count in each iteration. */
        actualCount = 0UL;
        /* Note: Each object returned successfully holds a reference and will not be released during control. */
        status = IoEnumerateDeviceObjectList(
            driverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        /* Note: On capacity growth, fully release the partial references from the current round before retrying. */
        if (status == STATUS_BUFFER_TOO_SMALL) {
            /* Note: Return each non-null object reference from this round. */
            kswordArkIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* Note: Free the old capacity array. */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* Note: Clear local pointers to avoid double-free on failure paths. */
            deviceObjects = NULL;
            /* Note: The actual count must increase to constitute a valid retryable race condition. */
            if (actualCount <= requestedCount) {
                /* Note: Inconsistent results indicate abnormal changes in object topology. */
                return STATUS_INVALID_DEVICE_STATE;
            }
            /* Note: Allocate based on the new count returned by the API in the next iteration. */
            requestedCount = actualCount;
            /* Note: Proceed to the next limited retry. */
            continue;
        }
        /* Note: Other enumeration failures must also release any references that may have already been populated. */
        if (!NT_SUCCESS(status)) {
            /* Note: Free all non-empty slots. */
            kswordArkIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* Note: Free the pointer array itself. */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* Note: Preserve the exact failure status. */
            return status;
        }

        /* Note: On success, actualCount should not exceed the allocated capacity. */
        if (actualCount > requestedCount) {
            /* Note: Release all references before reporting inconsistency. */
            kswordArkIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* Note: Free pointer array. */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* Note: Do not perform modifications on an incomplete snapshot. */
            return STATUS_INVALID_DEVICE_STATE;
        }

        /* Note: Only compare user addresses with already-referenced object pointers numerically; never directly dereference user addresses. */
        for (deviceIndex = 0UL; deviceIndex < actualCount; ++deviceIndex) {
            /* Note: Defensive skip of empty slots returned by the API. */
            if (deviceObjects[deviceIndex] == NULL) {
                /* Note: Continue checking other referenced objects. */
                continue;
            }
            /* Note: Precisely match the DeviceObject identity recorded during refresh. */
            if ((ULONGLONG)(ULONG_PTR)deviceObjects[deviceIndex] ==
                expectedDeviceObjectAddress) {
                /* Note: Transfer the reference to the caller; the release function must not process it further. */
                *deviceObjectOut = deviceObjects[deviceIndex];
                /* Note: Clearing the slot indicates that reference ownership has been transferred. */
                deviceObjects[deviceIndex] = NULL;
                /* Note: No need to continue scanning after a successful match. */
                break;
            }
        }

        /* Note: Release all snapshot references except the target. */
        kswordArkIoTimerReleaseDeviceList(deviceObjects, requestedCount);
        /* Note: Free temporary pointer array. */
        ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
        /* Note: Prevent subsequent paths from misusing the released array. */
        deviceObjects = NULL;
        /* Note: Caller holds the target reference on hit. */
        if (*deviceObjectOut != NULL) {
            /* Note: Stable identity snapshot established. */
            return STATUS_SUCCESS;
        }
        /* Note: If the address is not found in the complete snapshot, the device has been deleted or rebuilt. */
        return STATUS_NOT_FOUND;
    }

    /* Note: Rejects modification on unstable topology when continuous growth exceeds the retry budget. */
    return STATUS_RETRY;
}

/* Note: Validate version, action, confirmation token, and name terminator in fixed requests. */
static NTSTATUS
kswordArkIoTimerValidateRequest(
    _In_ const KSWORD_ARK_CONTROL_IO_TIMER_REQUEST* request,
    _Out_ size_t* driverNameCharsOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: All fixed parameters must be present. */
    if (request == NULL || driverNameCharsOut == NULL) {
        /* Note: Missing request or length output is a programming error. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: Default length is zero; uninitialized values are not used on failure. */
    *driverNameCharsOut = 0U;
    /* Note: Accept only the current protocol version. */
    if (request->version != KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION) {
        /* Note: Do not misinterpret old or future requests. */
        return STATUS_REVISION_MISMATCH;
    }
    /* Note: Only allow WDM-defined START and STOP actions. */
    if (request->action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START &&
        request->action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP) {
        /* Note: Unknown actions must never be downgraded for execution. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: Unknown flags may alter security semantics, so reject all. */
    if ((request->flags & ~KSWORD_ARK_IO_TIMER_CONTROL_FLAG_UI_CONFIRMED) != 0UL) {
        /* Note: Only the currently defined UI confirmed flag is valid. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: The kernel also requires explicit UI confirmation; button state alone is insufficient. */
    if ((request->flags & KSWORD_ARK_IO_TIMER_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        request->confirmationToken != KSWORD_ARK_IO_TIMER_CONTROL_CONFIRMATION_TOKEN) {
        /* Note: Reject modifications if the token or acknowledgment bit is missing. */
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    /* Note: All three identity snapshot fields must be non-zero. */
    if (request->expectedDriverObjectAddress == 0ULL ||
        request->expectedDeviceObjectAddress == 0ULL ||
        request->expectedTimerAddress == 0ULL) {
        /* Note: Wildcards or null addresses are not allowed for control. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: Verify fixed-name array contains NUL within bounds. */
    status = RtlStringCchLengthW(
        request->driverName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        driverNameCharsOut);
    /* Note: Non-terminated strings cannot be passed to the object manager. */
    if (!NT_SUCCESS(status)) {
        /* Note: Preserve the exact state of ntstrsafe. */
        return status;
    }
    /* Note: The control protocol accepts only absolute paths in the object namespace. */
    if (*driverNameCharsOut == 0U || request->driverName[0] != L'\\') {
        /* Note: Disable bare name fallback to avoid ambiguity in resolving objects with the same name. */
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    /* Note: The request satisfies fixed protocol constraints. */
    return STATUS_SUCCESS;
}

/* Note: Handles IoTimer start/stop; all business logic resides in the feature handler. */
NTSTATUS
kswordArkKernelIoctlControlIoTimer(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t driverNameChars = 0U;
    KSWORD_ARK_CONTROL_IO_TIMER_REQUEST requestSnapshot;
    KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE* response = NULL;
    UNICODE_STRING driverObjectName;
    PDRIVER_OBJECT driverObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Risk is communicated to the user by R3 only; R0 does not set additional feature thresholds based on risk level. */
    UNREFERENCED_PARAMETER(device);
    /* Note: Caller must provide a pointer to store return length. */
    if (bytesReturned == NULL) {
        /* Unable to safely complete the WDF request. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: All failure paths default to not returning uninitialized data. */
    *bytesReturned = 0U;
    /* Note: Both the CTL_CODE and the request handle must have write access. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Note: Access denied occurs before resolving any target identity. */
    if (!NT_SUCCESS(status)) {
        /* Note: Preserve WDF/security check status. */
        return status;
    }
    /* Note: Retrieve the complete fixed-size request buffer. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Note: Verify both the length provided by the dispatch and the actual length from WDF simultaneously. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST)) {
        /* Note: On success but insufficient length, uniformly return STATUS_INFO_LENGTH_MISMATCH. */
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    /* Note: Retrieve the complete fixed-size response buffer. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Note: Do not execute any control actions if the output is insufficient. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE)) {
        /* Note: Preserve WDF status or return BUFFER_TOO_SMALL. */
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* Note: METHOD_BUFFERED input and output may share SystemBuffer; copy the request before zeroing. */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    /* Note: The response exposes only the identity and state observed in this re-observation. */
    response = (KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE*)outputBuffer;
    /* Note: Clear old requests and uninitialized tail in the shared buffer. */
    RtlZeroMemory(response, sizeof(*response));
    /* Note: Set the fixed response version. */
    response->version = KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION;
    /* Note: Set fixed response size for R3 validation. */
    response->size = sizeof(*response);
    /* Note: Action echo helps the UI attribute results after asynchronous refresh. */
    response->action = requestSnapshot.action;
    /* Note: After completing the fixed response, a semantic failure also returns a parsable status packet. */
    *bytesReturned = sizeof(*response);

    /* Note: Validate version, action, token, address, and object name first. */
    status = kswordArkIoTimerValidateRequest(
        &requestSnapshot,
        &driverNameChars);
    /* Note: Malformed requests do not enter the object manager or touch the target object. */
    if (!NT_SUCCESS(status)) {
        /* Note: Record protocol-level failure. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST;
        /* Note: Retain precise NTSTATUS for UI diagnostics. */
        response->lastStatus = status;
        /* Note: Successful transmission enables R3 to read structured semantic errors. */
        return STATUS_SUCCESS;
    }

    /* Note: Construct a validated, NUL-terminated object name. */
    RtlInitUnicodeString(&driverObjectName, requestSnapshot.driverName);
    /* Note: Do not attempt untyped references when object type exports are unavailable. */
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        /* Note: Classify missing platform support as an unresolvable driver object. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND;
        /* Note: Use NOT_SUPPORTED to indicate that the error is not due to an invalid user address. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Note: The fixed response can be safely returned. */
        return STATUS_SUCCESS;
    }
    /* Note: Obtain a reference to the DriverObject protected by the Object Manager using its absolute name. */
    status = ObReferenceObjectByName(
        &driverObjectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0UL,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&driverObject);
    /* Note: Do not fall back to R3 address when the name disappears or the type does not match. */
    if (!NT_SUCCESS(status)) {
        /* Note: Return a semantic status indicating the object has disappeared. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND;
        /* Note: Preserve the object manager failure status. */
        response->lastStatus = status;
        /* Note: No reference acquired; cleanup is unnecessary. */
        return STATUS_SUCCESS;
    }

    /* Note: Record the actual DriverObject re-resolved by name in the response. */
    response->observedDriverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    /* Note: A mismatch between the address and the refreshed snapshot indicates the object has been unloaded and its name may have been reused. */
    if (response->observedDriverObjectAddress !=
        requestSnapshot.expectedDriverObjectAddress) {
        /* Note: Reject applying an old snapshot to a new driver with the same name. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_IDENTITY_CHANGED;
        /* Note: Uses retry status to prompt user to refresh. */
        response->lastStatus = STATUS_RETRY;
        /* Note: Release the DriverObject reference obtained by name. */
        ObDereferenceObject(driverObject);
        /* Note: Structured failure packets return normally. */
        return STATUS_SUCCESS;
    }

    /* Note: Obtain an independent reference to the target DeviceObject using the official snapshot API. */
    status = kswordArkIoTimerReferenceExpectedDevice(
        driverObject,
        requestSnapshot.expectedDeviceObjectAddress,
        &deviceObject);
    /* Note: Do not modify the target if it cannot be found in the complete snapshot. */
    if (!NT_SUCCESS(status)) {
        /* Note: NOT_FOUND indicates the old device object has disappeared; other values indicate enumeration failure. */
        response->status = status == STATUS_NOT_FOUND
            ? KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_NOT_FOUND
            : KSWORD_ARK_IO_TIMER_CONTROL_STATUS_ENUMERATION_FAILED;
        /* Note: Preserve the exact enumeration status. */
        response->lastStatus = status;
        /* Note: Device reference not acquired; only release DriverObject. */
        ObDereferenceObject(driverObject);
        /* Note: Structured failure packets return normally. */
        return STATUS_SUCCESS;
    }

    /* Note: Record the actual DeviceObject from the referenced snapshot in the response. */
    response->observedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject;
    /* Note: Re-verify object ownership to defend against anomalous or corrupted device lists. */
    if (deviceObject->DriverObject != driverObject) {
        /* Note: IoStartTimer/IoStopTimer cannot be called when ownership is inconsistent. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_IDENTITY_CHANGED;
        /* Note: Report object type/ownership mismatch. */
        response->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        /* Note: Return the reference to the target DeviceObject. */
        ObDereferenceObject(deviceObject);
        /* Note: Release the DriverObject reference. */
        ObDereferenceObject(driverObject);
        /* Note: Structured failure packets return normally. */
        return STATUS_SUCCESS;
    }

    /* Note: Only read the WDK public DEVICE_OBJECT.Timer field; do not dereference PIO_TIMER. */
    response->observedTimerAddress = (ULONGLONG)(ULONG_PTR)deviceObject->Timer;
    /* Note: A null Timer indicates the driver is not registered or the IoTimer has been cleaned up. */
    if (deviceObject->Timer == NULL) {
        /* Note: Clearly distinguish between a missing timer and an address change. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_NOT_PRESENT;
        /* Note: Use NOT_FOUND to indicate the public field is empty. */
        response->lastStatus = STATUS_NOT_FOUND;
        /* Note: Release the DeviceObject reference. */
        ObDereferenceObject(deviceObject);
        /* Note: Release the DriverObject reference. */
        ObDereferenceObject(driverObject);
        /* Note: Structured failure packets return normally. */
        return STATUS_SUCCESS;
    }
    /* Note: A change in the timer address indicates the original timer has been cleaned up and reinitialized. */
    if (response->observedTimerAddress != requestSnapshot.expectedTimerAddress) {
        /* Note: Reject applying old row control actions to a new timer. */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_IDENTITY_CHANGED;
        /* Prompt for re-confirmation after R3 refresh. */
        response->lastStatus = STATUS_RETRY;
        /* Note: Release the DeviceObject reference. */
        ObDereferenceObject(deviceObject);
        /* Note: Release the DriverObject reference. */
        ObDereferenceObject(driverObject);
        /* Note: Structured failure packets return normally. */
        return STATUS_SUCCESS;
    }

    /* Note: After risk notification, do not reject based on advanced mode or risk level; directly call the public WDM API. */
    if (requestSnapshot.action == KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START) {
        /* Note: Enable callbacks registered by the target driver via IoInitializeTimer. */
        IoStartTimer(deviceObject);
    }
    else {
        /* Note: Can be re-enabled via the same public API after stopping, without modifying private fields. */
        IoStopTimer(deviceObject);
    }

    /* Note: Both WDM APIs return VOID; success indicates the call has been accepted. */
    response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK;
    /* Note: VOID APIs have no runtime return value, so STATUS_SUCCESS is recorded. */
    response->lastStatus = STATUS_SUCCESS;
    /* Note: Release the DeviceObject reference held during control return. */
    ObDereferenceObject(deviceObject);
    /* Note: Release the DriverObject reference held by name. */
    ObDereferenceObject(driverObject);
    /* Note: Fixed response fully written. */
    return STATUS_SUCCESS;
}
