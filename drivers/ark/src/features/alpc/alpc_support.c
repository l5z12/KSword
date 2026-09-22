/*++

Module Name:

    alpc_support.c

Abstract:

    Shared helper routines for Phase-6 ALPC Port inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "alpc_support.h"
#include "ark/ark_push_lock.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#define KSWORD_ARK_ALPC_POOL_TAG 'pAsK'

#ifdef _X86_
#define KSWORD_ARK_KERNEL_HANDLE_BIT ((ULONG_PTR)0x80000000UL)
#else
#define KSWORD_ARK_KERNEL_HANDLE_BIT ((ULONG_PTR)0xFFFFFFFF80000000ULL)
#endif

typedef PVOID
(NTAPI* KswordArkExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

BOOLEAN
kswordArkAlpcIsOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if a DynData offset/shift is usable. Note: Both System Informer and
    Ksword use fixed sentinels to indicate missing fields; this unifies filtering
    here to prevent callers from misinterpreting ALPC_PORT private structures.

Arguments:

    Offset - Original field offset in DynData.

Return Value:

    TRUE indicates the private field is readable; FALSE indicates the field is missing.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkAlpcNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert internal DynData missing sentinel to ALPC protocol sentinel. Note: UI uses these offsets
    only for diagnostic display; offsets or object addresses must not be used as credentials.

Arguments:

    Offset - Original DynData offset.

Return Value:

    Either display the offset or return KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkAlpcIsOffsetPresent(offset)) {
        return KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
    }

    return offset;
}

BOOLEAN
kswordArkAlpcHasRequiredDynData(
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Check fields required by Phase-6 ALPC queries. Reading ALPC relationships touches
    communicationInfo, handleTable, and the port lock; fail closed if any required field is missing.

Arguments:

    DynState: Snapshot of DynData captured at the IOCTL entry point.

Return Value:

    TRUE indicates complete ALPC capability; FALSE indicates private field reads are not executable.

--*/
{
    if (dynState == NULL) {
        return FALSE;
    }

    return ((dynState->capabilityMask & KSW_CAP_ALPC_FIELDS) == KSW_CAP_ALPC_FIELDS) ? TRUE : FALSE;
}

VOID
kswordArkAlpcPrepareOffsets(
    _Inout_ KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE* response,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy ALPC DynData diagnostic fields to the response packet. Note: These fields explain
    why the query is available/unavailable and are not used in subsequent R3 operations.

Arguments:

    Response - Writable response packet.
    DynState - Snapshot of DynData.

Return Value:

    None. This function has no return value.

--*/
{
    if (response == NULL || dynState == NULL) {
        return;
    }

    response->dynDataCapabilityMask = dynState->capabilityMask;
    response->alpcCommunicationInfoOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcCommunicationInfo);
    response->alpcOwnerProcessOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcOwnerProcess);
    response->alpcConnectionPortOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcConnectionPort);
    response->alpcServerCommunicationPortOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcServerCommunicationPort);
    response->alpcClientCommunicationPortOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcClientCommunicationPort);
    response->alpcHandleTableOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcHandleTable);
    response->alpcHandleTableLockOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcHandleTableLock);
    response->alpcAttributesOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcAttributes);
    response->alpcAttributesFlagsOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcAttributesFlags);
    response->alpcPortContextOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcPortContext);
    response->alpcPortObjectLockOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcPortObjectLock);
    response->alpcSequenceNoOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcSequenceNo);
    response->alpcStateOffset = kswordArkAlpcNormalizeOffset(dynState->kernel.alpcState);
}

static PVOID
kswordArkAlpcAllocateNonPaged(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate a temporary NonPagedPool buffer. Note: Object name queries may lack ExAllocatePool2 on
    older systems, so maintain a compatible allocation strategy consistent with existing handle queries.

Arguments:

    BufferBytes - Number of bytes to allocate.

Return Value:

    Returns the buffer pointer on success, or NULL on failure.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswordArkExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswordArkExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, KSWORD_ARK_ALPC_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSWORD_ARK_ALPC_POOL_TAG);
#pragma warning(pop)
}

static VOID
kswordArkAlpcCopyUnicodeStringToFixed(
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _In_opt_ const UNICODE_STRING* source,
    _Out_opt_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Copy the UNICODE_STRING into a fixed protocol buffer. Note: All R3-visible strings are
    forced to be NUL-terminated, and TruncatedOut indicates whether truncation occurred.

Arguments:

    Destination: Target WCHAR array.
    DestinationChars: Capacity of the target array in WCHAR units.
    Source: optional source string.
    TruncatedOut - optional truncation marker for output.

Return Value:

    None. This function has no return value.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(source->Length / sizeof(WCHAR));
    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
        if (truncatedOut != NULL) {
            *truncatedOut = TRUE;
        }
    }

    RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

static NTSTATUS
kswordArkAlpcQueryObjectName(
    _In_ PVOID object,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Query the object name using ObQueryNameString. Note: An ALPC Port may have no name; an empty name
    is still considered success. An error is returned only if the API fails or buffer allocation fails.

Arguments:

    Object: Referenced object.
    Destination - Fixed output buffer.
    DestinationChars - Output buffer capacity.
    TruncatedOut - Indicates whether the receive was truncated.

Return Value:

    Returns STATUS_SUCCESS or the NTSTATUS from the object name query.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (object == NULL || destination == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    destination[0] = L'\0';
    status = ObQueryNameString(object, NULL, 0, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
    }

    allocationBytes = requiredBytes;
    if (allocationBytes < sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)) {
        allocationBytes = sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
    }
    if (allocationBytes > (64UL * 1024UL)) {
        allocationBytes = 64UL * 1024UL;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkAlpcAllocateNonPaged(allocationBytes);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(object, nameInfo, allocationBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        kswordArkAlpcCopyUnicodeStringToFixed(destination, destinationChars, &nameInfo->Name, truncatedOut);
    }

    ExFreePoolWithTag(nameInfo, KSWORD_ARK_ALPC_POOL_TAG);
    return status;
}

NTSTATUS
kswordArkAlpcQueryTypeName(
    _In_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Read the type name from the OBJECT_TYPE.Name DynData offset. Note: Used to verify that the passed
    handle is indeed an ALPC/Port, preventing arbitrary objects from being misinterpreted as ALPC_PORT.

Arguments:

    ObjectType: The type object returned by ObGetObjectType.
    DynState - Snapshot of DynData.
    Destination - Fixed output buffer.
    DestinationChars - Output buffer capacity.
    TruncatedOut - Indicates whether the receive was truncated.

Return Value:

    STATUS_SUCCESS indicates the type name was copied; otherwise, a failure status is returned.

--*/
{
    UNICODE_STRING typeName;
    WCHAR objectTypePath[KSWORD_ARK_ALPC_TYPE_NAME_CHARS];
    ULONG length = 0UL;
    ULONG lastSeparator = 0UL;
    BOOLEAN separatorFound = FALSE;
    BOOLEAN namespaceTruncated = FALSE;
    NTSTATUS namespaceStatus = STATUS_SUCCESS;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (objectType == NULL || dynState == NULL || destination == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(objectTypePath, sizeof(objectTypePath));
    namespaceStatus = kswordArkAlpcQueryObjectName(
        objectType,
        objectTypePath,
        RTL_NUMBER_OF(objectTypePath),
        &namespaceTruncated);
    if (NT_SUCCESS(namespaceStatus) && objectTypePath[0] != L'\0') {
        while (length < RTL_NUMBER_OF(objectTypePath) &&
            objectTypePath[length] != L'\0') {
            if (objectTypePath[length] == L'\\') {
                lastSeparator = length;
                separatorFound = TRUE;
            }
            length += 1UL;
        }
        typeName.Buffer = separatorFound ?
            &objectTypePath[lastSeparator + 1UL] : objectTypePath;
        typeName.Length = (USHORT)((length -
            (separatorFound ? lastSeparator + 1UL : 0UL)) * sizeof(WCHAR));
        typeName.MaximumLength = typeName.Length;
        kswordArkAlpcCopyUnicodeStringToFixed(
            destination,
            destinationChars,
            &typeName,
            truncatedOut);
        if (truncatedOut != NULL && namespaceTruncated) {
            *truncatedOut = TRUE;
        }
        return STATUS_SUCCESS;
    }
    if (!kswordArkAlpcIsOffsetPresent(dynState->kernel.otName)) {
        return NT_SUCCESS(namespaceStatus) ? STATUS_NOT_SUPPORTED : namespaceStatus;
    }

    RtlZeroMemory(&typeName, sizeof(typeName));
    __try {
        RtlCopyMemory(&typeName, (PUCHAR)objectType + dynState->kernel.otName, sizeof(typeName));
        kswordArkAlpcCopyUnicodeStringToFixed(destination, destinationChars, &typeName, truncatedOut);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkAlpcIsTypeNameAlpcPort(
    _In_reads_(typeNameChars) const WCHAR* typeName,
    _In_ ULONG typeNameChars
    )
/*++

Routine Description:

    Check if the object type name indicates an ALPC Port. Windows versions may display it as "ALPC
    Port" or "Port"; only these two known types are accepted, and all other types fail closed.

Arguments:

    TypeName - Fixed type name buffer.
    TypeNameChars - Buffer capacity for the type name.

Return Value:

    TRUE indicates ALPC private fields are allowed to be read; FALSE indicates a type mismatch.

--*/
{
    UNICODE_STRING actualName;
    UNICODE_STRING alpcPortName;
    UNICODE_STRING portName;
    ULONG actualChars = 0UL;

    if (typeName == NULL || typeNameChars == 0UL || typeName[0] == L'\0') {
        return FALSE;
    }

    while (actualChars < typeNameChars && typeName[actualChars] != L'\0') {
        actualChars += 1UL;
    }

    actualName.Buffer = (PWCHAR)typeName;
    actualName.Length = (USHORT)(actualChars * sizeof(WCHAR));
    actualName.MaximumLength = actualName.Length;
    RtlInitUnicodeString(&alpcPortName, L"ALPC Port");
    RtlInitUnicodeString(&portName, L"Port");

    if (RtlEqualUnicodeString(&actualName, &alpcPortName, TRUE)) {
        return TRUE;
    }
    if (RtlEqualUnicodeString(&actualName, &portName, TRUE)) {
        return TRUE;
    }

    return FALSE;
}

static HANDLE
kswordArkAlpcMakeKernelHandle(
    _In_ HANDLE handleValue
    )
/*++

Routine Description:

    Convert handle values from the System process to kernel handle format. Note: Logic aligns with
    System Informer's MakeKernelHandle, used exclusively for the PsInitialSystemProcess special case.

Arguments:

    HandleValue - original handle value from the user request.

Return Value:

    HANDLE with the kernel handle bit set.

--*/
{
    return (HANDLE)((ULONG_PTR)handleValue | KSWORD_ARK_KERNEL_HANDLE_BIT);
}

NTSTATUS
kswordArkAlpcReferenceHandleObject(
    _In_ PEPROCESS processObject,
    _In_ ULONG64 handleValue,
    _Outptr_result_nullonfailure_ PVOID* objectOut
    )
/*++

Routine Description:

    Reference the object pointed to by PID+Handle in the target process context. Note: The function does not
    receive an object address, so it does not upgrade the Phase-4 exposed address to kernel object credentials.

Arguments:

    ProcessObject - Referenced target process object.
    HandleValue - Handle value within the target process.
    ObjectOut: The object received after acquiring a reference; the caller must call ObDereferenceObject.

Return Value:

    STATUS_SUCCESS or an error status from ObReferenceObjectByHandle.

--*/
{
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    HANDLE targetHandle = (HANDLE)(ULONG_PTR)handleValue;
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || objectOut == NULL || handleValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *objectOut = NULL;

    if (processObject == PsInitialSystemProcess) {
        targetHandle = kswordArkAlpcMakeKernelHandle(targetHandle);
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        status = ObReferenceObjectByHandle(
            targetHandle,
            0,
            NULL,
            (processObject == PsInitialSystemProcess) ? KernelMode : UserMode,
            objectOut,
            NULL);
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }

    return status;
}

NTSTATUS
kswordArkAlpcReadPointerField(
    _In_ PVOID object,
    _In_ ULONG offset,
    _Outptr_result_maybenull_ PVOID* pointerOut
    )
/*++

Routine Description:

    Safely read pointer fields from the ALPC private structure. Note: All private field reads are wrapped in SEH;
    return an exception code instead of crashing if the target object exits or a structure exception occurs.

Arguments:

    Object - Base address of ALPC_PORT or ALPC_COMMUNICATION_INFO.
    Offset - Offset of the DynData field.
    PointerOut - Pointer received from the read operation.

Return Value:

    STATUS_SUCCESS or an exceptional NTSTATUS.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID value = NULL;

    if (object == NULL || pointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkAlpcIsOffsetPresent(offset)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        RtlCopyMemory(&value, (PUCHAR)object + offset, sizeof(value));
        *pointerOut = value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
kswordArkAlpcReadUlongField(
    _In_ PVOID object,
    _In_ ULONG offset,
    _Out_ ULONG* valueOut
    )
/*++

Routine Description:

    Safely read the ULONG field from the ALPC private structure. Note: Flags,
    SequenceNo, and State are all output as ULONGs to the shared protocol.

Arguments:

    Object - Structure base address.
    Offset - Offset of the DynData field.
    ValueOut - Receives a ULONG value.

Return Value:

    STATUS_SUCCESS or an exceptional NTSTATUS.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (object == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkAlpcIsOffsetPresent(offset)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        RtlCopyMemory(valueOut, (PUCHAR)object + offset, sizeof(*valueOut));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

NTSTATUS
kswordArkAlpcPopulateBasicInfo(
    _In_ PVOID portObject,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_ALPC_PORT_INFO* portInfo
    )
/*++

Routine Description:

    Read the owner/flags/context/sequence/state of an ALPC_PORT. Note:
    OwnerProcess carries valid-bit semantics; it must be read under the shared lock protection of PortObjectLock.

Arguments:

    PortObject - An ALPC Port object that is either referenced or currently stable.
    DynState - Snapshot of DynData.
    PortInfo - writable port info packet.

Return Value:

    STATUS_SUCCESS indicates that basic field reading is complete; otherwise, a failure status is returned.

--*/
{
    PVOID ownerProcessRaw = NULL;
    PEPROCESS ownerProcess = NULL;
    PEX_PUSH_LOCK portObjectLock = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    ULONG flagsValue = 0UL;
    ULONG stateValue = 0UL;
    ULONG sequenceValue = 0UL;
    PVOID pointerValue = NULL;
    BOOLEAN criticalRegionEntered = FALSE;
    BOOLEAN lockHeld = FALSE;

    if (portObject == NULL || dynState == NULL || portInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcOwnerProcess) ||
        !kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcPortObjectLock)) {
        return STATUS_NOT_SUPPORTED;
    }

    portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_OBJECT_PRESENT;
    portInfo->objectAddress = (ULONG64)(ULONG_PTR)portObject;
    portObjectLock = (PEX_PUSH_LOCK)((PUCHAR)portObject + dynState->kernel.alpcPortObjectLock);

    __try {
        KeEnterCriticalRegion();
        criticalRegionEntered = TRUE;
        kswordArkAcquirePushLockShared(portObjectLock);
        lockHeld = TRUE;
        RtlCopyMemory(&ownerProcessRaw, (PUCHAR)portObject + dynState->kernel.alpcOwnerProcess, sizeof(ownerProcessRaw));
        kswordArkReleasePushLockShared(portObjectLock);
        lockHeld = FALSE;
        KeLeaveCriticalRegion();
        criticalRegionEntered = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (lockHeld) {
            kswordArkReleasePushLockShared(portObjectLock);
            lockHeld = FALSE;
        }
        if (criticalRegionEntered) {
            KeLeaveCriticalRegion();
            criticalRegionEntered = FALSE;
        }
        return status;
    }

    if (ownerProcessRaw != NULL && (((ULONG_PTR)ownerProcessRaw & 1ULL) == 0ULL)) {
        ownerProcess = (PEPROCESS)ownerProcessRaw;
        portInfo->ownerProcessId = HandleToULong(PsGetProcessId(ownerProcess));
        portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_OWNER_PID_PRESENT;
    }

    if (kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcAttributes) &&
        kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcAttributesFlags)) {
        fieldStatus = kswordArkAlpcReadUlongField(
            (PUCHAR)portObject + dynState->kernel.alpcAttributes,
            dynState->kernel.alpcAttributesFlags,
            &flagsValue);
        if (NT_SUCCESS(fieldStatus)) {
            portInfo->flags = flagsValue;
            portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_FLAGS_PRESENT;
        }
        else if (NT_SUCCESS(status)) {
            status = fieldStatus;
        }
    }

    fieldStatus = kswordArkAlpcReadPointerField(portObject, dynState->kernel.alpcPortContext, &pointerValue);
    if (NT_SUCCESS(fieldStatus)) {
        portInfo->portContext = (ULONG64)(ULONG_PTR)pointerValue;
        portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_CONTEXT_PRESENT;
    }
    else if (fieldStatus != STATUS_NOT_SUPPORTED && NT_SUCCESS(status)) {
        status = fieldStatus;
    }

    fieldStatus = kswordArkAlpcReadUlongField(portObject, dynState->kernel.alpcSequenceNo, &sequenceValue);
    if (NT_SUCCESS(fieldStatus)) {
        portInfo->sequenceNo = sequenceValue;
        portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_SEQUENCE_PRESENT;
    }
    else if (fieldStatus != STATUS_NOT_SUPPORTED && NT_SUCCESS(status)) {
        status = fieldStatus;
    }

    fieldStatus = kswordArkAlpcReadUlongField(portObject, dynState->kernel.alpcState, &stateValue);
    if (NT_SUCCESS(fieldStatus)) {
        portInfo->state = stateValue;
        portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_STATE_PRESENT;
    }
    else if (fieldStatus != STATUS_NOT_SUPPORTED && NT_SUCCESS(status)) {
        status = fieldStatus;
    }

    return status;
}

NTSTATUS
kswordArkAlpcPopulateNameInfo(
    _In_ PVOID portObject,
    _Inout_ KSWORD_ARK_ALPC_PORT_INFO* portInfo,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Query and populate the object name of an ALPC Port. Note: Failure to query the name does not affect
    the display of object relationship fields, but the original NTSTATUS is retained in nameStatus.

Arguments:

    PortObject - An ALPC Port object that is either referenced or currently stable.
    PortInfo - Writable port information.
    TruncatedOut - Indicates whether the receive was truncated.

Return Value:

    STATUS_SUCCESS or an error related to ObQueryNameString.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (portObject == NULL || portInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkAlpcQueryObjectName(
        portObject,
        portInfo->portName,
        KSWORD_ARK_ALPC_PORT_NAME_CHARS,
        truncatedOut);
    portInfo->nameStatus = status;
    if (NT_SUCCESS(status)) {
        portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_NAME_PRESENT;
    }

    return status;
}

NTSTATUS
kswordArkAlpcValidatePortPointer(
    _In_ PVOID candidatePort,
    _In_ POBJECT_TYPE expectedType
    )
/*++

Routine Description:

    Verify the port pointer type in communicationInfo. Note: System Informer compares
    directly using AlpcPortObjectType; here, the object type of the validated handle
    serves as a same-type anchor to avoid introducing additional undocumented exports.

Arguments:

    CandidatePort: The candidate port object read from communicationInfo.
    ExpectedType - the object type of the queried handle.

Return Value:

    Returns STATUS_SUCCESS if types match; otherwise returns a type mismatch error.

--*/
{
    POBJECT_TYPE candidateType = NULL;

    if (candidatePort == NULL || expectedType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        candidateType = ObGetObjectType(candidatePort);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (candidateType != expectedType) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    return STATUS_SUCCESS;
}
