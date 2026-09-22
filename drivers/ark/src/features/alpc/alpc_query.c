/*++

Module Name:

    alpc_query.c

Abstract:

    Phase-6 ALPC Port inspection using DynData-gated private fields.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_alpc.h"
#include "ark/ark_push_lock.h"

#include "ark/ark_dyndata.h"
#include "alpc_runtime_fallback.h"
#include "alpc_support.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

static NTSTATUS
KswordARKAlpcReferenceCommunicationPorts(
    _In_ PVOID portObject,
    _In_ POBJECT_TYPE expectedType,
    _In_ const KswDynState* dynState,
    _Out_ KswordArkAlpcReferencedPorts* portsOut
    )
/*++

Routine Description:

    Reference the connection/server/client ports in ALPC communicationInfo. Note:
    Align with System Informer's locking model: hold the AlpcHandleTableLock shared lock when reading
    the communicationInfo handle table, then call ObReferenceObject after confirming the object type.

Arguments:

    PortObject: Validated ALPC Port object.
    ExpectedType - Object type of this ALPC Port.
    DynState - Snapshot of DynData.
    PortsOut - three port objects after receiving references; caller is responsible for releasing.

Return Value:

    STATUS_SUCCESS, STATUS_NOT_FOUND, or type/read errors.

--*/
{
    PVOID communicationInfo = NULL;
    PVOID handleTable = NULL;
    PEX_PUSH_LOCK handleTableLock = NULL;
    PVOID connectionPort = NULL;
    PVOID serverPort = NULL;
    PVOID clientPort = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN lockHeld = FALSE;
    BOOLEAN criticalRegionEntered = FALSE;
    // Record whether each of the three ports has successfully acquired a reference; do not equate non-null candidate pointers with reference ownership.
    BOOLEAN connectionPortReferenced = FALSE;
    // Record server port reference separately to ensure exception cleanup releases only the references actually held by this function.
    BOOLEAN serverPortReferenced = FALSE;
    // Separately track the client port reference to avoid incorrectly decrementing the object reference count if ObReferenceObject fails.
    BOOLEAN clientPortReferenced = FALSE;

    if (portObject == NULL || expectedType == NULL || dynState == NULL || portsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(portsOut, sizeof(*portsOut));

    status = kswordArkAlpcReadPointerField(portObject, dynState->kernel.alpcCommunicationInfo, &communicationInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (communicationInfo == NULL) {
        return STATUS_NOT_FOUND;
    }

    // Note: These two offsets are used to calculate a push lock address that will be written. If the sentinel 0xFFFFFFFF
    // is missing, it would be treated as a real offset and added. The upstream capability gate currently covers them,
    // but this function cannot rely on the caller; it must fail closed like the other fields in the same file.
    if (!kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcHandleTable) ||
        !kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcHandleTableLock)) {
        return STATUS_NOT_SUPPORTED;
    }

    handleTable = (PUCHAR)communicationInfo + dynState->kernel.alpcHandleTable;
    handleTableLock = (PEX_PUSH_LOCK)((PUCHAR)handleTable + dynState->kernel.alpcHandleTableLock);

    __try {
        KeEnterCriticalRegion();
        criticalRegionEntered = TRUE;
        kswordArkAcquirePushLockShared(handleTableLock);
        lockHeld = TRUE;

        if (kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcConnectionPort)) {
            RtlCopyMemory(&connectionPort, (PUCHAR)communicationInfo + dynState->kernel.alpcConnectionPort, sizeof(connectionPort));
            if (connectionPort != NULL) {
                status = kswordArkAlpcValidatePortPointer(connectionPort, expectedType);
                if (!NT_SUCCESS(status)) {
                    connectionPort = NULL;
                }
                else {
                    ObReferenceObject(connectionPort);
                    // This function only holds a reference to the connection port after ObReferenceObject returns successfully.
                    connectionPortReferenced = TRUE;
                }
            }
        }

        if (NT_SUCCESS(status) && kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcServerCommunicationPort)) {
            RtlCopyMemory(&serverPort, (PUCHAR)communicationInfo + dynState->kernel.alpcServerCommunicationPort, sizeof(serverPort));
            if (serverPort != NULL) {
                status = kswordArkAlpcValidatePortPointer(serverPort, expectedType);
                if (!NT_SUCCESS(status)) {
                    serverPort = NULL;
                }
                else {
                    ObReferenceObject(serverPort);
                    // This function only owns the server port reference after ObReferenceObject returns successfully.
                    serverPortReferenced = TRUE;
                }
            }
        }

        if (NT_SUCCESS(status) && kswordArkAlpcIsOffsetPresent(dynState->kernel.alpcClientCommunicationPort)) {
            RtlCopyMemory(&clientPort, (PUCHAR)communicationInfo + dynState->kernel.alpcClientCommunicationPort, sizeof(clientPort));
            if (clientPort != NULL) {
                status = kswordArkAlpcValidatePortPointer(clientPort, expectedType);
                if (!NT_SUCCESS(status)) {
                    clientPort = NULL;
                }
                else {
                    ObReferenceObject(clientPort);
                    // This function only owns the client port reference after ObReferenceObject returns successfully.
                    clientPortReferenced = TRUE;
                }
            }
        }

        kswordArkReleasePushLockShared(handleTableLock);
        lockHeld = FALSE;
        KeLeaveCriticalRegion();
        criticalRegionEntered = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (lockHeld) {
            kswordArkReleasePushLockShared(handleTableLock);
            lockHeld = FALSE;
        }
        if (criticalRegionEntered) {
            KeLeaveCriticalRegion();
            criticalRegionEntered = FALSE;
        }
    }

    if (!NT_SUCCESS(status)) {
        if (connectionPortReferenced && connectionPort != NULL) {
            ObDereferenceObject(connectionPort);
        }
        if (serverPortReferenced && serverPort != NULL) {
            ObDereferenceObject(serverPort);
        }
        if (clientPortReferenced && clientPort != NULL) {
            ObDereferenceObject(clientPort);
        }
        return status;
    }

    portsOut->connectionPort = connectionPort;
    portsOut->serverPort = serverPort;
    portsOut->clientPort = clientPort;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkAlpcPopulatePortInfo(
    _In_ PVOID portObject,
    _In_ ULONG relation,
    _In_ ULONG requestFlags,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_ALPC_PORT_INFO* portInfo,
    _Out_ BOOLEAN* nameTruncatedOut
    )
/*++

Routine Description:

    Populate a single ALPC port's information packet. Note: Basic fields and name fields are controlled
    separately by flags to avoid forcing potentially slow name queries when the UI only cares about the object.

Arguments:

    PortObject - ALPC Port object.
    Relation - query/connection/server/client relationship enumeration.
    RequestFlags - User request flags.
    DynState - Snapshot of DynData.
    PortInfo - Writable port information.
    NameTruncatedOut - Whether the received name was truncated.

Return Value:

    STATUS_SUCCESS or the first critical failure status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fieldStatus = STATUS_SUCCESS;

    if (nameTruncatedOut != NULL) {
        *nameTruncatedOut = FALSE;
    }
    if (portObject == NULL || dynState == NULL || portInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    portInfo->relation = relation;
    portInfo->fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_OBJECT_PRESENT;
    portInfo->objectAddress = (ULONG64)(ULONG_PTR)portObject;

    if ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_BASIC) != 0UL) {
        fieldStatus = kswordArkAlpcPopulateBasicInfo(portObject, dynState, portInfo);
        portInfo->basicStatus = fieldStatus;
        if (!NT_SUCCESS(fieldStatus)) {
            status = fieldStatus;
        }
    }

    if ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_NAMES) != 0UL) {
        fieldStatus = kswordArkAlpcPopulateNameInfo(portObject, portInfo, nameTruncatedOut);
        if (!NT_SUCCESS(fieldStatus) && NT_SUCCESS(status)) {
            status = fieldStatus;
        }
    }

    return status;
}

static VOID
kswordArkAlpcReleaseReferencedPorts(
    _Inout_ KswordArkAlpcReferencedPorts* ports
    )
/*++

Routine Description:

    Release the communication port reference. Note: Centralize release to avoid duplicate
    ObDereferenceObject calls across multiple exit paths, and nullify the pointer to prevent misuse.

Arguments:

    Ports - port reference collection.

Return Value:

    None. This function has no return value.

--*/
{
    if (ports == NULL) {
        return;
    }

    if (ports->connectionPort != NULL) {
        ObDereferenceObject(ports->connectionPort);
        ports->connectionPort = NULL;
    }
    if (ports->serverPort != NULL) {
        ObDereferenceObject(ports->serverPort);
        ports->serverPort = NULL;
    }
    if (ports->clientPort != NULL) {
        ObDereferenceObject(ports->clientPort);
        ports->clientPort = NULL;
    }
}

NTSTATUS
kswordArkDriverQueryAlpcPort(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_ALPC_PORT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query an ALPC Port pointed to by a PID+Handle, returning owner/state/flags and
    the connection/server/client relationship. Note: This function does not accept
    object addresses; all ALPC private field reads are gated by KSW_CAP_ALPC_FIELDS.

Arguments:

    OutputBuffer - Fixed response packet output buffer.
    OutputBufferLength - Output buffer capacity.
    Request - Query request containing PID and target handle.
    BytesWrittenOut - Bytes received for writing.

Return Value:

    STATUS_SUCCESS indicates the response packet is populated; validation failure returns the corresponding NTSTATUS.

--*/
{
    KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE* response = NULL;
    KswDynState dynState;
    KswAlpcRuntimeBasicInfo runtimeBasic;
    KswordArkAlpcReferencedPorts referencedPorts;
    PEPROCESS processObject = NULL;
    PVOID portObject = NULL;
    POBJECT_TYPE portObjectType = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    NTSTATUS runtimeStatus = STATUS_NOT_SUPPORTED;
    ULONG requestFlags = 0UL;
    BOOLEAN hasPrivateDynData = FALSE;
    BOOLEAN truncated = FALSE;
    BOOLEAN anyTruncated = FALSE;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->processId == 0UL || request->handleValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&runtimeBasic, sizeof(runtimeBasic));
    RtlZeroMemory(&referencedPorts, sizeof(referencedPorts));

    response = (KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_ALPC_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = request->processId;
    response->handleValue = request->handleValue;
    response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE;
    response->queryPort.relation = KSWORD_ARK_ALPC_PORT_RELATION_QUERY;
    response->connectionPort.relation = KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION;
    response->serverPort.relation = KSWORD_ARK_ALPC_PORT_RELATION_SERVER;
    response->clientPort.relation = KSWORD_ARK_ALPC_PORT_RELATION_CLIENT;

    kswordArkDynDataSnapshot(&dynState);
    kswordArkAlpcPrepareOffsets(response, &dynState);
    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL : request->flags;
    hasPrivateDynData = kswordArkAlpcHasRequiredDynData(&dynState);

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_PROCESS_LOOKUP_FAILED;
        response->objectReferenceStatus = status;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = kswordArkAlpcReferenceHandleObject(processObject, request->handleValue, &portObject);
    response->objectReferenceStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_HANDLE_REFERENCE_FAILED;
        ObDereferenceObject(processObject);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_OBJECT_PRESENT;
    response->queryPort.objectAddress = (ULONG64)(ULONG_PTR)portObject;
    response->queryPort.fieldFlags |= KSWORD_ARK_ALPC_PORT_FIELD_OBJECT_PRESENT;

    __try {
        portObjectType = ObGetObjectType(portObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->typeStatus = GetExceptionCode();
        response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_TYPE_MISMATCH;
        ObDereferenceObject(portObject);
        ObDereferenceObject(processObject);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    fieldStatus = kswordArkAlpcQueryTypeName(
        portObjectType,
        &dynState,
        response->typeName,
        KSWORD_ARK_ALPC_TYPE_NAME_CHARS,
        &truncated);
    response->typeStatus = fieldStatus;
    if (NT_SUCCESS(fieldStatus)) {
        response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_TYPE_NAME_PRESENT;
        anyTruncated = truncated ? TRUE : anyTruncated;
    }
    if (!NT_SUCCESS(fieldStatus) || !kswordArkAlpcIsTypeNameAlpcPort(response->typeName, KSWORD_ARK_ALPC_TYPE_NAME_CHARS)) {
        response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_TYPE_MISMATCH;
        ObDereferenceObject(portObject);
        ObDereferenceObject(processObject);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    if ((requestFlags & (KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_BASIC | KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_NAMES)) != 0UL) {
        if (hasPrivateDynData) {
            truncated = FALSE;
            fieldStatus = kswordArkAlpcPopulatePortInfo(
                portObject,
                KSWORD_ARK_ALPC_PORT_RELATION_QUERY,
                requestFlags,
                &dynState,
                &response->queryPort,
                &truncated);
        }
        else {
            ULONG fallbackFlags = requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_NAMES;

            truncated = FALSE;
            fieldStatus = kswordArkAlpcPopulatePortInfo(
                portObject,
                KSWORD_ARK_ALPC_PORT_RELATION_QUERY,
                fallbackFlags,
                &dynState,
                &response->queryPort,
                &truncated);
        }
        if ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_BASIC) != 0UL &&
            (!hasPrivateDynData ||
                !NT_SUCCESS(response->queryPort.basicStatus))) {
            runtimeStatus = kswordArkAlpcQueryRuntimeBasicInfo(
                processObject,
                request->handleValue,
                &runtimeBasic);
            response->queryPort.basicStatus = runtimeStatus;
            if (NT_SUCCESS(runtimeStatus)) {
                response->queryPort.flags = runtimeBasic.flags;
                response->queryPort.sequenceNo = runtimeBasic.sequenceNo;
                response->queryPort.portContext =
                    (ULONG64)(ULONG_PTR)runtimeBasic.portContext;
                response->queryPort.fieldFlags |=
                    KSWORD_ARK_ALPC_PORT_FIELD_FLAGS_PRESENT |
                    KSWORD_ARK_ALPC_PORT_FIELD_SEQUENCE_PRESENT |
                    KSWORD_ARK_ALPC_PORT_FIELD_CONTEXT_PRESENT;
                if ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_NAMES) == 0UL ||
                    NT_SUCCESS(response->queryPort.nameStatus)) {
                    fieldStatus = STATUS_SUCCESS;
                }
            }
            else if (NT_SUCCESS(fieldStatus)) {
                fieldStatus = runtimeStatus;
            }
        }
        response->basicStatus = response->queryPort.basicStatus;
        response->nameStatus = response->queryPort.nameStatus;
        response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_QUERY_PORT_PRESENT;
        if (truncated) {
            anyTruncated = TRUE;
        }
        if (!NT_SUCCESS(fieldStatus) && response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
            response->queryStatus = ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_BASIC) != 0UL) ?
                KSWORD_ARK_ALPC_QUERY_STATUS_BASIC_QUERY_FAILED :
                KSWORD_ARK_ALPC_QUERY_STATUS_NAME_QUERY_FAILED;
        }
    }

    if ((requestFlags & KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_COMMUNICATION) != 0UL) {
        fieldStatus = hasPrivateDynData ?
            KswordARKAlpcReferenceCommunicationPorts(
                portObject,
                portObjectType,
                &dynState,
                &referencedPorts) :
            STATUS_NOT_SUPPORTED;
        response->communicationStatus = fieldStatus;
        if (NT_SUCCESS(fieldStatus)) {
            if (referencedPorts.connectionPort != NULL) {
                truncated = FALSE;
                status = kswordArkAlpcPopulatePortInfo(
                    referencedPorts.connectionPort,
                    KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION,
                    requestFlags,
                    &dynState,
                    &response->connectionPort,
                    &truncated);
                response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_CONNECTION_PRESENT;
                anyTruncated = truncated ? TRUE : anyTruncated;
                if (!NT_SUCCESS(status) && response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
                    response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL;
                }
            }

            if (referencedPorts.serverPort != NULL) {
                truncated = FALSE;
                status = kswordArkAlpcPopulatePortInfo(
                    referencedPorts.serverPort,
                    KSWORD_ARK_ALPC_PORT_RELATION_SERVER,
                    requestFlags,
                    &dynState,
                    &response->serverPort,
                    &truncated);
                response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_SERVER_PRESENT;
                anyTruncated = truncated ? TRUE : anyTruncated;
                if (!NT_SUCCESS(status) && response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
                    response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL;
                }
            }

            if (referencedPorts.clientPort != NULL) {
                truncated = FALSE;
                status = kswordArkAlpcPopulatePortInfo(
                    referencedPorts.clientPort,
                    KSWORD_ARK_ALPC_PORT_RELATION_CLIENT,
                    requestFlags,
                    &dynState,
                    &response->clientPort,
                    &truncated);
                response->fieldFlags |= KSWORD_ARK_ALPC_RESPONSE_FIELD_CLIENT_PRESENT;
                anyTruncated = truncated ? TRUE : anyTruncated;
                if (!NT_SUCCESS(status) && response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
                    response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL;
                }
            }
        }
        else if (fieldStatus != STATUS_NOT_FOUND && response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
            response->queryStatus = hasPrivateDynData ?
                KSWORD_ARK_ALPC_QUERY_STATUS_COMMUNICATION_FAILED :
                KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL;
        }
    }

    if (response->queryStatus == KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = anyTruncated ?
            KSWORD_ARK_ALPC_QUERY_STATUS_NAME_TRUNCATED :
            KSWORD_ARK_ALPC_QUERY_STATUS_OK;
    }
    else if (response->queryStatus != KSWORD_ARK_ALPC_QUERY_STATUS_OK &&
        response->queryStatus != KSWORD_ARK_ALPC_QUERY_STATUS_NAME_TRUNCATED &&
        response->fieldFlags != 0UL) {
        response->queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL;
    }

    kswordArkAlpcReleaseReferencedPorts(&referencedPorts);
    ObDereferenceObject(portObject);
    ObDereferenceObject(processObject);
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
