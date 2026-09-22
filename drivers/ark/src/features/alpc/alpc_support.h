#pragma once

#include "ark/ark_alpc.h"
#include "ark/ark_dyndata.h"

EXTERN_C_START

// Note: Querying internal ALPC shared structures, storing only port pointers that have already been ObReferenceObject'd.
typedef struct KswordArkAlpcReferencedPorts
{
    PVOID connectionPort;
    PVOID serverPort;
    PVOID clientPort;
} KswordArkAlpcReferencedPorts, *PkswordArkAlpcReferencedPorts;

BOOLEAN
kswordArkAlpcIsOffsetPresent(
    _In_ ULONG offset
    );

BOOLEAN
kswordArkAlpcHasRequiredDynData(
    _In_ const KswDynState* dynState
    );

VOID
kswordArkAlpcPrepareOffsets(
    _Inout_ KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE* response,
    _In_ const KswDynState* dynState
    );

NTSTATUS
kswordArkAlpcQueryTypeName(
    _In_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _Out_ BOOLEAN* truncatedOut
    );

BOOLEAN
kswordArkAlpcIsTypeNameAlpcPort(
    _In_reads_(typeNameChars) const WCHAR* typeName,
    _In_ ULONG typeNameChars
    );

NTSTATUS
kswordArkAlpcReferenceHandleObject(
    _In_ PEPROCESS processObject,
    _In_ ULONG64 handleValue,
    _Outptr_result_nullonfailure_ PVOID* objectOut
    );

NTSTATUS
kswordArkAlpcReadPointerField(
    _In_ PVOID object,
    _In_ ULONG offset,
    _Outptr_result_maybenull_ PVOID* pointerOut
    );

NTSTATUS
kswordArkAlpcPopulateBasicInfo(
    _In_ PVOID portObject,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_ALPC_PORT_INFO* portInfo
    );

NTSTATUS
kswordArkAlpcPopulateNameInfo(
    _In_ PVOID portObject,
    _Inout_ KSWORD_ARK_ALPC_PORT_INFO* portInfo,
    _Out_ BOOLEAN* truncatedOut
    );

NTSTATUS
kswordArkAlpcValidatePortPointer(
    _In_ PVOID candidatePort,
    _In_ POBJECT_TYPE expectedType
    );

EXTERN_C_END
