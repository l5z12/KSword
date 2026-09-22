#pragma once

#include "ark/ark_handle.h"
#include "ark/ark_dyndata.h"

EXTERN_C_START

BOOLEAN
kswordArkHandleIsOffsetPresent(
    _In_ ULONG offset
    );

ULONG
kswordArkHandleNormalizeOffset(
    _In_ ULONG offset
    );

VOID
kswordArkHandlePrepareObjectDynData(
    _Inout_ KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response,
    _In_ const KswDynState* dynState
    );

PVOID
kswordArkHandleGetObjectBodyFromHeader(
    _In_opt_ PVOID objectHeader
    );

PVOID
kswordArkHandleGetObjectHeaderFromBody(
    _In_opt_ PVOID objectBody
    );

NTSTATUS
kswordArkHandleReadObjectTypeIndex(
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_ ULONG* objectTypeIndexOut
    );

ULONG
kswordArkHandleMergeTypeIndexSource(
    _In_ BOOLEAN objectTypeIndexPresent,
    _In_ ULONG objectTypeIndex,
    _In_ BOOLEAN headerTypeIndexPresent,
    _In_ ULONG headerTypeIndex
    );

VOID
kswordArkHandleFillEntryObjectHeaderAudit(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* entry,
    _In_opt_ PVOID objectHeader,
    _In_opt_ PVOID objectBody,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState
    );

VOID
kswordArkHandleFillQueryObjectHeaderAudit(
    _Inout_ KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response,
    _In_opt_ PVOID objectHeader,
    _In_opt_ PVOID objectBody,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState
    );

EXTERN_C_END
