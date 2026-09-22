#pragma once

#include "ark/ark_section.h"
#include "ark/ark_dyndata.h"

EXTERN_C_START

BOOLEAN
kswordArkSectionIsOffsetPresent(
    _In_ ULONG offset
    );

ULONG
kswordArkSectionNormalizeOffset(
    _In_ ULONG offset
    );

VOID
kswordArkSectionPrepareOffsets(
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response,
    _In_ const KswDynState* dynState
    );

BOOLEAN
kswordArkSectionHasRequiredDynData(
    _In_ const KswDynState* dynState
    );

NTSTATUS
kswordArkSectionReferenceProcessImageControlArea(
    _In_ PEPROCESS processObject,
    _Outptr_result_maybenull_ PFILE_OBJECT* fileObjectOut,
    _Outptr_result_maybenull_ PVOID* controlAreaOut
    );

NTSTATUS
kswordArkSectionReadProcessSectionObject(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _Outptr_result_maybenull_ PVOID* sectionObjectOut
    );

NTSTATUS
kswordArkSectionReadControlArea(
    _In_ PVOID sectionObject,
    _In_ const KswDynState* dynState,
    _Outptr_result_maybenull_ PVOID* controlAreaOut,
    _Out_ BOOLEAN* remoteUnsupportedOut
    );

NTSTATUS
kswordArkSectionEnumerateMappings(
    _In_ PVOID controlArea,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response,
    _In_ size_t entryCapacity
    );

NTSTATUS
kswordArkSectionEnumerateFileControlAreaMappings(
    _In_ PVOID controlArea,
    _In_ ULONG sectionKind,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE* response,
    _In_ size_t entryCapacity
    );

EXTERN_C_END
