/*++

Module Name:

    process_extended.c

Abstract:

    Phase-2 process extended EPROCESS field reader.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_extended.h"

#include "../../platform/process_resolver.h"

#include <ntstrsafe.h>

typedef NTSTATUS(NTAPI* KswordZwQueryInformationProcessFn)(
    _In_ HANDLE processHandle,
    _In_ ULONG processInformationClass,
    _Out_writes_bytes_(processInformationLength) PVOID processInformation,
    _In_ ULONG processInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef ULONG(NTAPI* KswordPsGetProcessSessionIdFn)(
    _In_ PEPROCESS process
    );

typedef struct KswordProcessImageFileNameInformation
{
    UNICODE_STRING imageName;
    WCHAR nameBuffer[KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS];
} KswordProcessImageFileNameInformation, *PkswordProcessImageFileNameInformation;

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#define KSWORD_PROCESS_IMAGE_FILE_NAME_CLASS 27UL

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID object,
    _In_ ULONG handleAttributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PHANDLE handle
    );

/* Note: Expose a kernel routine returning process creation time comparable to FILETIME. */
NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS process
    );

static BOOLEAN
KswordARKProcessIsOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    normalize DynData offset availability before any EPROCESS byte read.

Arguments:

    Offset - Candidate offset from the unified DynData state.

Return Value:

    TRUE when the offset can be used, otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkProcessSourceForOffset(
    _In_ ULONG offset,
    _In_ ULONG dynDataSource
    )
/*++

Routine Description:

    Convert an available DynData offset and its source into the process IOCTL
    source vocabulary used by R3.

Arguments:

    Offset - Candidate offset.
    DynDataSource - KSW_DYN_FIELD_SOURCE_* value for the field.

Return Value:

    KSWORD_ARK_PROCESS_FIELD_SOURCE_* value.

--*/
{
    if (!KswordARKProcessIsOffsetPresent(offset)) {
        return KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    }

    if (dynDataSource == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN) {
        return KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN;
    }
    if (dynDataSource == KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER) {
        return KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA;
    }
    if (dynDataSource == KSW_DYN_FIELD_SOURCE_PDB_PROFILE) {
        return KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE;
    }
    return KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
}

static BOOLEAN
kswordArkProcessRuntimeProtectionOffsets(
    _Out_ ULONG* protectionOffsetOut,
    _Out_ ULONG* signatureOffsetOut,
    _Out_ ULONG* sectionSignatureOffsetOut
    )
/*++

Routine Description:

    Resolve PP/PPL byte-field offsets from live ntoskrnl helpers. During forced process termination, DynData
    may be missing or may not have loaded the current kernel profile. Recover three byte-field offsets from
    narrow instruction patterns in PsGetProcessProtection and PsGetProcessSignatureLevel. Require consistency
    among the exported return values, live EPROCESS fields, and the adjacency of those three fields.

Arguments:

    ProtectionOffsetOut - Receives EPROCESS.Protection offset.
    SignatureOffsetOut - Receives EPROCESS.SignatureLevel offset.
    SectionSignatureOffsetOut - Receives EPROCESS.SectionSignatureLevel offset.

Return Value:

    TRUE when all three offsets are available and bounded; otherwise FALSE.

--*/
{
    const LONG kProtectionOffset = kswordArkDriverResolveProcessProtectionOffset();
    const LONG kSignatureOffset = kswordArkDriverResolveProcessSignatureLevelOffset();
    const LONG kSectionSignatureOffset = kswordArkDriverResolveProcessSectionSignatureLevelOffset();

    if (protectionOffsetOut == NULL ||
        signatureOffsetOut == NULL ||
        sectionSignatureOffsetOut == NULL) {
        return FALSE;
    }
    *protectionOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;
    *signatureOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;
    *sectionSignatureOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;

    if (kProtectionOffset <= 0 ||
        kSignatureOffset <= 0 ||
        kSectionSignatureOffset <= 0 ||
        kProtectionOffset > 0x3000L ||
        kSignatureOffset > 0x3000L ||
        kSectionSignatureOffset > 0x3000L) {
        return FALSE;
    }

    *protectionOffsetOut = (ULONG)kProtectionOffset;
    *signatureOffsetOut = (ULONG)kSignatureOffset;
    *sectionSignatureOffsetOut = (ULONG)kSectionSignatureOffset;
    return TRUE;
}

static NTSTATUS
kswordArkProcessPatchProtectionByOffsets(
    _In_ PEPROCESS processObject,
    _In_ ULONG protectionOffset,
    _In_ ULONG signatureOffset,
    _In_ ULONG sectionSignatureOffset,
    _In_ UCHAR protectionLevel,
    _In_ UCHAR signatureLevel,
    _In_ UCHAR sectionSignatureLevel
    )
/*++

Routine Description:

    Patch the three EPROCESS protection-related bytes through validated offsets.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    ProtectionOffset - Offset of EPROCESS.Protection.
    SignatureOffset - Offset of EPROCESS.SignatureLevel.
    SectionSignatureOffset - Offset of EPROCESS.SectionSignatureLevel.
    ProtectionLevel - Target PS_PROTECTION raw byte.
    SignatureLevel - Target process signature level.
    SectionSignatureLevel - Target section signature level.

Return Value:

    STATUS_SUCCESS when all bytes were written and verified; otherwise a read or
    validation status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL ||
        !KswordARKProcessIsOffsetPresent(protectionOffset) ||
        !KswordARKProcessIsOffsetPresent(signatureOffset) ||
        !KswordARKProcessIsOffsetPresent(sectionSignatureOffset)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        PUCHAR processBase = (PUCHAR)processObject;
        UCHAR* protectionByte = processBase + protectionOffset;
        UCHAR* signatureByte = processBase + signatureOffset;
        UCHAR* sectionSignatureByte = processBase + sectionSignatureOffset;
        UCHAR verifyProtection = 0U;
        UCHAR verifySignature = 0U;
        UCHAR verifySectionSignature = 0U;

        RtlCopyMemory(protectionByte, &protectionLevel, sizeof(protectionLevel));
        RtlCopyMemory(signatureByte, &signatureLevel, sizeof(signatureLevel));
        RtlCopyMemory(sectionSignatureByte, &sectionSignatureLevel, sizeof(sectionSignatureLevel));
        RtlCopyMemory(&verifyProtection, protectionByte, sizeof(verifyProtection));
        RtlCopyMemory(&verifySignature, signatureByte, sizeof(verifySignature));
        RtlCopyMemory(&verifySectionSignature, sectionSignatureByte, sizeof(verifySectionSignature));

        if (verifyProtection != protectionLevel ||
            verifySignature != signatureLevel ||
            verifySectionSignature != sectionSignatureLevel) {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static ULONG
kswordArkProcessNormalizeProtocolOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert driver-side DynData sentinel values into the process IOCTL sentinel.

Arguments:

    Offset - Raw offset from KswDynState.

Return Value:

    Usable offset, or KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE.

--*/
{
    if (!KswordARKProcessIsOffsetPresent(offset)) {
        return KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    }

    return offset;
}

static NTSTATUS
kswordArkProcessReadByteField(
    _In_ PEPROCESS processObject,
    _In_ ULONG offset,
    _Out_ UCHAR* valueOut
    )
/*++

Routine Description:

    Safely read one UCHAR from EPROCESS using a DynData supplied offset.

Arguments:

    ProcessObject - Target EPROCESS pointer.
    Offset - Field offset inside EPROCESS.
    ValueOut - Receives the byte value.

Return Value:

    STATUS_SUCCESS or the structured-exception code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKProcessIsOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory(valueOut, (PUCHAR)processObject + offset, sizeof(*valueOut));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
kswordArkProcessReadPointerField(
    _In_ PEPROCESS processObject,
    _In_ ULONG offset,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Safely read one pointer-sized field from EPROCESS and expose it as ULONG64.

Arguments:

    ProcessObject - Target EPROCESS pointer.
    Offset - Field offset inside EPROCESS.
    ValueOut - Receives the pointer value as an integer.

Return Value:

    STATUS_SUCCESS or the structured-exception code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pointerValue = NULL;

    if (processObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKProcessIsOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory(&pointerValue, (PUCHAR)processObject + offset, sizeof(pointerValue));
        *valueOut = (ULONG64)(ULONG_PTR)pointerValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static KswordZwQueryInformationProcessFn
kswordArkProcessResolveZwQueryInformationProcess(
    VOID
    )
/*++

Routine Description:

    Resolve ZwQueryInformationProcess dynamically for full image path queries.

Arguments:

    None.

Return Value:

    Function pointer when exported, otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
    return (KswordZwQueryInformationProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordPsGetProcessSessionIdFn
kswordArkProcessResolvePsGetProcessSessionId(
    VOID
    )
/*++

Routine Description:

    Resolve the public PsGetProcessSessionId routine dynamically.

Arguments:

    None.

Return Value:

    Function pointer when present, otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetProcessSessionId");
    return (KswordPsGetProcessSessionIdFn)MmGetSystemRoutineAddress(&routineName);
}

static VOID
kswordArkProcessPopulateSessionId(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Fill the process session ID through a public kernel API when available.

Arguments:

    Entry - Process entry being populated.
    ProcessObject - Target EPROCESS pointer.

Return Value:

    None. Missing routine leaves the field unavailable.

--*/
{
    KswordPsGetProcessSessionIdFn psGetProcessSessionId = NULL;

    if (entry == NULL || processObject == NULL) {
        return;
    }

    entry->sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    psGetProcessSessionId = kswordArkProcessResolvePsGetProcessSessionId();
    if (psGetProcessSessionId == NULL) {
        return;
    }

    __try {
        entry->sessionId = psGetProcessSessionId(processObject);
        entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT;
        entry->sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        entry->sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    }
}

static VOID
kswordArkProcessCopyImagePathToEntry(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_reads_(sourceChars) const WCHAR* sourceText,
    _In_ ULONG sourceChars
    )
/*++

Routine Description:

    Copy a bounded UTF-16 image path into the shared process entry.

Arguments:

    Entry - Output process entry.
    sourceText - UTF-16 source path.
    SourceChars - Source length in UTF-16 code units, excluding terminator.

Return Value:

    None.

--*/
{
    ULONG copyChars = 0UL;

    if (entry == NULL || sourceText == NULL || sourceChars == 0UL) {
        return;
    }

    copyChars = sourceChars;
    if (copyChars >= KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS) {
        copyChars = KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS - 1UL;
    }

    RtlCopyMemory(
        entry->imagePath,
        sourceText,
        (SIZE_T)copyChars * sizeof(WCHAR));
    entry->imagePath[copyChars] = 0U;
    entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_IMAGE_PATH_PRESENT;
    entry->imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API;
}

static VOID
kswordArkProcessPopulateImagePath(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Query the full image path using the public process-information API.

Arguments:

    Entry - Process entry being populated.
    ProcessObject - Target EPROCESS pointer.

Return Value:

    None. Missing image path leaves source as unavailable.

--*/
{
    KswordZwQueryInformationProcessFn zwQueryInformationProcess = NULL;
    KswordProcessImageFileNameInformation imageInformation;
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG returnedBytes = 0UL;

    if (entry == NULL || processObject == NULL) {
        return;
    }

    entry->imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    zwQueryInformationProcess = kswordArkProcessResolveZwQueryInformationProcess();
    if (zwQueryInformationProcess == NULL) {
        return;
    }

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        status = ObOpenObjectByPointer(
            processObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_QUERY_INFORMATION,
            *PsProcessType,
            KernelMode,
            &processHandle);
    }
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlZeroMemory(&imageInformation, sizeof(imageInformation));
    status = zwQueryInformationProcess(
        processHandle,
        KSWORD_PROCESS_IMAGE_FILE_NAME_CLASS,
        &imageInformation,
        sizeof(imageInformation),
        &returnedBytes);
    ZwClose(processHandle);

    if (!NT_SUCCESS(status)) {
        return;
    }
    if (imageInformation.imageName.Buffer == NULL ||
        imageInformation.imageName.Length == 0U) {
        return;
    }

    kswordArkProcessCopyImagePathToEntry(
        entry,
        imageInformation.imageName.Buffer,
        (ULONG)(imageInformation.imageName.Length / sizeof(WCHAR)));
}

static VOID
kswordArkProcessMarkReadFailure(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_ NTSTATUS readStatus
    )
/*++

Routine Description:

    Record that an optional kernel-field read failed without aborting process
    enumeration.

Arguments:

    Entry - Output process entry.
    ReadStatus - Optional read status.

Return Value:

    None.

--*/
{
    if (entry == NULL || NT_SUCCESS(readStatus)) {
        return;
    }

    entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED;
}

VOID
kswordArkProcessPopulateExtendedEntry(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Populate Phase-2 process fields from public APIs and unified DynData offsets.

Arguments:

    Entry - Entry with v1 PID/name fields already initialized.
    ProcessObject - EPROCESS pointer for the target process.

Return Value:

    None. Optional failures are represented through flags and R0 status.

--*/
{
    KswDynState dynState;
    NTSTATUS readStatus = STATUS_SUCCESS;

    if (entry == NULL || processObject == NULL) {
        return;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    /* Note: Creation time is derived from the referenced EPROCESS, used to bind R3/R0 dangerous actions to the same process instance. */
    entry->creationTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(processObject);
    entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING;
    entry->sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    entry->dynDataCapabilityMask = dynState.capabilityMask;
    entry->protectionOffset =
        kswordArkProcessNormalizeProtocolOffset(dynState.kernel.epProtection);
    entry->signatureLevelOffset =
        kswordArkProcessNormalizeProtocolOffset(dynState.kernel.epSignatureLevel);
    entry->sectionSignatureLevelOffset =
        kswordArkProcessNormalizeProtocolOffset(dynState.kernel.epSectionSignatureLevel);
    entry->objectTableOffset =
        kswordArkProcessNormalizeProtocolOffset(dynState.kernel.epObjectTable);
    entry->sectionObjectOffset =
        kswordArkProcessNormalizeProtocolOffset(dynState.kernel.epSectionObject);

    kswordArkProcessPopulateSessionId(entry, processObject);
    kswordArkProcessPopulateImagePath(entry, processObject);

    entry->protectionSource = kswordArkProcessSourceForOffset(
        dynState.kernel.epProtection,
        dynState.kernelSources.epProtection);
    entry->signatureLevelSource = kswordArkProcessSourceForOffset(
        dynState.kernel.epSignatureLevel,
        dynState.kernelSources.epSignatureLevel);
    entry->sectionSignatureLevelSource = kswordArkProcessSourceForOffset(
        dynState.kernel.epSectionSignatureLevel,
        dynState.kernelSources.epSectionSignatureLevel);
    entry->objectTableSource = kswordArkProcessSourceForOffset(
        dynState.kernel.epObjectTable,
        dynState.kernelSources.epObjectTable);
    entry->sectionObjectSource = kswordArkProcessSourceForOffset(
        dynState.kernel.epSectionObject,
        dynState.kernelSources.epSectionObject);

    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) ==
        KSW_CAP_PROCESS_PROTECTION_PATCH) {
        readStatus = kswordArkProcessReadByteField(
            processObject,
            dynState.kernel.epProtection,
            &entry->protection);
        if (NT_SUCCESS(readStatus)) {
            entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT;
        }
        kswordArkProcessMarkReadFailure(entry, readStatus);

        readStatus = kswordArkProcessReadByteField(
            processObject,
            dynState.kernel.epSignatureLevel,
            &entry->signatureLevel);
        if (NT_SUCCESS(readStatus)) {
            entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT;
        }
        kswordArkProcessMarkReadFailure(entry, readStatus);

        readStatus = kswordArkProcessReadByteField(
            processObject,
            dynState.kernel.epSectionSignatureLevel,
            &entry->sectionSignatureLevel);
        if (NT_SUCCESS(readStatus)) {
            entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT;
        }
        kswordArkProcessMarkReadFailure(entry, readStatus);
    }

    if (KswordARKProcessIsOffsetPresent(dynState.kernel.epObjectTable)) {
        entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE;
        readStatus = kswordArkProcessReadPointerField(
            processObject,
            dynState.kernel.epObjectTable,
            &entry->objectTableAddress);
        if (NT_SUCCESS(readStatus) && entry->objectTableAddress != 0ULL) {
            entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_VALUE_PRESENT;
        }
        kswordArkProcessMarkReadFailure(entry, readStatus);
    }

    if (KswordARKProcessIsOffsetPresent(dynState.kernel.epSectionObject)) {
        entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE;
        readStatus = kswordArkProcessReadPointerField(
            processObject,
            dynState.kernel.epSectionObject,
            &entry->sectionObjectAddress);
        if (NT_SUCCESS(readStatus) && entry->sectionObjectAddress != 0ULL) {
            entry->fieldFlags |= KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_VALUE_PRESENT;
        }
        kswordArkProcessMarkReadFailure(entry, readStatus);
    }

    if (entry->r0Status != KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED) {
        if (entry->fieldFlags & (
            KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT |
            KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE |
            KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE)) {
            entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_OK;
        }
        else if (entry->fieldFlags & (
            KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT |
            KSWORD_ARK_PROCESS_FIELD_IMAGE_PATH_PRESENT)) {
            entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL;
        }
    }
}

NTSTATUS
kswordArkProcessPatchProtectionByDynDataObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel,
    _In_ UCHAR signatureLevel,
    _In_ UCHAR sectionSignatureLevel
    )
/*++

Routine Description:

    Patch EPROCESS protection bytes on an already referenced process object.
    Note: When terminating a hidden process, the PID field may have already been rewritten, so the actual write
    logic cannot rely on PsLookupProcessByProcessId. The caller is responsible for providing a resolved and valid
    EPROCESS reference; this function only writes the Protection/Signature bytes according to the DynData offset.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    ProtectionLevel - Target PS_PROTECTION raw byte.
    SignatureLevel - Target process signature level.
    SectionSignatureLevel - Target section signature level.

Return Value:

    STATUS_SUCCESS or a defensive failure status. The caller keeps ownership of
    ProcessObject and must dereference it outside this function.

--*/
{
    KswDynState dynState;
    ULONG protectionOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG signatureOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG sectionSignatureOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS dynDataStatus = STATUS_PROCEDURE_NOT_FOUND;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Processing order:
     * 1) Prioritize offsets decoded via the current kernel protection/signature accessor and validated through liveness cross-checking.
     *    It originates from currently loaded kernel code and can override profile misses or outdated DynData packages.
     * 2. Fall back to the DynData profile if runtime resolution fails.
     * Returns: success if any source completes write and read-back verification; otherwise returns a more specific failure.
     */
    if (kswordArkProcessRuntimeProtectionOffsets(
            &protectionOffset,
            &signatureOffset,
            &sectionSignatureOffset)) {
        status = kswordArkProcessPatchProtectionByOffsets(
            processObject,
            protectionOffset,
            signatureOffset,
            sectionSignatureOffset,
            protectionLevel,
            signatureLevel,
            sectionSignatureLevel);
        if (NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) !=
        KSW_CAP_PROCESS_PROTECTION_PATCH) {
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }
    if (!KswordARKProcessIsOffsetPresent(dynState.kernel.epProtection) ||
        !KswordARKProcessIsOffsetPresent(dynState.kernel.epSignatureLevel) ||
        !KswordARKProcessIsOffsetPresent(dynState.kernel.epSectionSignatureLevel)) {
        return NT_SUCCESS(status) ? STATUS_PROCEDURE_NOT_FOUND : status;
    }

    dynDataStatus = kswordArkProcessPatchProtectionByOffsets(
        processObject,
        dynState.kernel.epProtection,
        dynState.kernel.epSignatureLevel,
        dynState.kernel.epSectionSignatureLevel,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);
    return dynDataStatus;
}

NTSTATUS
kswordArkProcessReadProtectionByte(
    _In_ PEPROCESS processObject,
    _Out_ UCHAR* protectionByteOut
    )
/*++

Routine Description:

    Read EPROCESS.Protection from an already referenced process object.
    Note: The inspection path guarded by PP relies on this to determine if protection bytes were externally
    restored, so the offset parsing order must match the write path kswordArkProcessPatchProtectionByDynDataObject
    exactly; otherwise, a false tampering scenario occurs where data is written at offset A but read at offset B.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    ProtectionByteOut - Receives the current PS_PROTECTION raw byte.

Return Value:

    STATUS_SUCCESS when the byte was read; otherwise a resolution or access
    failure status.

--*/
{
    KswDynState dynState;
    ULONG protectionOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG signatureOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG sectionSignatureOffset = KSW_DYN_OFFSET_UNAVAILABLE;

    if (processObject == NULL || protectionByteOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *protectionByteOut = 0U;

    if (!kswordArkProcessRuntimeProtectionOffsets(
            &protectionOffset,
            &signatureOffset,
            &sectionSignatureOffset)) {
        RtlZeroMemory(&dynState, sizeof(dynState));
        kswordArkDynDataSnapshot(&dynState);
        protectionOffset = dynState.kernel.epProtection;
    }

    if (!KswordARKProcessIsOffsetPresent(protectionOffset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        const UCHAR* protectionByte = (const UCHAR*)processObject + protectionOffset;
        RtlCopyMemory(protectionByteOut, protectionByte, sizeof(*protectionByteOut));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessClearDebugPortByObject(
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Zero EPROCESS.DebugPort so an attached user-mode debugger loses its debug
    Only write the entire pointer field here, do not touch any bitfields. DynData
    provides field offsets but not bit offsets; bit order varies across Windows
    versions, so hardcoding bit numbers will write to incorrect bits on some versions.

Arguments:

    ProcessObject - Referenced target EPROCESS.

Return Value:

    STATUS_SUCCESS when the field was zeroed and verified. STATUS_PROCEDURE_NOT_FOUND
    when DynData has no DebugPort offset on this machine.

--*/
{
    KswDynState dynState;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if (!KswordARKProcessIsOffsetPresent(dynState.kernel.epDebugPort)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        PVOID* debugPortField = (PVOID*)((PUCHAR)processObject + dynState.kernel.epDebugPort);
        PVOID verifyValue = NULL;

        *debugPortField = NULL;
        verifyValue = *debugPortField;
        if (verifyValue != NULL) {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

NTSTATUS
kswordArkProcessPatchProtectionByDynData(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel,
    _In_ UCHAR signatureLevel,
    _In_ UCHAR sectionSignatureLevel
    )
/*++

Routine Description:

    Patch EPROCESS protection bytes by resolving the target from a PID first.
    Note: This entry point is reserved for existing R3 PPL configuration; hiding process termination chains
    routes through kswordArkProcessPatchProtectionByDynDataObject to avoid being blocked by PID rewriting.

Arguments:

    ProcessId - Target process ID.
    ProtectionLevel - Target PS_PROTECTION raw byte.
    SignatureLevel - Target process signature level.
    SectionSignatureLevel - Target section signature level.

Return Value:

    STATUS_SUCCESS or a defensive failure status.

--*/
{
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkProcessPatchProtectionByDynDataObject(
        processObject,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);

    ObDereferenceObject(processObject);
    return status;
}
