/*++
Module Name:
    driver_integrity.c
Abstract:
    Read-only DriverObject, module-view, service-key, and optional kernel-global
    evidence collection for DriverDock integrity diagnostics.
Environment:
    Kernel-mode Driver Framework
--*/
#include "driver_integrity.h"
#include "kernel_cpu_integrity.h"
#include <ntstrsafe.h>
#include <stdarg.h>
#define KSW_DRIVER_INTEGRITY_TAG 'iDsK'
#define KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE))
#define KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FieldName) \
    { FIELD_OFFSET(FAST_IO_DISPATCH, FieldName), #FieldName }
#define KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT 128UL
#define KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT 32UL
#define KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT 50UL
#define KSW_DRIVER_INTEGRITY_RTL_AVL_TABLE_SIZE_LIMIT 0x400UL
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
typedef PVOID
(NTAPI* KswDriverIntegrityExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );
typedef NTSTATUS
(NTAPI* KswDriverIntegrityAuxInitializeFn)(
    VOID
    );
typedef NTSTATUS
(NTAPI* KswDriverIntegrityAuxQueryModulesFn)(
    _Inout_ PULONG bufferSize,
    _In_ ULONG elementSize,
    _Out_writes_bytes_opt_(*bufferSize) PVOID queryInfo
    );
typedef struct KswDriverIntegrityAuxModuleBasicInfo
{
    PVOID imageBase;
} KswDriverIntegrityAuxModuleBasicInfo, *PkswDriverIntegrityAuxModuleBasicInfo;
typedef struct KswDriverIntegrityAuxModuleExtendedInfo
{
    KswDriverIntegrityAuxModuleBasicInfo basicInfo;
    ULONG imageSize;
    USHORT fileNameOffset;
    UCHAR fullPathName[256];
} KswDriverIntegrityAuxModuleExtendedInfo, *PkswDriverIntegrityAuxModuleExtendedInfo;
typedef struct KswDriverIntegrityFastIoField
{
    ULONG offset;
    PCSTR name;
} KswDriverIntegrityFastIoField, *PkswDriverIntegrityFastIoField;
typedef struct KswDriverIntegrityDeviceSnapshot
{
    PDEVICE_OBJECT nextDevice;
    PDEVICE_OBJECT attachedDevice;
    PDRIVER_OBJECT driverObject;
    ULONG deviceType;
    ULONG flags;
} KswDriverIntegrityDeviceSnapshot, *PkswDriverIntegrityDeviceSnapshot;
typedef struct KswDriverIntegrityPiddbAvlSummary
{
    ULONGLONG balancedRootLeftChild;
    ULONGLONG balancedRootRightChild;
    ULONGLONG balancedRootParentValue;
    ULONGLONG orderedPointer;
    ULONGLONG restartKey;
    ULONG whichOrderedElement;
    ULONG numberGenericTableElements;
    ULONG depthOfTree;
    ULONG deleteCount;
} KswDriverIntegrityPiddbAvlSummary, *PkswDriverIntegrityPiddbAvlSummary;
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
static const KswDriverIntegrityFastIoField kGKswordArkFastIoFields[] = {
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoCheckIfPossible),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoRead),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryBasicInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryStandardInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoLock),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockSingle),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockAll),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockAllByKey),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoDeviceControl),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireFileForNtCreateSection),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseFileForNtCreateSection),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoDetachDevice),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryNetworkOpenInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireForModWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlRead),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlReadComplete),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(PrepareMdlWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlWriteComplete),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoReadCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoWriteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlReadCompleteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlWriteCompleteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryOpen),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseForModWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireForCcFlush),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseForCcFlush)
};
static PVOID
kswordArkDriverIntegrityAllocate(
    _In_ SIZE_T bufferBytes
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    static volatile LONG allocatorResolved = 0;
    static KswDriverIntegrityExAllocatePooL2Fn allocatePool2 = NULL;
    if (bufferBytes == 0U) {
        return NULL;
    }
    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        allocatePool2 = (KswDriverIntegrityExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }
    if (allocatePool2 != NULL) {
        return allocatePool2(POOL_FLAG_NON_PAGED, bufferBytes, KSW_DRIVER_INTEGRITY_TAG);
    }
#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_DRIVER_INTEGRITY_TAG);
#pragma warning(pop)
}
static VOID
kswordArkDriverIntegrityFormatDetail(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_z_ PCWSTR formatText,
    ...
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    va_list arguments;
    if (destination == NULL || destinationChars == 0UL || formatText == NULL) {
        return;
    }
    destination[0] = L'\0';
    va_start(arguments, formatText);
    (VOID)RtlStringCbVPrintfW(destination, (SIZE_T)destinationChars * sizeof(WCHAR), formatText, arguments);
    va_end(arguments);
    destination[destinationChars - 1UL] = L'\0';
}
static VOID
kswordArkDriverIntegrityCopyUnicode(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG charsToCopy = 0UL;
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }
    charsToCopy = (ULONG)(source->Length / sizeof(WCHAR));
    if (charsToCopy >= destinationChars) {
        charsToCopy = destinationChars - 1UL;
    }
    RtlCopyMemory(destination, source->Buffer, (SIZE_T)charsToCopy * sizeof(WCHAR));
    destination[charsToCopy] = L'\0';
}
static BOOLEAN
kswordArkDriverIntegrityDynOffsetPresent(
    _In_ ULONG offset
    )

/* Read-only helper; returns TRUE only for explicit PDB/DynData offsets. */
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}
static BOOLEAN
kswordArkDriverIntegrityReadUnloadedUnicodeName(
    _In_ ULONGLONG entryAddress,
    _In_ ULONG nameOffset,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )

/* Read-only helper; reads one _UNLOADED_DRIVERS.Name safely into a bounded text buffer. */
{
    UNICODE_STRING nameString;
    ULONG copyChars = 0UL;
    if (destination == NULL || destinationChars == 0UL) {
        return FALSE;
    }
    destination[0] = L'\0';
    if (entryAddress == 0ULL || !kswordArkDriverIntegrityDynOffsetPresent(nameOffset)) {
        return FALSE;
    }
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + (ULONGLONG)nameOffset), &nameString, sizeof(nameString))) {
        return FALSE;
    }
    if (nameString.Buffer == NULL || nameString.Length == 0U || nameString.Length > 512U || nameString.MaximumLength > 1024U) {
        return FALSE;
    }
    copyChars = (ULONG)(nameString.Length / sizeof(WCHAR));
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
    }
    if (!kswordArkHookReadMemorySafe((const VOID*)nameString.Buffer, destination, (SIZE_T)copyChars * sizeof(WCHAR))) {
        destination[0] = L'\0';
        return FALSE;
    }
    destination[copyChars] = L'\0';
    return TRUE;
}
static BOOLEAN
kswordArkDriverIntegrityReadUnloadedUlong64(
    _In_ ULONGLONG entryAddress,
    _In_ ULONG fieldOffset,
    _Out_ ULONGLONG* valueOut
    )

/* Read-only helper; reads one pointer-sized unloaded-driver field using PDB offset evidence. */
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0ULL;
    if (entryAddress == 0ULL || !kswordArkDriverIntegrityDynOffsetPresent(fieldOffset)) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + (ULONGLONG)fieldOffset), valueOut, sizeof(*valueOut));
}
static BOOLEAN
kswordArkDriverIntegrityReadUlongByOffset(
    _In_ ULONGLONG baseAddress,
    _In_ ULONG fieldOffset,
    _Out_ ULONG* valueOut
    )

/* Read-only helper; reads one ULONG field from a PDB-gated structure offset. */
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0UL;
    if (baseAddress == 0ULL || !kswordArkDriverIntegrityDynOffsetPresent(fieldOffset)) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(baseAddress + (ULONGLONG)fieldOffset), valueOut, sizeof(*valueOut));
}
static BOOLEAN
kswordArkDriverIntegrityReadPointerByOffset(
    _In_ ULONGLONG baseAddress,
    _In_ ULONG fieldOffset,
    _Out_ ULONGLONG* valueOut
    )

/* Read-only helper; reads one pointer-sized field from a PDB-gated structure offset. */
{
    PVOID pointerValue = NULL;
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0ULL;
    if (baseAddress == 0ULL || !kswordArkDriverIntegrityDynOffsetPresent(fieldOffset)) {
        return FALSE;
    }
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(baseAddress + (ULONGLONG)fieldOffset), &pointerValue, sizeof(pointerValue))) {
        return FALSE;
    }
    *valueOut = (ULONGLONG)(ULONG_PTR)pointerValue;
    return TRUE;
}
static BOOLEAN
kswordArkDriverIntegrityReadPointerAtOffset(
    _In_ ULONGLONG baseAddress,
    _In_ ULONG fieldOffset,
    _Out_ ULONGLONG* valueOut
    )

/* Read-only helper; reads one pointer-sized field where offset zero is valid. */
{
    PVOID pointerValue = NULL;
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0ULL;
    if (baseAddress == 0ULL || fieldOffset == KSW_DYN_OFFSET_UNAVAILABLE || fieldOffset == 0x0000FFFFUL) {
        return FALSE;
    }
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(baseAddress + (ULONGLONG)fieldOffset), &pointerValue, sizeof(pointerValue))) {
        return FALSE;
    }
    *valueOut = (ULONGLONG)(ULONG_PTR)pointerValue;
    return TRUE;
}
static NTSTATUS
kswordArkDriverIntegrityBuildDriverObjectName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* sourceName,
    _Out_writes_(destinationChars) PWCHAR destinationName,
    _In_ ULONG destinationChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG inputChars = 0UL;
    if (sourceName == NULL || destinationName == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destinationName[0] = L'\0';
    while (inputChars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS && sourceName[inputChars] != L'\0') {
        ++inputChars;
    }
    if (inputChars == 0UL || inputChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (sourceName[0] == L'\\') {
        return RtlStringCchCopyNW(destinationName, destinationChars, sourceName, inputChars);
    }
    return RtlStringCchPrintfW(destinationName, destinationChars, L"\\Driver\\%ws", sourceName);
}
static NTSTATUS
kswordArkDriverIntegrityExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _Out_writes_(leafChars) PWCHAR leafName,
    _In_ ULONG leafChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG index = 0UL;
    ULONG leafStart = 0UL;
    if (objectName == NULL || leafName == NULL || leafChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    leafName[0] = L'\0';
    while (index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS && objectName[index] != L'\0') {
        if (objectName[index] == L'\\') {
            leafStart = index + 1UL;
        }
        ++index;
    }
    if (index == 0UL || leafStart >= index) {
        return STATUS_INVALID_PARAMETER;
    }
    return RtlStringCchCopyW(leafName, leafChars, objectName + leafStart);
}
static BOOLEAN
kswordArkDriverIntegrityNameHasPrefix(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _In_z_ const WCHAR* prefix
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG index = 0UL;
    if (objectName == NULL || prefix == NULL) {
        return FALSE;
    }
    while (prefix[index] != L'\0') {
        WCHAR left = objectName[index];
        WCHAR right = prefix[index];
        if (left >= L'a' && left <= L'z') {
            left = (WCHAR)(left - L'a' + L'A');
        }
        if (right >= L'a' && right <= L'z') {
            right = (WCHAR)(right - L'a' + L'A');
        }
        if (left != right) {
            return FALSE;
        }
        ++index;
    }
    return TRUE;
}
static NTSTATUS
kswordArkDriverIntegrityReferenceCandidateName(
    _In_z_ const WCHAR* candidateName,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    UNICODE_STRING objectName;
    NTSTATUS status = STATUS_SUCCESS;
    if (candidateName == NULL || driverObjectOut == NULL || IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    RtlInitUnicodeString(&objectName, candidateName);
    status = ObReferenceObjectByName(&objectName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)driverObjectOut);
    if (!NT_SUCCESS(status)) {
        *driverObjectOut = NULL;
    }
    return status;
}
static NTSTATUS
kswordArkDriverIntegrityReferenceDriverObject(
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    WCHAR firstCandidate[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR leafName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR alternateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    if (request == NULL || driverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    status = kswordArkDriverIntegrityBuildDriverObjectName(request->driverName, firstCandidate, RTL_NUMBER_OF(firstCandidate));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkDriverIntegrityReferenceCandidateName(firstCandidate, driverObjectOut);
    if (NT_SUCCESS(status) || (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND && status != STATUS_NOT_FOUND)) {
        return status;
    }
    if (!NT_SUCCESS(kswordArkDriverIntegrityExtractLeafName(firstCandidate, leafName, RTL_NUMBER_OF(leafName)))) {
        return status;
    }
    if (!kswordArkDriverIntegrityNameHasPrefix(firstCandidate, L"\\FileSystem\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(alternateName, RTL_NUMBER_OF(alternateName), L"\\FileSystem\\%ws", leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverIntegrityReferenceCandidateName(alternateName, driverObjectOut);
            if (NT_SUCCESS(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }
    if (!kswordArkDriverIntegrityNameHasPrefix(firstCandidate, L"\\FileSystem\\Filters\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(alternateName, RTL_NUMBER_OF(alternateName), L"\\FileSystem\\Filters\\%ws", leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverIntegrityReferenceCandidateName(alternateName, driverObjectOut);
            if (NT_SUCCESS(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }
    return status;
}
static ULONG
kswordArkDriverIntegrityPointerRisk(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_opt_ const KswHookSystemModuleEntry* driverModule,
    _In_ ULONGLONG pointerValue
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    const KswHookSystemModuleEntry* ownerModule = NULL;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    if (pointerValue == 0ULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER;
    }
    ownerModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, pointerValue);
    if (ownerModule == NULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    if (driverModule != NULL && ownerModule->imageBase != driverModule->imageBase) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
    }
    return riskFlags;
}
static KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*
kswordArkDriverIntegrityLastEvidence(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ ULONG evidenceClass,
    _In_ ULONGLONG objectAddress,
    _In_ ULONGLONG targetAddress
    )

/* Read-only helper; returns the last row when it matches the just-added evidence, otherwise NULL. */
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    if (builder == NULL || builder->response == NULL || builder->response->returnedCount == 0UL) {
        return NULL;
    }
    response = builder->response;
    row = &response->entries[response->returnedCount - 1UL];
    if (row->evidenceClass != evidenceClass || row->objectAddress != objectAddress || row->targetAddress != targetAddress) {
        return NULL;
    }
    return row;
}
static ULONG
kswordArkDriverIntegrityRangeState(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_opt_ const KswHookSystemModuleEntry* driverModule,
    _In_ ULONGLONG address
    )

/* Read-only helper; classifies an observed pointer into driver, other module, unresolved, or NULL range. */
{
    const KswHookSystemModuleEntry* ownerModule = NULL;
    if (address == 0ULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_NULL;
    }
    ownerModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, address);
    if (ownerModule == NULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_UNRESOLVED;
    }
    if (driverModule != NULL && ownerModule->imageBase == driverModule->imageBase) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_IN_DRIVER;
    }
    return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_IN_OTHER_MODULE;
}
static ULONG
kswordArkDriverIntegrityScoreRisk(
    _In_ ULONG riskFlags
    )

/* Read-only helper; maps evidence bits to a bounded 0..100 score without changing system state. */
{
    ULONG score = 0UL;
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) != 0UL) {
        score += 25UL;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) != 0UL) {
        score += 20UL;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) != 0UL) {
        score += 35UL;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) != 0UL) {
        score += 45UL;
    }
    if ((riskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)) != 0UL) {
        score += 35UL;
    }
    if ((riskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP | KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)) != 0UL) {
        score += 30UL;
    }
    if ((riskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD | KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)) != 0UL) {
        score += 10UL;
    }
    if ((riskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)) != 0UL) {
        score += 50UL;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) != 0UL) {
        score += 50UL;
    }
    return (score > 100UL) ? 100UL : score;
}
static VOID
kswordArkDriverIntegrityFinalizeRows(
    _Inout_ KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response
    )

/* Read-only helper; fills common status, field masks, and scores after all collectors finish. */
{
    ULONG index = 0UL;
    if (response == NULL) {
        return;
    }
    for (index = 0UL; index < response->returnedCount; ++index) {
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = &response->entries[index];
        row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_COMMON;
        if (row->ownerModuleBase != 0ULL) {
            row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OWNER_MODULE;
        }
        if (row->processorGroup != ~0UL || row->processorNumber != ~0UL || row->vector != ~0UL) {
            row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_CPU_CONTEXT;
        }
        row->riskScore = kswordArkDriverIntegrityScoreRisk(row->riskFlags);
        row->entryStatus = (row->riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK : KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) != 0UL) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED;
        }
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) != 0UL) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE;
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED;
        }
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE) != 0UL) {
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        }
        if (row->riskFlags != KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) {
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        }
        if ((row->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) != 0UL && row->entryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
        }
        response->fieldFlags |= row->fieldMask;
        response->statusFlags |= row->statusFlags;
    }
    if ((response->flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED) != 0UL) {
        response->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED;
    }
}
static VOID
kswordArkDriverIntegrityAddSystemModuleRow(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ NTSTATUS moduleStatus,
    _In_ ULONGLONG driverStart
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    const KswHookSystemModuleEntry* ownerModule = NULL;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    if (!NT_SUCCESS(moduleStatus) || moduleInfo == NULL) {
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"SystemModuleInformation unavailable, status=0x%08lX.", (ULONG)moduleStatus);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 20UL, ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    ownerModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, driverStart);
    if (ownerModule == NULL && driverStart != 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"SystemModuleInformation modules=%lu, target=0x%llX.", moduleInfo->numberOfModules, driverStart);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, (ownerModule != NULL) ? 95UL : 60UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
}
static VOID
kswordArkDriverIntegrityAddAuxKlibRow(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ ULONGLONG driverStart
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    UNICODE_STRING initName;
    UNICODE_STRING queryName;
    KswDriverIntegrityAuxInitializeFn auxInitialize = NULL;
    KswDriverIntegrityAuxQueryModulesFn auxQueryModules = NULL;
    KswDriverIntegrityAuxModuleExtendedInfo* modules = NULL;
    ULONG bufferBytes = 0UL;
    ULONG moduleCount = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    RtlInitUnicodeString(&initName, L"AuxKlibInitialize");
    RtlInitUnicodeString(&queryName, L"AuxKlibQueryModuleInformation");
    auxInitialize = (KswDriverIntegrityAuxInitializeFn)MmGetSystemRoutineAddress(&initName);
    auxQueryModules = (KswDriverIntegrityAuxQueryModulesFn)MmGetSystemRoutineAddress(&queryName);
    if (auxInitialize == NULL || auxQueryModules == NULL) {
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 20UL,
            ~0UL, ~0UL, ~0UL, NULL, L"AuxKlib exports unavailable; SystemModuleInformation remains primary.");
        return;
    }
    status = auxInitialize();
    if (NT_SUCCESS(status)) {
        status = auxQueryModules(&bufferBytes, sizeof(KswDriverIntegrityAuxModuleExtendedInfo), NULL);
    }
    if (!(NT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) || bufferBytes == 0UL) {
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib size query failed, status=0x%08lX.", (ULONG)status);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    modules = (KswDriverIntegrityAuxModuleExtendedInfo*)kswordArkDriverIntegrityAllocate(bufferBytes);
    if (modules == NULL) {
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, L"AuxKlib buffer allocation failed.");
        return;
    }
    status = auxQueryModules(&bufferBytes, sizeof(KswDriverIntegrityAuxModuleExtendedInfo), modules);
    moduleCount = NT_SUCCESS(status) ? (bufferBytes / (ULONG)sizeof(KswDriverIntegrityAuxModuleExtendedInfo)) : 0UL;
    for (index = 0UL; index < moduleCount; ++index) {
        const ULONGLONG kBase = (ULONGLONG)(ULONG_PTR)modules[index].basicInfo.imageBase;
        const ULONGLONG kEnd = kBase + (ULONGLONG)modules[index].imageSize;
        if (driverStart >= kBase && driverStart < kEnd) {
            kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib modules=%lu, matched base=0x%llX size=0x%lX.", moduleCount, kBase, modules[index].imageSize);
            kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 90UL,
                ~0UL, ~0UL, ~0UL, NULL, detail);
            ExFreePoolWithTag(modules, KSW_DRIVER_INTEGRITY_TAG);
            return;
        }
    }
    kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib status=0x%08lX, modules=%lu, target not matched.", (ULONG)status, moduleCount);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, driverStart,
        NT_SUCCESS(status) ? KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED : KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, NT_SUCCESS(status) ? 60UL : 30UL, ~0UL, ~0UL, ~0UL, NULL, detail);
    ExFreePoolWithTag(modules, KSW_DRIVER_INTEGRITY_TAG);
}
static VOID
kswordArkDriverIntegrityBuildUnloadedSummary(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG mmUnloadedAddress,
    _In_ ULONGLONG mmLastUnloadedAddress,
    _Out_writes_(detailChars) PWCHAR detail,
    _In_ ULONG detailChars,
    _Out_ ULONG* confidenceOut,
    _Out_ ULONG* statusFlagsOut
    )

/* Read-only helper; summarizes bounded MmUnloadedDrivers entries when PDB offsets are present. */
{
    ULONG lastIndex = 0UL;
    ULONG scanIndex = 0UL;
    ULONG nonEmptyCount = 0UL;
    ULONGLONG newestStart = 0ULL;
    ULONGLONG newestEnd = 0ULL;
    ULONGLONG newestTime = 0ULL;
    ULONG entrySize = 0UL;
    ULONGLONG recordsAddress = 0ULL;
    WCHAR newestName[96] = { 0 };
    BOOLEAN offsetsPresent = FALSE;
    if (detail == NULL || detailChars == 0UL || confidenceOut == NULL || statusFlagsOut == NULL) {
        return;
    }
    *confidenceOut = 45UL;
    *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
    detail[0] = L'\0';
    if (dynState == NULL || mmUnloadedAddress == 0ULL) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars, L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; global evidence incomplete.", mmUnloadedAddress, mmLastUnloadedAddress);
        *confidenceOut = 20UL;
        *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)mmUnloadedAddress,
            &recordsAddress,
            sizeof(recordsAddress)) ||
        recordsAddress == 0ULL) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"MmUnloadedDrivers global=0x%llX; record array pointer is null or unreadable.",
            mmUnloadedAddress);
        *confidenceOut = 30UL;
        *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        return;
    }
    offsetsPresent =
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.uldName) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.uldStartAddress) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.uldEndAddress) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.uldCurrentTime) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.uldTypeSize);
    if (!offsetsPresent) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; _UNLOADED_DRIVERS offsets/type-size missing.",
            mmUnloadedAddress, mmLastUnloadedAddress);
        *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    entrySize = dynState->kernel.uldTypeSize;
    if (entrySize < sizeof(UNICODE_STRING) || entrySize > 0x200UL) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; _UNLOADED_DRIVERS TypeSize invalid: %lu.",
            mmUnloadedAddress, mmLastUnloadedAddress, entrySize);
        *confidenceOut = 35UL;
        *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    if (mmLastUnloadedAddress != 0ULL &&
        !kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)mmLastUnloadedAddress, &lastIndex, sizeof(lastIndex))) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; last index read failed.",
            mmUnloadedAddress, mmLastUnloadedAddress);
        *confidenceOut = 35UL;
        return;
    }
    for (scanIndex = 0UL; scanIndex < KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT; ++scanIndex) {
        const ULONGLONG kEntryAddress = recordsAddress + ((ULONGLONG)scanIndex * (ULONGLONG)entrySize);
        ULONGLONG startAddress = 0ULL;
        ULONGLONG endAddress = 0ULL;
        ULONGLONG timeValue = 0ULL;
        WCHAR nameText[96] = { 0 };
        if (!kswordArkDriverIntegrityReadUnloadedUlong64(kEntryAddress, dynState->kernel.uldStartAddress, &startAddress) ||
            !kswordArkDriverIntegrityReadUnloadedUlong64(kEntryAddress, dynState->kernel.uldEndAddress, &endAddress) ||
            !kswordArkDriverIntegrityReadUnloadedUlong64(kEntryAddress, dynState->kernel.uldCurrentTime, &timeValue)) {
            continue;
        }
        if (startAddress == 0ULL && endAddress == 0ULL && timeValue == 0ULL) {
            continue;
        }
        nonEmptyCount += 1UL;
        if (timeValue >= newestTime) {
            newestTime = timeValue;
            newestStart = startAddress;
            newestEnd = endAddress;
            if (!kswordArkDriverIntegrityReadUnloadedUnicodeName(kEntryAddress, dynState->kernel.uldName, nameText, RTL_NUMBER_OF(nameText))) {
                (VOID)RtlStringCchCopyW(nameText, RTL_NUMBER_OF(nameText), L"<name unread>");
            }
            (VOID)RtlStringCchCopyW(newestName, RTL_NUMBER_OF(newestName), nameText);
        }
    }
    kswordArkDriverIntegrityFormatDetail(detail, detailChars,
        L"MmUnloadedDrivers global=0x%llX records=0x%llX MmLastUnloadedDriver=0x%llX typeSize=%lu lastIndex=%lu scanned=%lu nonEmpty=%lu newest=%ws [0x%llX-0x%llX] time=0x%llX.",
        mmUnloadedAddress, recordsAddress, mmLastUnloadedAddress, entrySize, lastIndex, KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT,
        nonEmptyCount, newestName[0] != L'\0' ? newestName : L"<none>", newestStart, newestEnd, newestTime);
    *confidenceOut = (nonEmptyCount != 0UL) ? 70UL : 55UL;
    *statusFlagsOut = (nonEmptyCount != 0UL) ? 0UL : KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
}
static VOID
kswordArkDriverIntegrityBuildPiDdbSummary(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG piDdbAddress,
    _Out_writes_(detailChars) PWCHAR detail,
    _In_ ULONG detailChars,
    _Out_ ULONG* confidenceOut,
    _Out_ ULONG* statusFlagsOut
    )

/* Read-only helper; summarizes the PDB-gated _RTL_AVL_TABLE header for PiDDBCacheTable. */
{
    ULONGLONG balancedRootAddress = 0ULL;
    ULONG avlTypeSize = 0UL;
    KswDriverIntegrityPiddbAvlSummary summary;
    BOOLEAN requiredOffsetsPresent = FALSE;
    RtlZeroMemory(&summary, sizeof(summary));
    if (detail == NULL || detailChars == 0UL || confidenceOut == NULL || statusFlagsOut == NULL) {
        return;
    }
    *confidenceOut = 35UL;
    *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
    detail[0] = L'\0';
    if (dynState == NULL || piDdbAddress == 0ULL) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars, L"PiDDBCacheTable global=0x%llX; global evidence incomplete.", piDdbAddress);
        *confidenceOut = 20UL;
        *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    requiredOffsetsPresent =
        dynState->kernel.rtlAvlBalancedRoot != KSW_DYN_OFFSET_UNAVAILABLE &&
        dynState->kernel.rtlAvlBalancedRoot != 0x0000FFFFUL &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.rtlAvlNumberGenericTableElements) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.rtlAvlDepthOfTree) &&
        kswordArkDriverIntegrityDynOffsetPresent(dynState->kernel.rtlAvlTypeSize);
    if (!requiredOffsetsPresent) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"PiDDBCacheTable global=0x%llX; _RTL_AVL_TABLE offsets/type-size missing, entry walk disabled.",
            piDdbAddress);
        return;
    }
    avlTypeSize = dynState->kernel.rtlAvlTypeSize;
    if (avlTypeSize < (sizeof(PVOID) * 3U) || avlTypeSize > KSW_DRIVER_INTEGRITY_RTL_AVL_TABLE_SIZE_LIMIT) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"PiDDBCacheTable global=0x%llX; _RTL_AVL_TABLE TypeSize invalid: %lu.",
            piDdbAddress, avlTypeSize);
        return;
    }
    balancedRootAddress = piDdbAddress + (ULONGLONG)dynState->kernel.rtlAvlBalancedRoot;
    (VOID)kswordArkDriverIntegrityReadPointerAtOffset(balancedRootAddress, 0UL, &summary.balancedRootLeftChild);
    (VOID)kswordArkDriverIntegrityReadPointerAtOffset(balancedRootAddress, (ULONG)sizeof(PVOID), &summary.balancedRootRightChild);
    (VOID)kswordArkDriverIntegrityReadPointerAtOffset(balancedRootAddress, (ULONG)(sizeof(PVOID) * 2U), &summary.balancedRootParentValue);
    (VOID)kswordArkDriverIntegrityReadPointerByOffset(piDdbAddress, dynState->kernel.rtlAvlOrderedPointer, &summary.orderedPointer);
    (VOID)kswordArkDriverIntegrityReadPointerByOffset(piDdbAddress, dynState->kernel.rtlAvlRestartKey, &summary.restartKey);
    (VOID)kswordArkDriverIntegrityReadUlongByOffset(piDdbAddress, dynState->kernel.rtlAvlWhichOrderedElement, &summary.whichOrderedElement);
    if (!kswordArkDriverIntegrityReadUlongByOffset(piDdbAddress, dynState->kernel.rtlAvlNumberGenericTableElements, &summary.numberGenericTableElements) ||
        !kswordArkDriverIntegrityReadUlongByOffset(piDdbAddress, dynState->kernel.rtlAvlDepthOfTree, &summary.depthOfTree)) {
        kswordArkDriverIntegrityFormatDetail(detail, detailChars,
            L"PiDDBCacheTable global=0x%llX typeSize=%lu; AVL count/depth read failed.",
            piDdbAddress, avlTypeSize);
        *confidenceOut = 40UL;
        return;
    }
    (VOID)kswordArkDriverIntegrityReadUlongByOffset(piDdbAddress, dynState->kernel.rtlAvlDeleteCount, &summary.deleteCount);
    kswordArkDriverIntegrityFormatDetail(detail, detailChars,
        L"PiDDBCacheTable global=0x%llX typeSize=%lu count=%lu depth=%lu deleteCount=%lu balancedRoot=0x%llX left=0x%llX right=0x%llX parent=0x%llX ordered=0x%llX which=%lu restart=0x%llX; entry schema not yet consumed.",
        piDdbAddress, avlTypeSize, summary.numberGenericTableElements, summary.depthOfTree, summary.deleteCount,
        balancedRootAddress, summary.balancedRootLeftChild, summary.balancedRootRightChild,
        summary.balancedRootParentValue, summary.orderedPointer, summary.whichOrderedElement, summary.restartKey);
    *confidenceOut = 65UL;
    *statusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
}
static VOID
kswordArkDriverIntegrityAddDynRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ const KswDynState* dynState,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG driverSection,
    _In_ ULONGLONG driverSize,
    _In_ ULONGLONG driverStart,
    _In_ BOOLEAN includeOptionalGlobals
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    KswDriverIntegrityLdrTarget target;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    NTSTATUS ldrStatus = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    RtlZeroMemory(&target, sizeof(target));
    ldrStatus = kswordArkDriverIntegrityFindLoadedModule(dynState, driverStart, &target);
    if (NT_SUCCESS(ldrStatus) && target.found) {
        const KswHookSystemModuleEntry* ownerModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, target.dllBase);
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        if (driverSection != 0ULL && driverSection != target.entryAddress) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH;
        }
        if (driverStart != target.dllBase || driverSize != (ULONGLONG)target.sizeOfImage || target.sizeOfImage == 0UL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
        if (moduleInfo != NULL && ownerModule == NULL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
            L"PsLoadedModuleList=0x%llX KLDR=0x%llX DllBase=0x%llX Size=0x%lX DriverSize=0x%llX BaseName=%ws.",
            target.listHeadAddress, target.entryAddress, target.dllBase, target.sizeOfImage, driverSize,
            target.baseDllName[0] != L'\0' ? target.baseDllName : L"<unread>");
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES,
            driverSection, target.dllBase, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            90UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES, driverSection, target.dllBase); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_KLDR; row->kldrEntryAddress = target.entryAddress; row->kldrListHeadAddress = target.listHeadAddress; row->kldrDllBase = target.dllBase; row->kldrSizeOfImage = target.sizeOfImage; }
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION,
            driverSection, target.entryAddress, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            90UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, driverSection, target.entryAddress); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_KLDR; row->kldrEntryAddress = target.entryAddress; row->kldrListHeadAddress = target.listHeadAddress; row->kldrDllBase = target.dllBase; row->kldrSizeOfImage = target.sizeOfImage; }
    }
    else {
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
            L"PsLoadedModuleList unavailable or target not found, status=0x%08lX, listHead=0x%llX.",
            (ULONG)ldrStatus, target.listHeadAddress);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES, driverSection, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, 25UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, driverSection, driverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, 25UL,
            ~0UL, ~0UL, ~0UL, NULL, L"DriverSection captured; KLDR alignment unavailable or target not found through DynData.");
    }
    if (includeOptionalGlobals) {
        ULONGLONG mmUnloaded = kswordArkDriverIntegrityNtosAddressFromRva(dynState, dynState != NULL ? dynState->kernelGlobals.mmUnloadedDrivers : 0UL, sizeof(PVOID));
        ULONGLONG piDdb = kswordArkDriverIntegrityNtosAddressFromRva(dynState, dynState != NULL ? dynState->kernelGlobals.piDdbCacheTable : 0UL, sizeof(PVOID));
        ULONGLONG mmLastUnloaded = kswordArkDriverIntegrityNtosAddressFromRva(dynState, dynState != NULL ? dynState->kernelGlobals.mmLastUnloadedDriver : 0UL, sizeof(ULONG));
        const KswHookSystemModuleEntry* mmOwner = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, mmUnloaded);
        const KswHookSystemModuleEntry* piOwner = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, piDdb);
        ULONG mmSource = KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
        ULONG piSource = KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
        ULONG mmConfidence = 45UL;
        ULONG mmStatusFlags = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        ULONG piConfidence = 35UL;
        ULONG piStatusFlags = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        if (mmUnloaded != 0ULL) {
            mmSource |= KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE;
        }
        if (piDdb != 0ULL) {
            piSource |= KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE;
        }
        kswordArkDriverIntegrityBuildUnloadedSummary(dynState, mmUnloaded, mmLastUnloaded, detail, RTL_NUMBER_OF(detail), &mmConfidence, &mmStatusFlags);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, mmUnloaded, 0ULL,
            (mmUnloaded == 0ULL) ? (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) : KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE,
            mmSource, (mmUnloaded == 0ULL) ? 15UL : mmConfidence, ~0UL, ~0UL, ~0UL, mmOwner, detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, mmUnloaded, 0ULL); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OPTIONAL_GLOBAL; row->statusFlags |= (mmUnloaded == 0ULL) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED : mmStatusFlags; }
        kswordArkDriverIntegrityBuildPiDdbSummary(dynState, piDdb, detail, RTL_NUMBER_OF(detail), &piConfidence, &piStatusFlags);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, piDdb, 0ULL,
            (piDdb == 0ULL) ? (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) : KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE,
            piSource, (piDdb == 0ULL) ? 15UL : piConfidence, ~0UL, ~0UL, ~0UL, piOwner, detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, piDdb, 0ULL); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OPTIONAL_GLOBAL; row->statusFlags |= (piDdb == 0ULL) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED : piStatusFlags; }
    }
}
static VOID
kswordArkDriverIntegrityAddDriverObjectRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    const ULONGLONG kDriverStart = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
    const ULONGLONG kDriverSize = (ULONGLONG)driverObject->DriverSize;
    const KswHookSystemModuleEntry* driverModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, kDriverStart);
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG index = 0UL;
    if (kDriverStart == 0ULL || kDriverSize == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER;
    }
    if (driverModule == NULL && kDriverStart != 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    if (driverModule != NULL) {
        const ULONGLONG kModuleBase = (ULONGLONG)(ULONG_PTR)driverModule->imageBase;
        const ULONGLONG kModuleEnd = kModuleBase + (ULONGLONG)driverModule->imageSize;
        if (kDriverStart != kModuleBase || kDriverStart + kDriverSize > kModuleEnd || kDriverSize != (ULONGLONG)driverModule->imageSize) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
    }
    kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"DriverObject=0x%p DriverStart=0x%llX DriverSize=0x%llX DriverSection=0x%p DriverUnload=0x%p.",
        driverObject, kDriverStart, kDriverSize, driverObject->DriverSection, driverObject->DriverUnload);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)driverObject, kDriverStart, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, (driverModule != NULL) ? 90UL : 55UL,
        ~0UL, ~0UL, ~0UL, driverModule, detail);
    row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)driverObject, kDriverStart); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject; row->driverStart = kDriverStart; row->driverSize = kDriverSize; row->driverSection = (ULONGLONG)(ULONG_PTR)driverObject->DriverSection; row->driverUnload = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload; }
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, (ULONGLONG)(ULONG_PTR)driverObject->DriverSection, kDriverStart,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION,
        70UL, ~0UL, ~0UL, ~0UL, driverModule, L"DriverSection captured read-only; KLDR alignment row follows when DynData is available.");
    if (driverObject->DriverUnload == NULL) {
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)driverObject, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 75UL,
            ~0UL, ~0UL, ~0UL, NULL, L"DriverObject->DriverUnload is NULL; no unload or repair attempted.");
    }
    for (index = 0UL; index < KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT; ++index) {
        const ULONGLONG kAddress = (ULONGLONG)(ULONG_PTR)driverObject->MajorFunction[index];
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"MajorFunction[%lu]=0x%llX.", index, kAddress);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION, (ULONGLONG)(ULONG_PTR)&driverObject->MajorFunction[index], kAddress,
            kswordArkDriverIntegrityPointerRisk(moduleInfo, driverModule, kAddress), KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            85UL, ~0UL, ~0UL, ~0UL, kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, kAddress), detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION, (ULONGLONG)(ULONG_PTR)&driverObject->MajorFunction[index], kAddress); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DISPATCH_TARGET | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = index; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject; row->driverStart = kDriverStart; row->driverSize = kDriverSize; row->rangeState = kswordArkDriverIntegrityRangeState(moduleInfo, driverModule, kAddress); }
    }
    if (driverObject->FastIoDispatch != NULL) {
        for (index = 0UL; index < RTL_NUMBER_OF(kGKswordArkFastIoFields); ++index) {
            const UCHAR* fieldAddress = (const UCHAR*)driverObject->FastIoDispatch + kGKswordArkFastIoFields[index].offset;
            PVOID routine = NULL;
            if (!kswordArkHookReadMemorySafe(fieldAddress, &routine, sizeof(routine)) || routine == NULL) {
                continue;
            }
            kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"FastIoDispatch.%S=0x%p.", kGKswordArkFastIoFields[index].name, routine);
            kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO, (ULONGLONG)(ULONG_PTR)fieldAddress, (ULONGLONG)(ULONG_PTR)routine,
                kswordArkDriverIntegrityPointerRisk(moduleInfo, driverModule, (ULONGLONG)(ULONG_PTR)routine),
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
                80UL, ~0UL, ~0UL, ~0UL, kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, (ULONGLONG)(ULONG_PTR)routine), detail);
            row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO, (ULONGLONG)(ULONG_PTR)fieldAddress, (ULONGLONG)(ULONG_PTR)routine); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_FAST_IO_TARGET | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = index; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject; row->driverStart = kDriverStart; row->driverSize = kDriverSize; row->rangeState = kswordArkDriverIntegrityRangeState(moduleInfo, driverModule, (ULONGLONG)(ULONG_PTR)routine); }
        }
    }
}
static BOOLEAN
kswordArkDriverIntegrityReadDeviceSnapshot(
    _In_ PDEVICE_OBJECT deviceObject,
    _Out_ KswDriverIntegrityDeviceSnapshot* snapshot
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    if (deviceObject == NULL || snapshot == NULL) {
        return FALSE;
    }
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    return kswordArkHookReadMemorySafe(&deviceObject->NextDevice, &snapshot->nextDevice, sizeof(snapshot->nextDevice)) &&
        kswordArkHookReadMemorySafe(&deviceObject->AttachedDevice, &snapshot->attachedDevice, sizeof(snapshot->attachedDevice)) &&
        kswordArkHookReadMemorySafe(&deviceObject->DriverObject, &snapshot->driverObject, sizeof(snapshot->driverObject)) &&
        kswordArkHookReadMemorySafe(&deviceObject->DeviceType, &snapshot->deviceType, sizeof(snapshot->deviceType)) &&
        kswordArkHookReadMemorySafe(&deviceObject->Flags, &snapshot->flags, sizeof(snapshot->flags));
}
static BOOLEAN
kswordArkDriverIntegrityPointerVisited(
    _In_reads_(visitedCount) PDEVICE_OBJECT const* visited,
    _In_ ULONG visitedCount,
    _In_opt_ PDEVICE_OBJECT candidate
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    ULONG index = 0UL;
    if (candidate == NULL) {
        return FALSE;
    }
    for (index = 0UL; index < visitedCount; ++index) {
        if (visited[index] == candidate) {
            return TRUE;
        }
    }
    return FALSE;
}
static VOID
kswordArkDriverIntegrityAddDeviceRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG maxDevices,
    _In_ ULONG maxAttachedDevices
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    PDEVICE_OBJECT visitedRoots[KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT] = { 0 };
    PDEVICE_OBJECT rootDevice = driverObject->DeviceObject;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG rootCount = 0UL;
    if (maxDevices == 0UL || maxDevices > KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT) {
        maxDevices = KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT;
    }
    if (maxAttachedDevices == 0UL || maxAttachedDevices > KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT) {
        maxAttachedDevices = KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT;
    }
    while (rootDevice != NULL && rootCount < maxDevices) {
        KswDriverIntegrityDeviceSnapshot rootSnapshot;
        PDEVICE_OBJECT visitedAttached[KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT] = { 0 };
        PDEVICE_OBJECT attachedDevice = NULL;
        ULONG attachedCount = 0UL;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
        if (kswordArkDriverIntegrityPointerVisited(visitedRoots, rootCount, rootDevice)) {
            kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 90UL, ~0UL, ~0UL, ~0UL, NULL,
                L"DriverObject->DeviceObject/NextDevice chain loop detected.");
            break;
        }
        visitedRoots[rootCount++] = rootDevice;
        if (!kswordArkDriverIntegrityReadDeviceSnapshot(rootDevice, &rootSnapshot)) {
            kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 40UL, ~0UL, ~0UL, ~0UL, NULL,
                L"Failed to safely read root DeviceObject fields.");
            break;
        }
        if (rootSnapshot.driverObject != driverObject) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"DeviceObject=0x%p Next=0x%p Attached=0x%p Type=0x%lX Flags=0x%lX.",
            rootDevice, rootSnapshot.nextDevice, rootSnapshot.attachedDevice, rootSnapshot.deviceType, rootSnapshot.flags);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice,
            (ULONGLONG)(ULONG_PTR)rootSnapshot.attachedDevice, riskFlags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 80UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)rootSnapshot.attachedDevice); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DEVICE_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject; row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootDevice; row->nextDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.nextDevice; row->attachedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.attachedDevice; row->deviceDriverObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.driverObject; row->deviceType = rootSnapshot.deviceType; row->deviceFlags = rootSnapshot.flags; }
        attachedDevice = rootSnapshot.attachedDevice;
        while (attachedDevice != NULL && attachedCount < maxAttachedDevices) {
            KswDriverIntegrityDeviceSnapshot attachedSnapshot;
            ULONG attachedRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
            if (kswordArkDriverIntegrityPointerVisited(visitedAttached, attachedCount, attachedDevice)) {
                kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)attachedDevice,
                    KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 90UL, ~0UL, ~0UL, ~0UL, NULL,
                    L"AttachedDevice chain loop detected.");
                break;
            }
            visitedAttached[attachedCount++] = attachedDevice;
            if (!kswordArkDriverIntegrityReadDeviceSnapshot(attachedDevice, &attachedSnapshot)) {
                break;
            }
            if (attachedSnapshot.driverObject != driverObject) {
                attachedRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH;
            }
            kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AttachedDevice=0x%p OwnerDriver=0x%p NextAttached=0x%p.",
                attachedDevice, attachedSnapshot.driverObject, attachedSnapshot.attachedDevice);
            kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice,
                (ULONGLONG)(ULONG_PTR)attachedDevice, attachedRisk, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 75UL,
                ~0UL, ~0UL, ~0UL, NULL, detail);
            row = kswordArkDriverIntegrityLastEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)attachedDevice); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DEVICE_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = attachedCount; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject; row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedDevice; row->nextDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.nextDevice; row->attachedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.attachedDevice; row->deviceDriverObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.driverObject; row->deviceType = attachedSnapshot.deviceType; row->deviceFlags = attachedSnapshot.flags; }
            attachedDevice = attachedSnapshot.attachedDevice;
        }
        rootDevice = rootSnapshot.nextDevice;
    }
}
static VOID
kswordArkDriverIntegrityAddServiceRow(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* request
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    WCHAR serviceName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR keyPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS] = { 0 };
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    if (driverObject != NULL && driverObject->DriverExtension != NULL) {
        kswordArkDriverIntegrityCopyUnicode(&driverObject->DriverExtension->ServiceKeyName, serviceName, RTL_NUMBER_OF(serviceName));
    }
    if (serviceName[0] == L'\0') {
        WCHAR objectName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        if (NT_SUCCESS(kswordArkDriverIntegrityBuildDriverObjectName(request->driverName, objectName, RTL_NUMBER_OF(objectName)))) {
            (VOID)kswordArkDriverIntegrityExtractLeafName(objectName, serviceName, RTL_NUMBER_OF(serviceName));
        }
    }
    if (serviceName[0] == L'\0') {
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, L"No service key name could be derived.");
        return;
    }
    status = RtlStringCchPrintfW(keyPath, RTL_NUMBER_OF(keyPath), L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws", serviceName);
    if (!NT_SUCCESS(status)) {
        return;
    }
    RtlInitUnicodeString(&keyName, keyPath);
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"Service key %ws open failed, status=0x%08lX.", serviceName, (ULONG)status);
        kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 45UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    kswordArkDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"Service key %ws opened read-only.", serviceName);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 80UL,
        ~0UL, ~0UL, ~0UL, NULL, detail);
    ZwClose(keyHandle);
}
NTSTATUS
kswordArkDriverQueryDriverIntegrity(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST requestSnapshot;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KswDriverIntegrityBuilder builder;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    KswDynState dynState;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG flags = 0UL;
    ULONG cpuCount = 0UL;
    ULONGLONG targetBase = 0ULL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(&requestSnapshot, sizeof(requestSnapshot));
    if (request != NULL) {
        RtlCopyMemory(&requestSnapshot, request, sizeof(requestSnapshot));
    }
    flags = (requestSnapshot.flags == 0UL) ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT : requestSnapshot.flags;
    if (requestSnapshot.maxRows == 0UL || requestSnapshot.maxRows > KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS) {
        requestSnapshot.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
    }
    capacity = (ULONG)((outputBufferLength - KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK;
    response->entrySize = sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
    response->lastStatus = STATUS_SUCCESS;
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&dynState, sizeof(dynState));
    builder.response = response;
    builder.capacity = capacity;
    builder.rowLimit = requestSnapshot.maxRows;
    moduleStatus = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    kswordArkDynDataSnapshot(&dynState);
    targetBase = requestSnapshot.targetModuleBase;
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT) != 0UL) {
        status = kswordArkDriverIntegrityReferenceDriverObject(&requestSnapshot, &driverObject);
        response->lastStatus = status;
        if (NT_SUCCESS(status)) {
            targetBase = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
        }
        else {
            response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
            kswordArkDriverIntegrityAddEvidence(&builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, 0ULL, targetBase,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 30UL, ~0UL, ~0UL, ~0UL, NULL,
                L"DriverObject reference failed; module and CPU evidence still collected.");
        }
    }
    kswordArkDriverIntegrityAddSystemModuleRow(&builder, moduleInfo, moduleStatus, targetBase);
    kswordArkDriverIntegrityAddAuxKlibRow(&builder, targetBase);
    if (driverObject != NULL) {
        kswordArkDriverIntegrityAddDriverObjectRows(&builder, driverObject, moduleInfo);
        kswordArkDriverIntegrityAddDeviceRows(&builder, driverObject, requestSnapshot.maxDevices, requestSnapshot.maxAttachedDevices);
    }
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_SERVICE) != 0UL) {
        kswordArkDriverIntegrityAddServiceRow(&builder, driverObject, &requestSnapshot);
    }
    if (driverObject != NULL) {
        kswordArkDriverIntegrityAddDynRows(
            &builder,
            &dynState,
            moduleInfo,
            (ULONGLONG)(ULONG_PTR)driverObject->DriverSection,
            (ULONGLONG)driverObject->DriverSize,
            (ULONGLONG)(ULONG_PTR)driverObject->DriverStart,
            ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) != 0UL) ? TRUE : FALSE);
    }
    else {
        kswordArkDriverIntegrityAddDynRows(&builder, &dynState, moduleInfo, 0ULL, 0ULL, targetBase,
            ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) != 0UL) ? TRUE : FALSE);
    }
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU) != 0UL) {
        status = kswordArkCpuIntegrityCollect(&builder, moduleInfo, flags, requestSnapshot.maxIdtVectorsPerCpu, &cpuCount);
        response->cpuCount = cpuCount;
        if (!NT_SUCCESS(status) && response->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
            response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
            response->lastStatus = status;
        }
    }
    response->moduleCount = (moduleInfo != NULL) ? moduleInfo->numberOfModules : 0UL;
    kswordArkDriverIntegrityFinalizeRows(response);
    if ((response->flags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)) != 0UL &&
        response->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
    }
    *bytesWrittenOut = KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE + ((size_t)response->returnedCount * sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    return STATUS_SUCCESS;
}
