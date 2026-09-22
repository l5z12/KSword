/*++

Module Name:

    callback_enum.c

Abstract:

    Implements the read-only callback traversal IOCTL for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include <fltKernel.h>
#include "callback_internal.h"
#define KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL 1
#include "callback_external_core.h"
#include "callback_extended_kernel.h"
#include "ark/ark_dyndata.h"
#include "../../platform/kernel_object_probe.h"

#define KSWORD_ARK_CALLBACK_ENUM_TAG 'eCbK'
#define KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES 4096UL
#define KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_ENUM_NOTIFY_SLOT_COUNT 64UL
#define KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_ENUM_OBJECT_TYPE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES 0x80L
#define KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES 0x180L
#define KSWORD_ARK_CALLBACK_ENUM_FAST_REF_MASK (~(ULONG_PTR)0x0FULL)
#define KSWORD_ARK_CALLBACK_ENUM_MAX_PDB_STRUCT_OFFSET 0x1000UL
#define SystemModuleInformation 11UL

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef struct KswordArkCallbackEnumCodeCandidate
{
    ULONG64 address;
    LONG relativeOffset;
} KswordArkCallbackEnumCodeCandidate;

typedef struct KswordArkCallbackEnumObjectScanResult
{
    ULONG64 preOperation;
    ULONG64 postOperation;
    ULONG operationMask;
    ULONG64 registrationBlock;
    BOOLEAN usedPdbOffsets;
} KswordArkCallbackEnumObjectScanResult;

typedef struct KswordArkCallbackEnumSourceContext
{
    ULONG source;
    ULONG trustFlags;
    ULONG removeBehavior;
    ULONG extraFieldFlags;
    PCWSTR detailPrefix;
} KswordArkCallbackEnumSourceContext;

typedef struct KswordArkCallbackEnumDyndataProfile
{
    KswDynState state;
    BOOLEAN active;
    ULONG64 ntosImageBase;
    ULONG ntosImageSize;
} KswordArkCallbackEnumDyndataProfile;

/* Note: Lock the wire layout for V2/V3 at compile time to prevent R0/R3 from misinterpreting pages due to alignment differences. */
C_ASSERT(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2) == 24U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2, entries) == 32U);
C_ASSERT(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST) == 40U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE, entries) == 48U);

typedef enum KswordArkCallbackEnumObjectListState
{
    kKswordArkCallbackEnumObjectListInvalid = 0,
    kKswordArkCallbackEnumObjectListEmpty = 1,
    kKswordArkCallbackEnumObjectListNonEmpty = 2
} KswordArkCallbackEnumObjectListState;

static const KswordArkCallbackEnumSourceContext kGKswordArkCallbackEnumPdbNotifySourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED,
    L"PDB callback profile trusted notify array"
};

static const KswordArkCallbackEnumSourceContext kGKswordArkCallbackEnumPdbRegistrySourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_NONE,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED,
    L"PDB callback profile trusted registry list"
};

static const KswordArkCallbackEnumSourceContext kGKswordArkCallbackEnumPdbObjectSourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
        KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE,
    L"PDB callback profile trusted object list"
};

/* Note: The two constants define the entry start offsets for responses compatible with V2 and snapshot V3, respectively. */
static const ULONG kGKswordArkCallbackEnumHeaderBytesV3 =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
static const ULONG kGKswordArkCallbackEnumHeaderBytesV2 =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));

_Must_inspect_result_
static NTSTATUS
kswordArkCallbackEnumResolveModuleByAddress(
    _In_ ULONG64 callbackAddress,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    );

extern NTSTATUS
kswordArkRegistryCallback(
    _In_opt_ PVOID callbackContext,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2
    );

extern VOID
kswordArkProcessCreateNotifyEx(
    _Inout_ PEPROCESS process,
    _In_ HANDLE processId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo
    );

extern VOID
kswordArkThreadCreateNotify(
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ BOOLEAN create
    );

extern VOID
kswordArkLoadImageNotify(
    _In_opt_ PUNICODE_STRING fullImageName,
    _In_ HANDLE processId,
    _In_ PIMAGE_INFO imageInfo
    );

extern OB_PREOP_CALLBACK_STATUS
kswordArkObjectPreOperation(
    _In_ PVOID registrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION operationInformation
    );

extern FLT_PREOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Outptr_result_maybenull_ PVOID* completionContext
    );

VOID
kswordArkCallbackEnumCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
/*++

Routine Description:

    Copy the NUL-terminated wide string to the fixed response field. Note: The function
    always truncates and terminates the string, so R3 can safely cast to the fixed field.

Arguments:

    Destination: Output wide-character buffer.
    DestinationChars - Capacity of the output buffer, in WCHARs.
    Source - optional input wide string.

Return Value:

    No return value.

--*/
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyNW(destination, (size_t)destinationChars, source, (size_t)(destinationChars - 1UL));
    destination[destinationChars - 1UL] = L'\0';
}

VOID
kswordArkCallbackEnumCopyUnicode(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_ PCUNICODE_STRING source
    )
{
    size_t copyChars = 0U;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    copyChars = (size_t)(source->Length / sizeof(WCHAR));
    if (copyChars >= (size_t)destinationChars) {
        copyChars = (size_t)destinationChars - 1U;
    }

    RtlCopyMemory(destination, source->Buffer, copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

static VOID
kswordArkCallbackEnumCopyAnsiPathToWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
{
    ULONG index = 0UL;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < destinationChars && index < sourceBytes; ++index) {
        if (source[index] == '\0') {
            break;
        }
        destination[index] = (WCHAR)source[index];
    }

    destination[index] = L'\0';
}

VOID
kswordArkCallbackEnumInitModuleCache(
    _Out_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    initialize the module cache structure. Note: The cache is used only within a single IOCTL enumeration
    cycle to avoid repeatedly querying SystemModuleInformation for every resolved callback address.

Arguments:

    ModuleCache - Output module cache.

Return Value:

    No return value.

--*/
{
    if (moduleCache == NULL) {
        return;
    }

    moduleCache->moduleInfo = NULL;
    moduleCache->moduleInfoBytes = 0UL;
}

VOID
kswordArkCallbackEnumFreeModuleCache(
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Release module cache. Note: This function only releases non-paged pool allocated
    for this enumeration path and clears the pointer to prevent subsequent misuse.

Arguments:

    ModuleCache: Input/output module cache.

Return Value:

    No return value.

--*/
{
    if (moduleCache == NULL) {
        return;
    }

    if (moduleCache->moduleInfo != NULL) {
        ExFreePool(moduleCache->moduleInfo);
        moduleCache->moduleInfo = NULL;
    }
    moduleCache->moduleInfoBytes = 0UL;
}

_Must_inspect_result_
NTSTATUS
kswordArkCallbackEnumEnsureModuleCache(
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Populate the system module cache on demand. Note: Private callback scanning frequently needs to check if candidate
    function addresses fall within loaded kernel modules; caching reduces the overhead of ZwQuerySystemInformation.

Arguments:

    ModuleCache: Input/output module cache.

Return Value:

    Returns STATUS_SUCCESS on success; returns the corresponding NTSTATUS on allocation or query failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;

    if (moduleCache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (moduleCache->moduleInfo != NULL) {
        return STATUS_SUCCESS;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }

    moduleCache->moduleInfo = (KswordArkCallbackModuleInformation*)kswordArkAllocateNonPaged(
        requiredBytes,
        KSWORD_ARK_CALLBACK_ENUM_TAG);
    if (moduleCache->moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    moduleCache->moduleInfoBytes = requiredBytes;

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        moduleCache->moduleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackEnumFreeModuleCache(moduleCache);
        return status;
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
kswordArkCallbackEnumResolveModuleByAddressCached(
    _Inout_opt_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 callbackAddress,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    )
/*++

Routine Description:

    Use the cached system module table to resolve the module owning an address. Note: This function does not dereference callback function
    addresses, only performs numeric range comparisons, making it suitable for filtering candidate addresses after private structure scanning.

Arguments:

    ModuleCache: Optional module cache; if NULL, use the original one-time query function.
    CallbackAddress - Input callback function address.
    modulePath: Output module path.
    ModulePathChars - Capacity of the module path buffer.
    ModuleBaseOut - Optional output module base address.
    ModuleSizeOut - Optional output module size.

Return Value:

    Returns STATUS_SUCCESS on a hit; returns STATUS_NOT_FOUND on a miss;
    returns the corresponding NTSTATUS if cache initialization fails.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG moduleIndex = 0UL;

    if (modulePath == NULL || modulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    modulePath[0] = L'\0';
    if (moduleBaseOut != NULL) {
        *moduleBaseOut = 0ULL;
    }
    if (moduleSizeOut != NULL) {
        *moduleSizeOut = 0UL;
    }
    if (callbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (moduleCache == NULL) {
        return kswordArkCallbackEnumResolveModuleByAddress(
            callbackAddress,
            modulePath,
            modulePathChars,
            moduleBaseOut,
            moduleSizeOut);
    }

    status = kswordArkCallbackEnumEnsureModuleCache(moduleCache);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleCache->moduleInfo->numberOfModules; ++moduleIndex) {
        const KswordArkCallbackModuleEntry* moduleEntry =
            &moduleCache->moduleInfo->modules[moduleIndex];
        const ULONG64 kModuleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
        const ULONG64 kModuleEnd = kModuleBase + (ULONG64)moduleEntry->imageSize;
        if (callbackAddress < kModuleBase || callbackAddress >= kModuleEnd) {
            continue;
        }

        if (moduleBaseOut != NULL) {
            *moduleBaseOut = kModuleBase;
        }
        if (moduleSizeOut != NULL) {
            *moduleSizeOut = moduleEntry->imageSize;
        }
        kswordArkCallbackEnumCopyAnsiPathToWide(
            modulePath,
            modulePathChars,
            moduleEntry->fullPathName,
            RTL_NUMBER_OF(moduleEntry->fullPathName));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

BOOLEAN
kswordArkCallbackEnumIsKernelModuleAddress(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 candidateAddress
    )
/*++

Routine Description:

    Check if the candidate address lies within any loaded kernel module. Note: Scanning private structure
    fields can produce multiple pointer candidates; this filter prioritizes retaining actual code addresses.

Arguments:

    ModuleCache - Module cache.
    CandidateAddress - Candidate address.

Return Value:

    Returns TRUE if within the module scope; otherwise returns FALSE.

--*/
{
    WCHAR modulePath[4];

    RtlZeroMemory(modulePath, sizeof(modulePath));
    return NT_SUCCESS(kswordArkCallbackEnumResolveModuleByAddressCached(
        moduleCache,
        candidateAddress,
        modulePath,
        RTL_NUMBER_OF(modulePath),
        NULL,
        NULL));
}

BOOLEAN
kswordArkCallbackEnumReadMemory(
    _In_ const VOID* sourceAddress,
    _Out_writes_bytes_(bytesToRead) VOID* destinationBuffer,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Read kernel memory with exception protection. Note: private callback arrays and linked lists lack a public
    synchronization contract, so all field reads must be short-path, bounded, and resilient to invalid addresses.

Arguments:

    SourceAddress - Input source address.
    DestinationBuffer: Output buffer.
    BytesToRead - Number of bytes to read.

Return Value:

    Returns TRUE on success; returns FALSE for invalid addresses, parameter errors, or exceptions.

--*/
{
    if (sourceAddress == NULL || destinationBuffer == NULL || bytesToRead == 0U) {
        return FALSE;
    }
    // Note: Most call sites are within spin locks (DISPATCH_LEVEL), where SEH cannot catch kernel page faults; therefore, the entire range must be
    // verified page-by-page for residency. Probing only the start and end would miss intermediate pages and short reads crossing page boundaries.
    if (!kswordArkKernelProbeRangeIsResident(sourceAddress, bytesToRead)) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(destinationBuffer, sourceAddress, bytesToRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(destinationBuffer, bytesToRead);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumReadUchar(
    _In_ ULONG64 address,
    _Out_ UCHAR* valueOut
    )
/*++

Routine Description:

    Read a UCHAR. Note: Used for machine code pattern matching; all accesses are protected by exception handling.

Arguments:

    Address - Input address.
    ValueOut - Output bytes.

Return Value:

    Returns TRUE on success, or FALSE on failure.

--*/
{
    UCHAR value = 0U;

    if (valueOut == NULL) {
        return FALSE;
    }
    if (!kswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)address, &value, sizeof(value))) {
        *valueOut = 0U;
        return FALSE;
    }
    *valueOut = value;
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumReadPointer(
    _In_ ULONG64 address,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Reads a value with pointer width. Note: Callback array slots, linked list fields, and object
    type fields are all read via this function to avoid dereferencing private addresses directly.

Arguments:

    Address - The address where the input pointer value resides.
    ValueOut - Pointer value read as output.

Return Value:

    Returns TRUE on success, or FALSE on failure.

--*/
{
    ULONG_PTR value = 0U;

    if (valueOut == NULL) {
        return FALSE;
    }
    if (!kswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)address, &value, sizeof(value))) {
        *valueOut = 0ULL;
        return FALSE;
    }
    *valueOut = (ULONG64)value;
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumReadUlong(
    _In_ ULONG64 address,
    _Out_ ULONG* valueOut
    )
/*++

Routine Description:

    Read the ULONG value. Note: Used to read diagnostic fields such
    as object callback operation masks and notify enable masks.

Arguments:

    Address - Input field address.
    ValueOut - Output ULONG.

Return Value:

    Returns TRUE on success, or FALSE on failure.

--*/
{
    ULONG value = 0UL;

    if (valueOut == NULL) {
        return FALSE;
    }
    if (!kswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)address, &value, sizeof(value))) {
        *valueOut = 0UL;
        return FALSE;
    }
    *valueOut = value;
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumReadListEntry(
    _In_ ULONG64 address,
    _Out_ LIST_ENTRY* listEntryOut
    )
/*++

Routine Description:

    Read LIST_ENTRY. Note: Registry and object callback list traversal
    only reads Flink/Blink without modifying the list content.

Arguments:

    Address - Input LIST_ENTRY address.
    ListEntryOut: Output list entry.

Return Value:

    Returns TRUE on success, or FALSE on failure.

--*/
{
    if (listEntryOut == NULL) {
        return FALSE;
    }
    return kswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)address,
        listEntryOut,
        sizeof(*listEntryOut));
}

static BOOLEAN
kswordArkCallbackEnumReadUnicodeString(
    _In_ ULONG64 address,
    _Out_ UNICODE_STRING* unicodeStringOut
    )
/*++

Routine Description:

    Read the UNICODE_STRING descriptor. Note: Only the descriptor itself is copied;
    the actual string buffer undergoes boundary checking again in the copy function.

Arguments:

    Address - Input UNICODE_STRING address.
    UnicodeStringOut - Output descriptor.

Return Value:

    Returns TRUE on success, or FALSE on failure.

--*/
{
    if (unicodeStringOut == NULL) {
        return FALSE;
    }
    return kswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)address,
        unicodeStringOut,
        sizeof(*unicodeStringOut));
}

static BOOLEAN
kswordArkCallbackEnumLooksLikeKernelPointer(
    _In_ ULONG64 candidateAddress
    )
/*++

Routine Description:

    Perform a fast shape check on the candidate kernel pointer. Note: This function only checks
    address range and alignment; actual code pointers require module table hit filtering.

Arguments:

    CandidateAddress - Candidate address.

Return Value:

    Returns TRUE if it looks like a kernel pointer; otherwise returns FALSE.

--*/
{
    if (candidateAddress == 0ULL) {
        return FALSE;
    }
    if (candidateAddress < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumPdbSourceIsProfile(
    _In_ ULONG source
    )
/*++

Routine Description:

    Checks whether one DynData field was supplied by the applied PDB callback
    profile. This keeps trusted callback rows tied to PDB sourced fields only,
    instead of treating unavailable or runtime-pattern values as trusted.

Arguments:

    Source - DynData source identifier stored next to one callback RVA/offset.

Return Value:

    TRUE when Source is KSW_DYN_FIELD_SOURCE_PDB_PROFILE; otherwise FALSE.

--*/
{
    return source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE;
}

static BOOLEAN
kswordArkCallbackEnumPdbOffsetAvailable(
    _In_ ULONG offset,
    _In_ ULONG source
    )
/*++

Routine Description:

    Validates a PDB callback structure offset before it is used to index into a
    private kernel structure. Processing rejects unavailable, non-PDB sourced,
    or excessively large offsets so the caller can fall back to existing
    heuristic scanning.

Arguments:

    Offset - Structure offset captured in KswDynState.CallbackOffsets.
    Source - Source tag captured in KswDynState.CallbackOffsetSources.

Return Value:

    TRUE when the offset is PDB-sourced and within the callback enum safety
    window; otherwise FALSE.

--*/
{
    if (!kswordArkCallbackEnumPdbSourceIsProfile(source)) {
        return FALSE;
    }
    if (offset == KSW_DYN_OFFSET_UNAVAILABLE) {
        return FALSE;
    }
    if (offset > KSWORD_ARK_CALLBACK_ENUM_MAX_PDB_STRUCT_OFFSET) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
kswordArkCallbackEnumCaptureDynDataProfile(
    _Out_ KswordArkCallbackEnumDyndataProfile* profileOut
    )
/*++

Routine Description:

    Captures the current DynData snapshot and extracts the callback PDB profile
    identity gate used by this file. Processing requires CallbackProfileActive,
    a present ntoskrnl identity, a non-zero image base, and a non-zero
    SizeOfImage before any RVA is allowed to become a VA.

Arguments:

    ProfileOut - Receives a zeroed profile wrapper and the copied DynData state.

Return Value:

    STATUS_SUCCESS when the callback profile identity is usable. A failure
    status means callers must keep the legacy pattern fallback behavior.

--*/
{
    KswordArkCallbackEnumDyndataProfile profile;

    if (profileOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&profile, sizeof(profile));
    kswordArkDynDataSnapshot(&profile.state);

    if (!profile.state.callbackProfileActive) {
        *profileOut = profile;
        return STATUS_NOT_SUPPORTED;
    }
    if (profile.state.ntoskrnl.present == 0UL ||
        profile.state.ntoskrnl.imageBase == 0ULL ||
        profile.state.ntoskrnl.sizeOfImage == 0UL) {
        *profileOut = profile;
        return STATUS_NOT_FOUND;
    }
    if (!kswordArkCallbackEnumLooksLikeKernelPointer(profile.state.ntoskrnl.imageBase)) {
        *profileOut = profile;
        return STATUS_ACCESS_VIOLATION;
    }

    profile.active = TRUE;
    profile.ntosImageBase = profile.state.ntoskrnl.imageBase;
    profile.ntosImageSize = profile.state.ntoskrnl.sizeOfImage;
    *profileOut = profile;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumPdbRvaToVa(
    _In_ const KswordArkCallbackEnumDyndataProfile* profile,
    _In_ ULONG globalRva,
    _In_ ULONG globalSource,
    _In_ SIZE_T probeBytes,
    _Out_ ULONG64* addressOut
    )
/*++

Routine Description:

    Converts one PDB callback global RVA to a kernel VA. Processing enforces
    the callback profile identity gate, PDB field source, rva < SizeOfImage,
    integer-overflow safety, kernel-address shape, and a small readable probe.

Arguments:

    Profile - Captured callback DynData profile wrapper.
    GlobalRva - RVA from KswDynState.CallbackGlobals.
    GlobalSource - Source tag from KswDynState.CallbackGlobalSources.
    ProbeBytes - Number of bytes to read as a basic VA readability check.
    AddressOut - Receives imageBase + GlobalRva on success.

Return Value:

    STATUS_SUCCESS when the RVA was converted and probed successfully. Any
    failure status tells the caller to use the existing private pattern path.

--*/
{
    UCHAR probeBuffer[sizeof(LIST_ENTRY)];
    ULONG64 address = 0ULL;

    if (addressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *addressOut = 0ULL;
    if (profile == NULL || !profile->active || !profile->state.callbackProfileActive) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkCallbackEnumPdbSourceIsProfile(globalSource)) {
        return STATUS_NOT_FOUND;
    }
    if (globalRva == 0UL || globalRva == KSW_DYN_OFFSET_UNAVAILABLE) {
        return STATUS_NOT_FOUND;
    }
    if (globalRva >= profile->ntosImageSize) {
        return STATUS_NOT_FOUND;
    }
    if (probeBytes > sizeof(probeBuffer)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (probeBytes != 0U && ((ULONG64)globalRva + (ULONG64)probeBytes) > (ULONG64)profile->ntosImageSize) {
        return STATUS_NOT_FOUND;
    }
    if (profile->ntosImageBase > (((ULONG64)~0ULL) - (ULONG64)globalRva)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    address = profile->ntosImageBase + (ULONG64)globalRva;
    if (!kswordArkCallbackEnumLooksLikeKernelPointer(address)) {
        return STATUS_ACCESS_VIOLATION;
    }
    if (probeBytes != 0U) {
        RtlZeroMemory(probeBuffer, sizeof(probeBuffer));
        if (!kswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)address, probeBuffer, probeBytes)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    *addressOut = address;
    return STATUS_SUCCESS;
}

static VOID
kswordArkCallbackEnumApplySourceContext(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext
    )
/*++

Routine Description:

    Applies source, trust, removal-behavior, and extra field flags to one
    callback enumeration row. Processing is intentionally additive for
    fieldFlags so existing row-specific fields remain intact.

Arguments:

    Entry - Callback enumeration row being populated.
    SourceContext - Optional traversal source metadata. NULL leaves the row as
        already initialized by the caller.

Return Value:

    No return value.

--*/
{
    if (entry == NULL || sourceContext == NULL) {
        return;
    }

    entry->source = sourceContext->source;
    entry->trustFlags = sourceContext->trustFlags;
    entry->removeBehavior = sourceContext->removeBehavior;
    entry->fieldFlags |= sourceContext->extraFieldFlags;
}

static ULONG64
kswordArkCallbackEnumResolveRelativeAddress(
    _In_ ULONG64 instructionAddress,
    _In_ ULONG displacementOffset
    )
/*++

Routine Description:

    Parse x64 RIP-relative/call relative addresses. Note: Compatible with SKT64
    implementation semantics; result is InstructionAddress + Offset + sizeof(INT32) + disp32.

Arguments:

    InstructionAddress: Starting address of the instruction.
    DisplacementOffset: offset of the disp32 value within the instruction.

Return Value:

    Returns the resolved absolute address on success; returns 0 on read failure.

--*/
{
    LONG displacement = 0L;

    if (instructionAddress == 0ULL) {
        return 0ULL;
    }
    if (!kswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)(instructionAddress + displacementOffset),
        &displacement,
        sizeof(displacement))) {
        return 0ULL;
    }

    return instructionAddress + (ULONG64)displacementOffset + sizeof(LONG) + (LONG64)displacement;
}

static PVOID
kswordArkCallbackEnumGetSystemRoutine(
    _In_z_ PCWSTR routineName
    )
/*++

Routine Description:

    Parse ntoskrnl exported routines. Note: Retrieve public exports via MmGetSystemRoutineAddress,
    then locate private global variables from the exported function code.

Arguments:

    RoutineName - Input exported routine name.

Return Value:

    Returns the routine address on success; returns NULL on failure.

--*/
{
    UNICODE_STRING routineNameString;

    RtlInitUnicodeString(&routineNameString, routineName);
    return MmGetSystemRoutineAddress(&routineNameString);
}

static BOOLEAN
kswordArkCallbackEnumFindCodePattern(
    _In_ ULONG64 startAddress,
    _In_ ULONG scanBytes,
    _In_reads_bytes_(patternBytes) const UCHAR* pattern,
    _In_reads_bytes_(patternBytes) const UCHAR* mask,
    _In_ ULONG patternBytes,
    _Out_ ULONG64* matchAddressOut
    )
/*++

Routine Description:

    Search for byte patterns within the specified code window. Note: Non-zero bytes in the mask indicate
    exact match requirements, while zero bytes act as wildcards; skip the current candidate if a read fails.

Arguments:

    StartAddress - Scan start address.
    ScanBytes - The maximum scan length.
    Pattern: Pattern byte array.
    Mask - Mask byte array.
    patternBytes - Pattern length.
    MatchAddressOut - Output hit address.

Return Value:

    Returns TRUE on match; FALSE on no match.

--*/
{
    ULONG offset = 0UL;
    ULONG patternIndex = 0UL;

    if (matchAddressOut == NULL) {
        return FALSE;
    }
    *matchAddressOut = 0ULL;
    if (startAddress == 0ULL || pattern == NULL || mask == NULL || patternBytes == 0UL || scanBytes < patternBytes) {
        return FALSE;
    }

    for (offset = 0UL; offset <= scanBytes - patternBytes; ++offset) {
        BOOLEAN matched = TRUE;
        for (patternIndex = 0UL; patternIndex < patternBytes; ++patternIndex) {
            UCHAR value = 0U;
            if (!kswordArkCallbackEnumReadUchar(startAddress + offset + patternIndex, &value)) {
                matched = FALSE;
                break;
            }
            if (mask[patternIndex] != 0U && value != pattern[patternIndex]) {
                matched = FALSE;
                break;
            }
        }
        if (matched) {
            *matchAddressOut = startAddress + offset;
            return TRUE;
        }
    }

    return FALSE;
}

_Must_inspect_result_
static NTSTATUS
kswordArkCallbackEnumResolveModuleByAddress(
    _In_ ULONG64 callbackAddress,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    )
/*++

Routine Description:

    Resolve the owning kernel module based on the callback address. Note: The implementation only reads the system module
    list without dereferencing the callback address itself, making it suitable for diagnostic read-only enumeration paths.

Arguments:

    CallbackAddress - Input callback function address.
    modulePath: Output module path.
    ModulePathChars - Capacity of the module path buffer.
    ModuleBaseOut - Optional output module base address.
    ModuleSizeOut - Optional output module size.

Return Value:

    Returns STATUS_SUCCESS on successful parsing; returns STATUS_NOT_FOUND
    on miss; returns the corresponding NTSTATUS on query failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    ULONG moduleIndex = 0UL;
    KswordArkCallbackModuleInformation* moduleInfo = NULL;

    if (modulePath == NULL || modulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    modulePath[0] = L'\0';
    if (moduleBaseOut != NULL) {
        *moduleBaseOut = 0ULL;
    }
    if (moduleSizeOut != NULL) {
        *moduleSizeOut = 0UL;
    }
    if (callbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }

    moduleInfo = (KswordArkCallbackModuleInformation*)kswordArkAllocateNonPaged(
        requiredBytes,
        KSWORD_ARK_CALLBACK_ENUM_TAG);
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, requiredBytes, &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePool(moduleInfo);
        return status;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswordArkCallbackModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const ULONG64 kModuleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
        const ULONG64 kModuleEnd = kModuleBase + (ULONG64)moduleEntry->imageSize;
        if (callbackAddress < kModuleBase || callbackAddress >= kModuleEnd) {
            continue;
        }

        if (moduleBaseOut != NULL) {
            *moduleBaseOut = kModuleBase;
        }
        if (moduleSizeOut != NULL) {
            *moduleSizeOut = moduleEntry->imageSize;
        }
        kswordArkCallbackEnumCopyAnsiPathToWide(
            modulePath,
            modulePathChars,
            moduleEntry->fullPathName,
            RTL_NUMBER_OF(moduleEntry->fullPathName));
        ExFreePool(moduleInfo);
        return STATUS_SUCCESS;
    }

    ExFreePool(moduleInfo);
    return STATUS_NOT_FOUND;
}

KSWORD_ARK_CALLBACK_ENUM_ENTRY*
kswordArkCallbackEnumReserveEntry(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG entryIndex = 0UL;

    if (builder == NULL ||
        (builder->entryCapacity != 0UL && builder->entries == NULL)) {
        return NULL;
    }

    kswordArkCallbackEnumSnapshotCommitPending(builder);

    /* Note: Record the full sequence number first; rows before pagination must still be fully enumerated to ensure totalCount stability. */
    entryIndex = builder->totalCount;
    builder->totalCount += 1UL;
    if (entryIndex < builder->startIndex) {
        RtlZeroMemory(&builder->scratchEntry, sizeof(builder->scratchEntry));
        builder->scratchEntry.size = sizeof(builder->scratchEntry);
        builder->pendingEntry = &builder->scratchEntry;
        return &builder->scratchEntry;
    }

    /* Note: After the current page is full, continue using the scratch row to complete the read-only traversal and total count. */
    if (builder->returnedCount >= builder->entryCapacity) {
        builder->flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED;
        RtlZeroMemory(&builder->scratchEntry, sizeof(builder->scratchEntry));
        builder->scratchEntry.size = sizeof(builder->scratchEntry);
        builder->pendingEntry = &builder->scratchEntry;
        return &builder->scratchEntry;
    }

    entry = &builder->entries[builder->returnedCount];
    builder->returnedCount += 1UL;
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    builder->pendingEntry = entry;
    return entry;
}

static VOID
kswordArkCallbackEnumFinalizeModule(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || entry->callbackAddress == 0ULL) {
        return;
    }

    status = kswordArkCallbackEnumResolveModuleByAddress(
        entry->callbackAddress,
        entry->modulePath,
        RTL_NUMBER_OF(entry->modulePath),
        &entry->moduleBase,
        &entry->moduleSize);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
        entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_WITHIN_MODULE;
    }
    else {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_MISSING;
        entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_MODULE_UNRESOLVED;
    }
}

VOID
kswordArkCallbackEnumFinalizeModuleCached(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry
    )
/*++

Routine Description:

    Complete the module field of the callback record using the module cache. Note: Private scanning
    generates a large number of records; the cached version reduces the number of system module queries.

Arguments:

    ModuleCache - Module cache.
    Entry - Input/output callback enumeration entry.

Return Value:

    No return value.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || entry->callbackAddress == 0ULL) {
        return;
    }

    status = kswordArkCallbackEnumResolveModuleByAddressCached(
        moduleCache,
        entry->callbackAddress,
        entry->modulePath,
        RTL_NUMBER_OF(entry->modulePath),
        &entry->moduleBase,
        &entry->moduleSize);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
        entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_WITHIN_MODULE;
    }
    else {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_MISSING;
        entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_MODULE_UNRESOLVED;
    }
}

static VOID
kswordArkCallbackEnumCopyUnicodeSafe(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_ const UNICODE_STRING* source
    )
/*++

Routine Description:

    Copy UNICODE_STRING from private structures with exception protection. Note: Registry and object
    callback altitudes come from a private list; limit max length and validate buffer addresses during copy.

Arguments:

    Destination: Output fixed-width character buffer.
    DestinationChars - Output buffer capacity.
    Source: input UNICODE_STRING descriptor.

Return Value:

    No return value.

--*/
{
    USHORT copyBytes = 0U;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }
    if (source->Length > source->MaximumLength && source->MaximumLength != 0U) {
        return;
    }
    if (source->Length > (USHORT)((destinationChars - 1UL) * sizeof(WCHAR))) {
        copyBytes = (USHORT)((destinationChars - 1UL) * sizeof(WCHAR));
    }
    else {
        copyBytes = source->Length;
    }
    if (copyBytes == 0U) {
        return;
    }
    if (!MmIsAddressValid(source->Buffer) ||
        !MmIsAddressValid((PUCHAR)source->Buffer + copyBytes - sizeof(WCHAR))) {
        return;
    }

    __try {
        RtlCopyMemory(destination, source->Buffer, copyBytes);
        destination[copyBytes / sizeof(WCHAR)] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        destination[0] = L'\0';
    }
}

static VOID
kswordArkCallbackEnumAddSelfRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ ULONG registeredMask,
    _In_ ULONG requiredMask,
    _In_ ULONG callbackClass,
    _In_ ULONG registrationType,
    _In_ ULONG operationMask,
    _In_ ULONG objectTypeMask,
    _In_ ULONG64 callbackAddress,
    _In_ ULONG64 contextAddress,
    _In_ ULONG64 registrationAddress,
    _In_opt_z_ PCWSTR nameText,
    _In_opt_z_ PCWSTR altitudeText,
    _In_opt_z_ PCWSTR detailText
    )
/*++

Routine Description:

    Write to the callback record registered by Ksword itself. Note: These addresses come from this driver compilation
    unit, so the current Ksword runtime status can be accurately displayed without scanning system private lists.

Arguments:

    Builder - Enum response builder.
    RegisteredMask: The bitmap of registered callbacks in the runtime.
    RequiredMask - Required bits for the current record.
    CallbackClass - Callback category.
    RegistrationType - The specific registration API type.
    OperationMask - Callback operation mask.
    ObjectTypeMask: The object type mask.
    CallbackAddress - Address of the callback function.
    ContextAddress - Address of the callback context.
    RegistrationAddress: cookie or registration handle.
    NameText - display name.
    AltitudeText - optional altitude text.
    DetailText - The detailed text.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = callbackClass;
    entry->registrationType = registrationType;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF;
    entry->status = ((registeredMask & requiredMask) != 0UL)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD;
    entry->operationMask = operationMask;
    entry->objectTypeMask = objectTypeMask;
    if ((objectTypeMask & KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP) != 0UL) {
        entry->registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = callbackAddress;
    entry->contextAddress = contextAddress;
    entry->registrationAddress = registrationAddress;

    if (callbackAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS;
    }
    if (contextAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    }
    if (registrationAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    if (operationMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (objectTypeMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK;
    }
    if (registrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    if (nameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), nameText);
    }
    if (altitudeText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        kswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), altitudeText);
    }

    kswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), detailText);
    kswordArkCallbackEnumFinalizeModule(entry);
}

VOID
kswordArkCallbackEnumAddUnsupportedRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ ULONG callbackClass,
    _In_opt_z_ PCWSTR nameText,
    _In_opt_z_ PCWSTR detailText
    )
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = callbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->lastStatus = STATUS_NOT_SUPPORTED;
    if (nameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), nameText);
    }
    kswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), detailText);
}

static VOID
kswordArkCallbackEnumAddSelfCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    enumerate callbacks registered by KswordARK itself into the system. Note: runtime holds the registration
    bitmap, registry cookie, and Ob registration handle, so these lines accurately reflect the driver state.

Arguments:

    Builder - Enum response builder.

Return Value:

    No return value.

--*/
{
    ULONG registeredMask = 0UL;
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    const ULONG64 kContextAddress = (ULONG64)(ULONG_PTR)runtime;

    if (runtime != NULL) {
        registeredMask = runtime->registeredCallbacksMask;
    }

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_REG_OP_ALL,
        0UL,
        (ULONG64)(ULONG_PTR)kswordArkRegistryCallback,
        kContextAddress,
        (runtime != NULL) ? (ULONG64)runtime->registryCookie.QuadPart : 0ULL,
        L"KswordArkRegistryCallback",
        L"385201.5141",
        L"CmRegisterCallbackEx 注册表回调；外部 CmCallbackListHead 私有链表由“私有结构枚举”阶段另行展示。");

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_PROCESS,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX,
        KSWORD_ARK_PROCESS_OP_CREATE,
        0UL,
        (ULONG64)(ULONG_PTR)kswordArkProcessCreateNotifyEx,
        kContextAddress,
        0ULL,
        L"KswordArkProcessCreateNotifyEx",
        NULL,
        L"PsSetCreateProcessNotifyRoutineEx 进程创建回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_THREAD,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
        0UL,
        (ULONG64)(ULONG_PTR)kswordArkThreadCreateNotify,
        kContextAddress,
        0ULL,
        L"KswordArkThreadCreateNotify",
        NULL,
        L"PsSetCreateThreadNotifyRoutine 线程创建/退出回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_IMAGE,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_IMAGE_OP_LOAD,
        0UL,
        (ULONG64)(ULONG_PTR)kswordArkLoadImageNotify,
        kContextAddress,
        0ULL,
        L"KswordArkLoadImageNotify",
        NULL,
        L"PsSetLoadImageNotifyRoutine 镜像加载回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_OBJECT,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_OBJECT_OP_HANDLE_CREATE | KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE,
        KSWORD_ARK_OBJECT_OP_TYPE_PROCESS | KSWORD_ARK_OBJECT_OP_TYPE_THREAD,
        (ULONG64)(ULONG_PTR)kswordArkObjectPreOperation,
        kContextAddress,
        (runtime != NULL) ? (ULONG64)(ULONG_PTR)runtime->obRegistrationHandle : 0ULL,
        L"KswordArkObjectPreOperation",
        L"385201.5142",
        L"ObRegisterCallbacks 对象句柄回调；仅覆盖 Process/Thread Handle Create/Duplicate。");

    kswordArkCallbackEnumAddSelfRow(
        builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_MINIFILTER_OP_ALL,
        0UL,
        (ULONG64)(ULONG_PTR)kswordArkMinifilterPreOperation,
        kContextAddress,
        (runtime != NULL) ? (ULONG64)(ULONG_PTR)runtime->miniFilterHandle : 0ULL,
        L"KswordArkMinifilterPreOperation",
        L"385210",
        L"FltRegisterFilter 文件系统微过滤器回调；同时服务文件监控和自定义回调规则。");

    kswordArkCallbackExtendedAddSelfBugcheckCallbacks(builder);
}

static VOID
kswordArkCallbackEnumAddLocateRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ ULONG callbackClass,
    _In_opt_z_ PCWSTR nameText,
    _In_ ULONG64 locatedAddress,
    _In_ NTSTATUS locateStatus,
    _In_opt_z_ PCWSTR detailText
    )
/*++

Routine Description:

    Write a private global location diagnostic line. Note: The location line helps R3 determine if SKT64-style
    features match on the current kernel version and displays the address of the global array or linked list head.

Arguments:

    Builder - Enum response builder.
    CallbackClass - Callback category.
    NameText - display name.
    LocatedAddress - The located global address.
    LocateStatus - Locate status.
    DetailText - The detailed text.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = callbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
    entry->status = NT_SUCCESS(locateStatus)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED;
    entry->lastStatus = locateStatus;
    entry->registrationAddress = locatedAddress;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    if (locatedAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), nameText);
    kswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), detailText);
}

static NTSTATUS
kswordArkCallbackEnumLocatePspCreateProcessNotifyRoutine(
    _Out_ ULONG64* arrayAddressOut
    )
/*++

Routine Description:

    Locates the private PspCreateProcessNotifyRoutine array. Note: Implementation reuses the
    SKT64 approach: first locate the internal PspSet* call via PsSetCreateProcessNotifyRoutine,
    then search for the 4C 8D rip-relative array address within the internal function.

Arguments:

    ArrayAddressOut - Output address of the notify array.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"PsSetCreateProcessNotifyRoutine");
    ULONG64 innerRoutine = 0ULL;
    ULONG64 matchAddress = 0ULL;
    ULONG64 arrayAddress = 0ULL;
    static const UCHAR kCallPattern[] = { 0xE8U, 0x00U, 0x00U, 0x00U, 0x00U, 0x48U };
    static const UCHAR kCallMask[] = { 1U, 0U, 0U, 0U, 0U, 1U };
    static const UCHAR kLeaPattern[] = { 0x4CU, 0x8DU };
    static const UCHAR kLeaMask[] = { 1U, 1U };

    if (arrayAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *arrayAddressOut = 0ULL;
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kCallPattern,
        kCallMask,
        sizeof(kCallPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    innerRoutine = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 1UL);
    if (innerRoutine == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)innerRoutine)) {
        return STATUS_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        innerRoutine,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kLeaPattern,
        kLeaMask,
        sizeof(kLeaPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    arrayAddress = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 3UL);
    if (arrayAddress == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)arrayAddress)) {
        return STATUS_NOT_FOUND;
    }

    *arrayAddressOut = arrayAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumLocatePspCreateThreadNotifyRoutine(
    _Out_ ULONG64* arrayAddressOut
    )
/*++

Routine Description:

    Locate the private PspCreateThreadNotifyRoutine array. Note: SKT64 uses a
    48 8D 0D rip-relative reference within PsRemoveCreateThreadNotifyRoutine.

Arguments:

    ArrayAddressOut - Output address of the notify array.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"PsRemoveCreateThreadNotifyRoutine");
    ULONG64 matchAddress = 0ULL;
    ULONG64 arrayAddress = 0ULL;
    static const UCHAR kLeaPattern[] = { 0x48U, 0x8DU, 0x0DU };
    static const UCHAR kLeaMask[] = { 1U, 1U, 1U };

    if (arrayAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *arrayAddressOut = 0ULL;
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kLeaPattern,
        kLeaMask,
        sizeof(kLeaPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    arrayAddress = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 3UL);
    if (arrayAddress == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)arrayAddress)) {
        return STATUS_NOT_FOUND;
    }

    *arrayAddressOut = arrayAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumLocatePspLoadImageNotifyRoutine(
    _Out_ ULONG64* arrayAddressOut
    )
/*++

Routine Description:

    Locate the private PspLoadImageNotifyRoutine array. Note: Prefer PsSetLoadImageNotifyRoutineEx;
    if the export is missing, fall back to PsSetLoadImageNotifyRoutine.

Arguments:

    ArrayAddressOut - Output address of the notify array.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"PsSetLoadImageNotifyRoutineEx");
    ULONG64 matchAddress = 0ULL;
    ULONG64 arrayAddress = 0ULL;
    static const UCHAR kLeaPattern[] = { 0x48U, 0x8DU, 0x0DU };
    static const UCHAR kLeaMask[] = { 1U, 1U, 1U };

    if (arrayAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *arrayAddressOut = 0ULL;
    if (exportAddress == 0ULL) {
        exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"PsSetLoadImageNotifyRoutine");
    }
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kLeaPattern,
        kLeaMask,
        sizeof(kLeaPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    arrayAddress = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 3UL);
    if (arrayAddress == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)arrayAddress)) {
        return STATUS_NOT_FOUND;
    }

    *arrayAddressOut = arrayAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumLocatePspNotifyEnableMask(
    _Out_ ULONG64* maskAddressOut
    )
/*++

Routine Description:

    Locate the private global PspNotifyEnableMask. Note: This value is not a callback
    item itself, but it helps determine whether the Psp notify path is enabled.

Arguments:

    MaskAddressOut - Output mask address.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"PsSetLoadImageNotifyRoutineEx");
    ULONG64 matchAddress = 0ULL;
    ULONG64 maskAddress = 0ULL;
    static const UCHAR kMaskPattern[] = { 0x8BU, 0x05U, 0x00U, 0x00U, 0x00U, 0x00U, 0xA8U };
    static const UCHAR kMaskMask[] = { 1U, 1U, 0U, 0U, 0U, 0U, 1U };

    if (maskAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *maskAddressOut = 0ULL;
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kMaskPattern,
        kMaskMask,
        sizeof(kMaskPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    maskAddress = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 2UL);
    if (maskAddress == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)maskAddress)) {
        return STATUS_NOT_FOUND;
    }

    *maskAddressOut = maskAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumLocateCmCallbackListHead(
    _Out_ ULONG64* listHeadOut
    )
/*++

Routine Description:

    Locate the private CmCallbackListHead list head. Note: SKT64 finds the
    48 8D 0D rip-relative list head reference within CmUnRegisterCallback.

Arguments:

    ListHeadOut - The address of the output list head.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)kswordArkCallbackEnumGetSystemRoutine(L"CmUnRegisterCallback");
    ULONG64 matchAddress = 0ULL;
    ULONG64 listHead = 0ULL;
    static const UCHAR kLeaPattern[] = { 0x48U, 0x8DU, 0x0DU };
    static const UCHAR kLeaMask[] = { 1U, 1U, 1U };

    if (listHeadOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *listHeadOut = 0ULL;
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        kLeaPattern,
        kLeaMask,
        sizeof(kLeaPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    listHead = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 3UL);
    if (listHead == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)listHead)) {
        return STATUS_NOT_FOUND;
    }

    *listHeadOut = listHead;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCallbackEnumLocateObpCallPreOperationCallbacks(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _Out_ ULONG64* routineAddressOut
    )
/*++

Routine Description:

    Locate internal routines within ObpCallPreOperationCallbacks. Note: SKT64 matches call sites from
    ntoskrnl code; Ksword reuses this pattern and restricts scanning to the kernel module image range.

Arguments:

    ModuleCache - Module cache.
    RoutineAddressOut - Outputs the internal routine address.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 ntBase = 0ULL;
    ULONG ntSize = 0UL;
    ULONG64 matchAddress = 0ULL;
    ULONG64 routineAddress = 0ULL;
    static const UCHAR kPattern[] = {
        0xE8U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x85U, 0xC0U, 0x78U, 0x00U,
        0x45U, 0x84U, 0x00U, 0x75U, 0x00U, 0x8BU
    };
    static const UCHAR kMask[] = {
        1U, 0U, 0U, 0U, 0U,
        1U, 1U, 1U, 0U,
        1U, 1U, 0U, 1U, 0U, 1U
    };

    if (routineAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *routineAddressOut = 0ULL;

    status = kswordArkCallbackEnumEnsureModuleCache(moduleCache);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (moduleCache->moduleInfo == NULL || moduleCache->moduleInfo->numberOfModules == 0UL) {
        return STATUS_NOT_FOUND;
    }

    ntBase = (ULONG64)(ULONG_PTR)moduleCache->moduleInfo->modules[0].imageBase;
    ntSize = moduleCache->moduleInfo->modules[0].imageSize;
    if (ntBase == 0ULL || ntSize < sizeof(kPattern)) {
        return STATUS_NOT_FOUND;
    }

    if (!kswordArkCallbackEnumFindCodePattern(ntBase, ntSize, kPattern, kMask, sizeof(kPattern), &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    routineAddress = kswordArkCallbackEnumResolveRelativeAddress(matchAddress, 1UL);
    if (routineAddress == 0ULL || !kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, routineAddress)) {
        return STATUS_NOT_FOUND;
    }

    *routineAddressOut = routineAddress;
    return STATUS_SUCCESS;
}

static VOID
kswordArkCallbackEnumClassifyNotifyRegistration(
    _In_ ULONG callbackClass,
    _In_ ULONG64 contextAddress,
    _Out_ ULONG* registrationTypeOut,
    _Outptr_ PCWSTR* registrationNameOut
    )
/*++

Routine Description:

    Identifies registration APIs for process, thread, and image notifications. Note: These Psp
    arrays encode Legacy/Ex variants in EX_CALLBACK_ROUTINE_BLOCK.Context; unknown values are
    conservatively preserved as Unknown to avoid misrepresenting private layouts as confirmed types.

Arguments:

    CallbackClass - Callback category.
    ContextAddress: The original Context value of the routine block.
    RegistrationTypeOut - Output shared protocol registration type.
    RegistrationNameOut - output name suffix.

Return Value:

    No return value.

--*/
{
    if (registrationTypeOut == NULL || registrationNameOut == NULL) {
        return;
    }

    *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN;
    *registrationNameOut = L"Unknown";

    if (callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS) {
        switch (contextAddress) {
        case 0ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_LEGACY;
            *registrationNameOut = L"Legacy";
            break;

        case 2ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX;
            *registrationNameOut = L"Ex";
            break;

        case 6ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX2;
            *registrationNameOut = L"Ex2";
            break;

        default:
            break;
        }
    }
    else if (callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD) {
        switch (contextAddress) {
        case 0ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_LEGACY;
            *registrationNameOut = L"Legacy";
            break;

        case 1ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_NON_SYSTEM;
            *registrationNameOut = L"Ex/NonSystem";
            break;

        case 2ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_SUBSYSTEMS;
            *registrationNameOut = L"Ex/Subsystems";
            break;

        default:
            break;
        }
    }
    else if (callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE) {
        switch (contextAddress) {
        case 0ULL:
            *registrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_LEGACY_OR_EX_DEFAULT;
            *registrationNameOut = L"Legacy/ExDefault";
            break;

        case 1ULL:
            *registrationTypeOut =
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_EX_CONFLICTING_ARCHITECTURE;
            *registrationNameOut = L"Ex/ConflictingArchitecture";
            break;

        default:
            break;
        }
    }
}

static VOID
kswordArkCallbackEnumAddNotifyArrayEntry(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG callbackClass,
    _In_ ULONG operationMask,
    _In_ ULONG slotIndex,
    _In_ ULONG64 slotAddress,
    _In_ ULONG64 fastRefValue,
    _In_ ULONG64 routineBlock,
    _In_ ULONG64 functionAddress,
    _In_ ULONG64 contextAddress,
    _In_opt_z_ PCWSTR namePrefix,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext,
    _In_ ULONG sourceRva
    )
/*++

Routine Description:

    Write a Psp notify array entry. Note: The array slot stores an EX_FAST_REF; the lower 4 bits are the reference
    count. Clearing the lower bits yields the EX_CALLBACK_ROUTINE_BLOCK, from which Function and Context can be read.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    CallbackClass - Callback category.
    OperationMask - Operation mask.
    SlotIndex - array slot index.
    SlotAddress - Array slot address.
    FastRefValue - Original EX_FAST_REF value.
    RoutineBlock: decoded routine block address.
    FunctionAddress - Callback function address.
    ContextAddress - Address of the callback context.
    NamePrefix: Line name prefix.
    SourceContext: optional source metadata; the PDB path uses it to mark trusted/source/remove.
    SourceRva: PDB global RVA; pass 0 if no PDB path is provided, used only for detail diagnostics.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN;
    PCWSTR registrationName = L"Unknown";

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = callbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = operationMask;
    kswordArkCallbackEnumClassifyNotifyRegistration(
        callbackClass,
        contextAddress,
        &registrationType,
        &registrationName);
    entry->registrationType = registrationType;
    if (registrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = functionAddress;
    entry->contextAddress = contextAddress;
    entry->registrationAddress = slotAddress;
    kswordArkCallbackEnumApplySourceContext(entry, sourceContext);
    if (sourceContext != NULL &&
        (sourceContext->extraFieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE) != 0UL) {
        entry->rawStorageValue = fastRefValue;
    }
    if (sourceContext == NULL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    if (callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS ||
        callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD ||
        callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE) {
        (VOID)RtlStringCbPrintfW(
            entry->name,
            sizeof(entry->name),
            L"%ws/%ws[%lu]",
            (namePrefix != NULL) ? namePrefix : L"PspNotify",
            registrationName,
            (unsigned long)slotIndex);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->name,
            sizeof(entry->name),
            L"%ws[%lu]",
            (namePrefix != NULL) ? namePrefix : L"PspNotify",
            (unsigned long)slotIndex);
    }
    if (sourceContext != NULL && sourceContext->source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；RegistrationType=%ws，RVA=0x%08lX，slot=0x%p，EX_FAST_REF=0x%llX，RoutineBlock=0x%p，Function=0x%p，Context=0x%p。",
            (sourceContext->detailPrefix != NULL) ? sourceContext->detailPrefix : L"PDB callback profile trusted notify array",
            registrationName,
            (unsigned long)sourceRva,
            (PVOID)(ULONG_PTR)slotAddress,
            fastRefValue,
            (PVOID)(ULONG_PTR)routineBlock,
            (PVOID)(ULONG_PTR)functionAddress,
            (PVOID)(ULONG_PTR)contextAddress);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"Psp notify 私有数组项；RegistrationType=%ws，fallback=pattern scan，slot=0x%p，EX_FAST_REF=0x%llX，RoutineBlock=0x%p，Function=0x%p，Context=0x%p。",
            registrationName,
            (PVOID)(ULONG_PTR)slotAddress,
            fastRefValue,
            (PVOID)(ULONG_PTR)routineBlock,
            (PVOID)(ULONG_PTR)functionAddress,
            (PVOID)(ULONG_PTR)contextAddress);
    }
    kswordArkCallbackEnumFinalizeModuleCached(moduleCache, entry);
}

static ULONG
kswordArkCallbackEnumAddNotifyArray(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG callbackClass,
    _In_ ULONG operationMask,
    _In_ ULONG64 arrayAddress,
    _In_opt_z_ PCWSTR namePrefix,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext,
    _In_ ULONG sourceRva
    )
/*++

Routine Description:

    Traverse the Psp notify private array. Note: This function only reads the EX_FAST_REF array, does not call removal
    APIs, and does not rewrite any slots; each candidate function must hit the kernel module table to be displayed.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    CallbackClass - Callback category.
    OperationMask - Operation mask.
    ArrayAddress: Private array address.
    NamePrefix: Line name prefix.
    SourceContext - optional source metadata; NULL indicates retaining the old pattern fallback marker.
    SourceRva: PDB global RVA; pass 0 if no PDB path is provided, used only for detail diagnostics.

Return Value:

    Return the count of enumerated valid callbacks.

--*/
{
    ULONG slotIndex = 0UL;
    ULONG addedCount = 0UL;

    if (arrayAddress == 0ULL) {
        return 0UL;
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_CALLBACK_ENUM_NOTIFY_SLOT_COUNT; ++slotIndex) {
        ULONG64 slotAddress = arrayAddress + ((ULONG64)slotIndex * sizeof(ULONG_PTR));
        ULONG64 fastRefValue = 0ULL;
        ULONG64 routineBlock = 0ULL;
        ULONG64 functionAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (!kswordArkCallbackEnumReadPointer(slotAddress, &fastRefValue)) {
            continue;
        }
        if (fastRefValue == 0ULL) {
            continue;
        }

        routineBlock = fastRefValue & (ULONG64)KSWORD_ARK_CALLBACK_ENUM_FAST_REF_MASK;
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(routineBlock)) {
            continue;
        }
        if (!kswordArkCallbackEnumReadPointer(routineBlock + sizeof(ULONG_PTR), &functionAddress)) {
            continue;
        }
        if (!kswordArkCallbackEnumReadPointer(routineBlock + (2ULL * sizeof(ULONG_PTR)), &contextAddress)) {
            contextAddress = 0ULL;
        }
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(functionAddress)) {
            continue;
        }
        if (!kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, functionAddress)) {
            continue;
        }

        kswordArkCallbackEnumAddNotifyArrayEntry(
            builder,
            moduleCache,
            callbackClass,
            operationMask,
            slotIndex,
            slotAddress,
            fastRefValue,
            routineBlock,
            functionAddress,
            contextAddress,
            namePrefix,
            sourceContext,
            sourceRva);
        addedCount += 1UL;
    }

    return addedCount;
}

static VOID
kswordArkCallbackEnumAddRegistryEntry(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG entryIndex,
    _In_ ULONG64 entryAddress,
    _In_ ULONG64 functionAddress,
    _In_ ULONG64 contextAddress,
    _In_ const UNICODE_STRING* altitudeString,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext,
    _In_ ULONG sourceRva
    )
/*++

Routine Description:

    Write a Cm registry callback list entry. Note: private structures drift across Windows
    versions, so this function only writes Function candidates verified by the module table.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    EntryIndex - Linked list index.
    EntryAddress - address of the linked list node.
    FunctionAddress - Callback function address.
    ContextAddress - Address of the callback context.
    AltitudeString - Optional altitude descriptor.
    SourceContext - optional source metadata; used to mark trusted/source via the PDB path.
    SourceRva - CmCallbackListHead PDB RVA; pass 0 if not a PDB path, used for detail diagnostics only.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = KSWORD_ARK_REG_OP_ALL;
    entry->callbackAddress = functionAddress;
    entry->contextAddress = contextAddress;
    entry->registrationAddress = entryAddress;
    kswordArkCallbackEnumApplySourceContext(entry, sourceContext);
    if (sourceContext == NULL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"CmCallback[%lu]",
        (unsigned long)entryIndex);
    if (altitudeString != NULL) {
        kswordArkCallbackEnumCopyUnicodeSafe(
            entry->altitude,
            RTL_NUMBER_OF(entry->altitude),
            altitudeString);
        if (entry->altitude[0] != L'\0') {
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        }
    }
    if (sourceContext != NULL && sourceContext->source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；CmCallbackListHead RVA=0x%08lX，Entry=0x%p，Function=0x%p，Context=0x%p；cookie/字段恢复未标记 verified remove。",
            (sourceContext->detailPrefix != NULL) ? sourceContext->detailPrefix : L"PDB callback profile trusted registry list",
            (unsigned long)sourceRva,
            (PVOID)(ULONG_PTR)entryAddress,
            (PVOID)(ULONG_PTR)functionAddress,
            (PVOID)(ULONG_PTR)contextAddress);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"CmCallbackListHead 私有链表项；fallback=pattern scan，Entry=0x%p，Function=0x%p，Context=0x%p。",
            (PVOID)(ULONG_PTR)entryAddress,
            (PVOID)(ULONG_PTR)functionAddress,
            (PVOID)(ULONG_PTR)contextAddress);
    }
    kswordArkCallbackEnumFinalizeModuleCached(moduleCache, entry);
}

static BOOLEAN
kswordArkCallbackEnumFindRegistryFields(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 entryAddress,
    _Out_ ULONG64* functionAddressOut,
    _Out_ ULONG64* contextAddressOut,
    _Out_ UNICODE_STRING* altitudeStringOut
    )
/*++

Routine Description:

    Heuristically identify the Function, Context, and Altitude fields from the Cm callback private node. Note:
    Prefer pointers that can be resolved to kernel modules as function addresses,
    then search for context and altitude descriptors in adjacent fields.

Arguments:

    ModuleCache - Module cache.
    EntryAddress - address of the linked list node.
    FunctionAddressOut: Output function address.
    ContextAddressOut - Output context address.
    AltitudeStringOut - Outputs the altitude descriptor.

Return Value:

    Return TRUE if the function address is successfully identified; otherwise return FALSE.

--*/
{
    LONG offset = 0L;
    ULONG64 functionAddress = 0ULL;
    ULONG64 contextAddress = 0ULL;
    UNICODE_STRING altitudeString;

    RtlZeroMemory(&altitudeString, sizeof(altitudeString));
    if (functionAddressOut == NULL || contextAddressOut == NULL || altitudeStringOut == NULL) {
        return FALSE;
    }
    *functionAddressOut = 0ULL;
    *contextAddressOut = 0ULL;
    RtlZeroMemory(altitudeStringOut, sizeof(*altitudeStringOut));

    for (offset = 0x10L; offset <= 0x100L; offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 candidate = 0ULL;
        if (!kswordArkCallbackEnumReadPointer(entryAddress + (ULONG64)offset, &candidate)) {
            continue;
        }
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(candidate)) {
            continue;
        }
        if (!kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, candidate)) {
            continue;
        }

        functionAddress = candidate;
        if (offset >= (LONG)sizeof(ULONG_PTR)) {
            (VOID)kswordArkCallbackEnumReadPointer(
                entryAddress + (ULONG64)(offset - (LONG)sizeof(ULONG_PTR)),
                &contextAddress);
        }
        if (contextAddress == 0ULL) {
            (VOID)kswordArkCallbackEnumReadPointer(
                entryAddress + (ULONG64)(offset + (LONG)sizeof(ULONG_PTR)),
                &contextAddress);
        }
        break;
    }

    if (functionAddress == 0ULL) {
        return FALSE;
    }

    for (offset = 0x10L; offset <= 0x120L; offset += (LONG)sizeof(USHORT)) {
        UNICODE_STRING candidateString;
        RtlZeroMemory(&candidateString, sizeof(candidateString));
        if (!kswordArkCallbackEnumReadUnicodeString(entryAddress + (ULONG64)offset, &candidateString)) {
            continue;
        }
        if (candidateString.Buffer == NULL ||
            candidateString.Length == 0U ||
            candidateString.Length > 128U ||
            candidateString.MaximumLength < candidateString.Length ||
            (candidateString.Length % sizeof(WCHAR)) != 0U) {
            continue;
        }
        if (!MmIsAddressValid(candidateString.Buffer)) {
            continue;
        }

        altitudeString = candidateString;
        break;
    }

    *functionAddressOut = functionAddress;
    *contextAddressOut = contextAddress;
    *altitudeStringOut = altitudeString;
    return TRUE;
}

static ULONG
kswordArkCallbackEnumAddRegistryList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 listHeadAddress,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext,
    _In_ ULONG sourceRva
    )
/*++

Routine Description:

    Traverse the private CmCallbackListHead list. Note: The traversal sets a maximum node count and
    validates LIST_ENTRY pointers to prevent infinite loops caused by malformed private structures.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    ListHeadAddress: The address of the list head.
    SourceContext - optional source metadata; NULL indicates retaining the old pattern fallback marker.
    SourceRva - CmCallbackListHead PDB RVA; pass 0 if not a PDB path, used for detail diagnostics only.

Return Value:

    Returns the count of valid registry callbacks found during enumeration.

--*/
{
    LIST_ENTRY listHead;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (listHeadAddress == 0ULL ||
        !kswordArkCallbackEnumReadListEntry(listHeadAddress, &listHead)) {
        return 0UL;
    }

    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT) {
        LIST_ENTRY currentEntry;
        ULONG64 functionAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;
        UNICODE_STRING altitudeString;

        RtlZeroMemory(&currentEntry, sizeof(currentEntry));
        RtlZeroMemory(&altitudeString, sizeof(altitudeString));
        if (!kswordArkCallbackEnumReadListEntry(currentAddress, &currentEntry)) {
            break;
        }
        if (currentEntry.Flink == NULL || currentEntry.Blink == NULL) {
            break;
        }

        if (kswordArkCallbackEnumFindRegistryFields(
            moduleCache,
            currentAddress,
            &functionAddress,
            &contextAddress,
            &altitudeString)) {
            kswordArkCallbackEnumAddRegistryEntry(
                builder,
                moduleCache,
                index,
                currentAddress,
                functionAddress,
                contextAddress,
                &altitudeString,
                sourceContext,
                sourceRva);
            addedCount += 1UL;
        }

        currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
        index += 1UL;
    }

    return addedCount;
}

static BOOLEAN
kswordArkCallbackEnumObjectNodeLooksValid(
    _In_ ULONG64 nodeAddress
    )
/*++

Routine Description:

    Perform basic validation on the object callback list node. Note: The object type's private list has no public structure;
    only the LIST_ENTRY format is validated here, while the actual callback function is confirmed by the module table.

Arguments:

    NodeAddress: Candidate LIST_ENTRY address.

Return Value:

    Returns TRUE if traversable; otherwise returns FALSE.

--*/
{
    LIST_ENTRY entry;

    RtlZeroMemory(&entry, sizeof(entry));
    if (nodeAddress == 0ULL || !kswordArkCallbackEnumReadListEntry(nodeAddress, &entry)) {
        return FALSE;
    }
    if (entry.Flink == NULL || entry.Blink == NULL) {
        return FALSE;
    }
    if ((ULONG64)(ULONG_PTR)entry.Flink < (ULONG64)(ULONG_PTR)MmUserProbeAddress ||
        (ULONG64)(ULONG_PTR)entry.Blink < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumFindObjectTypeCallbackListHead(
    _In_ POBJECT_TYPE objectType,
    _Out_ ULONG64* listHeadAddressOut
    )
/*++

Routine Description:

    Locate the CallbackList list head within the OBJECT_TYPE private structure. Note: This structure is version-dependent, so the function
    searches only within the first few bytes of the object type for a candidate head that satisfies the "non-empty doubly-linked list" condition.

Arguments:

    ObjectType - Input pointer to the object type.
    ListHeadAddressOut - Output list head address.

Return Value:

    Return TRUE if a non-null linked list head is found; otherwise return FALSE.

--*/
{
    ULONG offset = 0UL;
    ULONG64 objectTypeAddress = (ULONG64)(ULONG_PTR)objectType;

    if (listHeadAddressOut == NULL) {
        return FALSE;
    }
    *listHeadAddressOut = 0ULL;
    if (objectType == NULL || objectTypeAddress == 0ULL) {
        return FALSE;
    }

    for (offset = 0x40UL; offset < KSWORD_ARK_CALLBACK_ENUM_OBJECT_TYPE_SCAN_BYTES; offset += (ULONG)sizeof(ULONG_PTR)) {
        ULONG64 headAddress = objectTypeAddress + offset;
        LIST_ENTRY headEntry;
        ULONG64 flinkAddress = 0ULL;
        ULONG64 blinkAddress = 0ULL;
        LIST_ENTRY firstEntry;

        RtlZeroMemory(&headEntry, sizeof(headEntry));
        RtlZeroMemory(&firstEntry, sizeof(firstEntry));
        if (!kswordArkCallbackEnumReadListEntry(headAddress, &headEntry)) {
            continue;
        }

        flinkAddress = (ULONG64)(ULONG_PTR)headEntry.Flink;
        blinkAddress = (ULONG64)(ULONG_PTR)headEntry.Blink;
        if (flinkAddress == 0ULL || blinkAddress == 0ULL || flinkAddress == headAddress) {
            continue;
        }
        if (!kswordArkCallbackEnumObjectNodeLooksValid(flinkAddress)) {
            continue;
        }
        if (!kswordArkCallbackEnumReadListEntry(flinkAddress, &firstEntry)) {
            continue;
        }
        if ((ULONG64)(ULONG_PTR)firstEntry.Blink != headAddress &&
            (ULONG64)(ULONG_PTR)headEntry.Blink != flinkAddress) {
            continue;
        }

        *listHeadAddressOut = headAddress;
        return TRUE;
    }

    return FALSE;
}

static KswordArkCallbackEnumObjectListState
kswordArkCallbackEnumFindObjectTypeCallbackListHeadPdb(
    _In_ POBJECT_TYPE objectType,
    _In_ ULONG callbackListOffset,
    _Out_ ULONG64* listHeadAddressOut
    )
/*++

Routine Description:

    Locates OBJECT_TYPE.CallbackList from a PDB supplied structure offset.
    Processing computes ObjectType + CallbackListOffset, reads the LIST_ENTRY
    head, and accepts either an empty self-referential list or a non-empty list
    whose first node links back to the computed head.

Arguments:

    ObjectType - Input OBJECT_TYPE pointer.
    CallbackListOffset - PDB offset of _OBJECT_TYPE.CallbackList.
    ListHeadAddressOut - Receives the computed list head VA on success.

Return Value:

    Returns KswordArkCallbackEnumObjectListNonEmpty when the PDB offset
    produced a readable/reasonable non-empty list head, KswordArkCallbackEnumObjectListEmpty
    when the head is readable but empty/self-referential, and
    KswordArkCallbackEnumObjectListInvalid when the offset is unusable and the
    caller must fall back to the existing object-type heuristic scan.

--*/
{
    ULONG64 objectTypeAddress = (ULONG64)(ULONG_PTR)objectType;
    ULONG64 headAddress = 0ULL;
    LIST_ENTRY headEntry;
    ULONG64 flinkAddress = 0ULL;
    ULONG64 blinkAddress = 0ULL;

    if (listHeadAddressOut == NULL) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }
    *listHeadAddressOut = 0ULL;
    if (objectType == NULL || objectTypeAddress == 0ULL) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }
    if (objectTypeAddress > (((ULONG64)~0ULL) - (ULONG64)callbackListOffset)) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }

    headAddress = objectTypeAddress + (ULONG64)callbackListOffset;
    RtlZeroMemory(&headEntry, sizeof(headEntry));
    if (!kswordArkCallbackEnumReadListEntry(headAddress, &headEntry)) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }

    flinkAddress = (ULONG64)(ULONG_PTR)headEntry.Flink;
    blinkAddress = (ULONG64)(ULONG_PTR)headEntry.Blink;
    if (flinkAddress == headAddress && blinkAddress == headAddress) {
        *listHeadAddressOut = headAddress;
        return kKswordArkCallbackEnumObjectListEmpty;
    }
    if (flinkAddress == 0ULL || blinkAddress == 0ULL) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }
    if (!kswordArkCallbackEnumObjectNodeLooksValid(flinkAddress)) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }
    if (blinkAddress < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return kKswordArkCallbackEnumObjectListInvalid;
    }

    {
        LIST_ENTRY firstEntry;
        RtlZeroMemory(&firstEntry, sizeof(firstEntry));
        if (!kswordArkCallbackEnumReadListEntry(flinkAddress, &firstEntry)) {
            return kKswordArkCallbackEnumObjectListInvalid;
        }
        if ((ULONG64)(ULONG_PTR)firstEntry.Blink != headAddress) {
            return kKswordArkCallbackEnumObjectListInvalid;
        }
    }

    *listHeadAddressOut = headAddress;
    return kKswordArkCallbackEnumObjectListNonEmpty;
}

static BOOLEAN
kswordArkCallbackEnumFindObjectCallbackFieldsPdb(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_opt_ const KswordArkCallbackEnumDyndataProfile* profile,
    _In_ ULONG64 nodeAddress,
    _Out_ KswordArkCallbackEnumObjectScanResult* resultOut
    )
/*++

Routine Description:

    Reads _CALLBACK_ENTRY_ITEM fields using PDB supplied offsets. Processing
    derives the entry-item base from EntryItemList when available, then reads
    PreOperation, PostOperation, Operations, and CallbackEntry directly. Function
    pointers must resolve to a loaded kernel module before the result is trusted.

Arguments:

    ModuleCache - Module cache used to validate callback function pointers.
    Profile - Captured callback DynData profile containing PDB offsets/sources.
    NodeAddress - Current LIST_ENTRY node address from OBJECT_TYPE.CallbackList.
    ResultOut - Receives parsed callback fields.

Return Value:

    TRUE when direct PDB-offset parsing finds at least one valid callback
    function. FALSE means the caller should use the existing heuristic parser.

--*/
{
    const KswDynCallbackOffsets* offsets = NULL;
    const KswDynCallbackOffsets* sources = NULL;
    ULONG64 entryItemBase = nodeAddress;
    ULONG64 preOperation = 0ULL;
    ULONG64 postOperation = 0ULL;
    ULONG64 callbackEntry = 0ULL;
    ULONG64 registrationProbe = 0ULL;
    ULONG operationMask = 0UL;
    KswordArkCallbackEnumObjectScanResult result;

    if (profile == NULL || !profile->active || resultOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(resultOut, sizeof(*resultOut));
    RtlZeroMemory(&result, sizeof(result));

    offsets = &profile->state.callbackOffsets;
    sources = &profile->state.callbackOffsetSources;
    if (!kswordArkCallbackEnumPdbOffsetAvailable(
            offsets->callbackEntryItemEntryList,
            sources->callbackEntryItemEntryList) ||
        !kswordArkCallbackEnumPdbOffsetAvailable(
            offsets->callbackEntryItemPreOperation,
            sources->callbackEntryItemPreOperation) ||
        !kswordArkCallbackEnumPdbOffsetAvailable(
            offsets->callbackEntryItemPostOperation,
            sources->callbackEntryItemPostOperation) ||
        !kswordArkCallbackEnumPdbOffsetAvailable(
            offsets->callbackEntryItemOperations,
            sources->callbackEntryItemOperations) ||
        !kswordArkCallbackEnumPdbOffsetAvailable(
            offsets->callbackEntryItemCallbackEntry,
            sources->callbackEntryItemCallbackEntry)) {
        return FALSE;
    }

    if (nodeAddress < (ULONG64)offsets->callbackEntryItemEntryList) {
        return FALSE;
    }
    entryItemBase = nodeAddress - (ULONG64)offsets->callbackEntryItemEntryList;

    if (!kswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->callbackEntryItemPreOperation,
            &preOperation) ||
        !kswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->callbackEntryItemPostOperation,
            &postOperation) ||
        !kswordArkCallbackEnumReadUlong(
            entryItemBase + (ULONG64)offsets->callbackEntryItemOperations,
            &operationMask) ||
        !kswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->callbackEntryItemCallbackEntry,
            &callbackEntry)) {
        return FALSE;
    }

    if (preOperation != 0ULL) {
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(preOperation) ||
            !kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, preOperation)) {
            return FALSE;
        }
        result.preOperation = preOperation;
    }
    if (postOperation != 0ULL) {
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(postOperation) ||
            !kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, postOperation)) {
            return FALSE;
        }
        result.postOperation = postOperation;
    }
    if (result.preOperation == 0ULL && result.postOperation == 0ULL) {
        return FALSE;
    }
    if ((operationMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) == 0UL ||
        (operationMask & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE | 0xFFFF0000UL)) != 0UL) {
        return FALSE;
    }
    if (callbackEntry == 0ULL || !kswordArkCallbackEnumLooksLikeKernelPointer(callbackEntry)) {
        return FALSE;
    }
    if (callbackEntry == entryItemBase ||
        callbackEntry == nodeAddress ||
        kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, callbackEntry) ||
        !kswordArkCallbackEnumReadPointer(callbackEntry, &registrationProbe)) {
        return FALSE;
    }

    result.operationMask = operationMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE);
    result.registrationBlock = callbackEntry;
    result.usedPdbOffsets = TRUE;
    *resultOut = result;
    return TRUE;
}

static BOOLEAN
kswordArkCallbackEnumFindObjectCallbackFields(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 nodeAddress,
    _Out_ KswordArkCallbackEnumObjectScanResult* resultOut
    )
/*++

Routine Description:

    Identify Pre/PostOperation, Operations, and Registration fields from the object callback private node.
    Note: Pre/PostOperation pointers must reside within loaded kernel modules;
    the Operations mask is read heuristically from the adjacent ULONG field.

Arguments:

    ModuleCache - Module cache.
    NodeAddress - Linked list node address.
    ResultOut - Output identification result.

Return Value:

    Return TRUE if at least one callback function returns TRUE; otherwise return FALSE.

--*/
{
    LONG offset = 0L;
    KswordArkCallbackEnumObjectScanResult result;

    RtlZeroMemory(&result, sizeof(result));
    if (resultOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(resultOut, sizeof(*resultOut));

    for (offset = KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES * -1L;
        offset <= KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES;
        offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 fieldAddress = 0ULL;
        ULONG64 candidate = 0ULL;

        if (offset < 0L && nodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? nodeAddress - (ULONG64)(-offset)
            : nodeAddress + (ULONG64)offset;
        if (!kswordArkCallbackEnumReadPointer(fieldAddress, &candidate)) {
            continue;
        }
        if (!kswordArkCallbackEnumLooksLikeKernelPointer(candidate)) {
            continue;
        }
        if (!kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, candidate)) {
            continue;
        }

        if (result.preOperation == 0ULL) {
            result.preOperation = candidate;
        }
        else if (result.postOperation == 0ULL && candidate != result.preOperation) {
            result.postOperation = candidate;
            break;
        }
    }

    if (result.preOperation == 0ULL && result.postOperation == 0ULL) {
        return FALSE;
    }

    for (offset = -0x40L; offset <= 0x80L; offset += (LONG)sizeof(ULONG)) {
        ULONG candidateMask = 0UL;
        ULONG64 fieldAddress = 0ULL;
        if (offset < 0L && nodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? nodeAddress - (ULONG64)(-offset)
            : nodeAddress + (ULONG64)offset;
        if (!kswordArkCallbackEnumReadUlong(fieldAddress, &candidateMask)) {
            continue;
        }
        if ((candidateMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) != 0UL &&
            (candidateMask & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE | 0xFFFF0000UL)) == 0UL) {
            result.operationMask = candidateMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE);
            break;
        }
    }
    if (result.operationMask == 0UL) {
        result.operationMask = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    }

    for (offset = KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES * -1L;
        offset <= KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES;
        offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 fieldAddress = 0ULL;
        ULONG64 candidate = 0ULL;
        if (offset < 0L && nodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? nodeAddress - (ULONG64)(-offset)
            : nodeAddress + (ULONG64)offset;
        if (!kswordArkCallbackEnumReadPointer(fieldAddress, &candidate)) {
            continue;
        }
        if (candidate == 0ULL ||
            candidate == result.preOperation ||
            candidate == result.postOperation) {
            continue;
        }
        if (kswordArkCallbackEnumLooksLikeKernelPointer(candidate) && !kswordArkCallbackEnumIsKernelModuleAddress(moduleCache, candidate)) {
            result.registrationBlock = candidate;
            break;
        }
    }

    *resultOut = result;
    return TRUE;
}

static VOID
kswordArkCallbackEnumAddObjectCallbackEntry(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG entryIndex,
    _In_ ULONG objectTypeMask,
    _In_z_ PCWSTR objectTypeName,
    _In_ ULONG64 nodeAddress,
    _In_ ULONG64 callbackAddress,
    _In_ ULONG operationMask,
    _In_ ULONG64 registrationBlock,
    _In_ BOOLEAN isPostOperation,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext,
    _In_ BOOLEAN usedPdbOffsets,
    _In_opt_ const KswDynCallbackOffsets* pdbOffsets
    )
/*++

Routine Description:

    Write a candidate to the ObRegisterCallbacks private linked list. Note: A single node may
    have both Pre and Post functions; after matching module addresses, display them separately.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    EntryIndex - Linked list index.
    ObjectTypeMask: The object type mask.
    ObjectTypeName - Display name of the object type.
    NodeAddress - Linked list node address.
    CallbackAddress - Address of the callback function.
    OperationMask - Ob operation mask.
    RegistrationBlock - Candidate address for the registration block.
    IsPostOperation: TRUE indicates PostOperation; FALSE indicates PreOperation.
    SourceContext - optional source metadata; used to mark trusted/source via the PDB path.
    UsedPdbOffsets - TRUE indicates the field comes from a PDB offset; FALSE indicates heuristic field recovery.
    PdbOffsets - Optional PDB offset structure; prints actual offset values only in trusted path details.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = operationMask;
    entry->objectTypeMask = objectTypeMask;
    if ((objectTypeMask & KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP) != 0UL) {
        entry->registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = callbackAddress;
    // The list node is only diagnostic storage identity. It is never a valid
    // RegistrationHandle and therefore travels separately from registrationAddress.
    entry->rawStorageValue = nodeAddress;
    kswordArkCallbackEnumApplySourceContext(entry, sourceContext);
    if (usedPdbOffsets && sourceContext != NULL && registrationBlock != 0ULL) {
        // _CALLBACK_ENTRY_ITEM.CallbackEntry is the value returned by
        // ObRegisterCallbacks. Only a profile-gated exact field read may publish it.
        entry->registrationAddress = registrationBlock;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
    }
    else {
        // Heuristic scans cannot prove the private structure version, but the UI
        // exposes a high-risk candidate path when the candidate block is present.
        entry->contextAddress = registrationBlock;
        if (registrationBlock != 0ULL) {
            entry->registrationAddress = registrationBlock;
            entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE;
        }
        entry->fieldFlags &= ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE);
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"Ob%wsCallback[%ws:%lu]",
        isPostOperation ? L"Post" : L"Pre",
        objectTypeName,
        (unsigned long)entryIndex);
    if (sourceContext != NULL && sourceContext->source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；fieldPath=%ws，ObjectType=%ws，Node=0x%p，%wsOperation=0x%p，Operations=0x%lX，%ws=0x%p，offsets[EntryList=0x%lX,Pre=0x%lX,Post=0x%lX,Ops=0x%lX,CallbackEntry=0x%lX]。",
            (sourceContext->detailPrefix != NULL) ? sourceContext->detailPrefix : L"PDB callback profile trusted object list",
            usedPdbOffsets ? L"PDB offsets" : L"heuristic fallback",
            objectTypeName,
            (PVOID)(ULONG_PTR)nodeAddress,
            isPostOperation ? L"Post" : L"Pre",
            (PVOID)(ULONG_PTR)callbackAddress,
            (unsigned long)operationMask,
            usedPdbOffsets ? L"CallbackEntry" : L"RegistrationBlock",
            (PVOID)(ULONG_PTR)registrationBlock,
            (unsigned long)((pdbOffsets != NULL) ? pdbOffsets->callbackEntryItemEntryList : 0UL),
            (unsigned long)((pdbOffsets != NULL) ? pdbOffsets->callbackEntryItemPreOperation : 0UL),
            (unsigned long)((pdbOffsets != NULL) ? pdbOffsets->callbackEntryItemPostOperation : 0UL),
            (unsigned long)((pdbOffsets != NULL) ? pdbOffsets->callbackEntryItemOperations : 0UL),
            (unsigned long)((pdbOffsets != NULL) ? pdbOffsets->callbackEntryItemCallbackEntry : 0UL));
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"OBJECT_TYPE CallbackList 私有链表候选；fallback=heuristic scan，ObjectType=%ws，Node=0x%p，%wsOperation=0x%p，Operations=0x%lX，RegistrationBlock=0x%p。",
            objectTypeName,
            (PVOID)(ULONG_PTR)nodeAddress,
            isPostOperation ? L"Post" : L"Pre",
            (PVOID)(ULONG_PTR)callbackAddress,
            (unsigned long)operationMask,
            (PVOID)(ULONG_PTR)registrationBlock);
    }
    kswordArkCallbackEnumFinalizeModuleCached(moduleCache, entry);
}
static ULONG
kswordArkCallbackEnumAddObjectTypeCallbackList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ POBJECT_TYPE objectType,
    _In_ ULONG objectTypeMask,
    _In_z_ PCWSTR objectTypeName,
    _In_opt_ const KswordArkCallbackEnumDyndataProfile* profile,
    _In_opt_ const KswordArkCallbackEnumSourceContext* sourceContext
    )
/*++

Routine Description:

    enumerate the private callback list of an object type's Ob callback. Note: If a PDB profile
    is available, prefer using the _OBJECT_TYPE.CallbackList and _CALLBACK_ENTRY_ITEM field
    offsets; if fields are incomplete or reading fails, fall back to the original heuristic scan.

Arguments:

    Builder - Enum response builder.
    ModuleCache - Module cache.
    ObjectType - Target object type.
    ObjectTypeMask: The object type mask.
    ObjectTypeName - Object type name.
    Profile: Optional PDB callback profile; NULL indicates using only the legacy heuristic.
    SourceContext - optional source metadata; used to mark trusted/source via the PDB path.

Return Value:

    Returns: The count of valid object callbacks enumerated.

--*/
{
    ULONG64 listHeadAddress = 0ULL;
    LIST_ENTRY listHead;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;
    KswordArkCallbackEnumObjectListState listHeadState = kKswordArkCallbackEnumObjectListInvalid;
    BOOLEAN usingPdbListHead = FALSE;

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (profile != NULL &&
        profile->active &&
        kswordArkCallbackEnumPdbOffsetAvailable(
            profile->state.callbackOffsets.objectTypeCallbackList,
            profile->state.callbackOffsetSources.objectTypeCallbackList) &&
        (listHeadState = kswordArkCallbackEnumFindObjectTypeCallbackListHeadPdb(
            objectType,
            profile->state.callbackOffsets.objectTypeCallbackList,
            &listHeadAddress)) != kKswordArkCallbackEnumObjectListInvalid) {
        usingPdbListHead = TRUE;
    }
    if (!usingPdbListHead) {
        if (!kswordArkCallbackEnumFindObjectTypeCallbackListHead(objectType, &listHeadAddress)) {
            return 0UL;
        }
        profile = NULL;
        sourceContext = NULL;
    }
    if (!kswordArkCallbackEnumReadListEntry(listHeadAddress, &listHead)) {
        return 0UL;
    }
    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT) {
        LIST_ENTRY currentEntry;
        KswordArkCallbackEnumObjectScanResult scanResult;

        RtlZeroMemory(&currentEntry, sizeof(currentEntry));
        RtlZeroMemory(&scanResult, sizeof(scanResult));
        if (!kswordArkCallbackEnumReadListEntry(currentAddress, &currentEntry)) {
            break;
        }
        if (!kswordArkCallbackEnumFindObjectCallbackFieldsPdb(
                moduleCache,
                profile,
                currentAddress,
                &scanResult) &&
            !kswordArkCallbackEnumFindObjectCallbackFields(moduleCache, currentAddress, &scanResult)) {
            currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
            index += 1UL;
            continue;
        }
        if (scanResult.preOperation != 0ULL) {
            const KswordArkCallbackEnumSourceContext* rowSourceContext =
                (scanResult.usedPdbOffsets && sourceContext != NULL) ? sourceContext : NULL;
            kswordArkCallbackEnumAddObjectCallbackEntry(
                builder,
                moduleCache,
                index,
                objectTypeMask,
                objectTypeName,
                currentAddress,
                scanResult.preOperation,
                scanResult.operationMask,
                scanResult.registrationBlock,
                FALSE,
                rowSourceContext,
                scanResult.usedPdbOffsets,
                (profile != NULL) ? &profile->state.callbackOffsets : NULL);
            addedCount += 1UL;
        }
        if (scanResult.postOperation != 0ULL) {
            const KswordArkCallbackEnumSourceContext* rowSourceContext =
                (scanResult.usedPdbOffsets && sourceContext != NULL) ? sourceContext : NULL;
            kswordArkCallbackEnumAddObjectCallbackEntry(
                builder,
                moduleCache,
                index,
                objectTypeMask,
                objectTypeName,
                currentAddress,
                scanResult.postOperation,
                scanResult.operationMask,
                scanResult.registrationBlock,
                TRUE,
                rowSourceContext,
                scanResult.usedPdbOffsets,
                (profile != NULL) ? &profile->state.callbackOffsets : NULL);
            addedCount += 1UL;
        }

        currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
        index += 1UL;
    }

    if (usingPdbListHead &&
        listHeadState == kKswordArkCallbackEnumObjectListEmpty) {
        return addedCount;
    }

    return addedCount;
}

VOID
kswordArkCallbackEnumAddPrivateCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    enumerate system private callback structures. Implementation reference: SKT64 feature location method;
    read-only traversal of the Psp notify array, Cm callback list, and Process/Thread OBJECT_TYPE callback lists.

Arguments:

    Builder - Enum response builder.

Return Value:

    No return value.

--*/
{
    KswordArkCallbackModuleCache moduleCache;
    KswordArkCallbackEnumDyndataProfile pdbProfile;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 processArray = 0ULL;
    ULONG64 threadArray = 0ULL;
    ULONG64 imageArray = 0ULL;
    ULONG64 notifyEnableMask = 0ULL;
    ULONG64 cmListHead = 0ULL;
    ULONG64 obpCallPreOperationCallbacks = 0ULL;
    ULONG addedCount = 0UL;
    ULONG notifyMaskValue = 0UL;
    WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    RtlZeroMemory(&pdbProfile, sizeof(pdbProfile));
    (VOID)kswordArkCallbackEnumCaptureDynDataProfile(&pdbProfile);

    status = kswordArkCallbackEnumLocatePspNotifyEnableMask(&notifyEnableMask);
    if (NT_SUCCESS(status)) {
        (VOID)kswordArkCallbackEnumReadUlong(notifyEnableMask, &notifyMaskValue);
    }
    kswordArkCallbackEnumAddLocateRow(
        builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
        L"PspNotifyEnableMask",
        notifyEnableMask,
        status,
        NT_SUCCESS(status)
            ? L"已定位 PspNotifyEnableMask；用于诊断进程/线程/镜像 notify 全局启用状态。"
            : L"未能定位 PspNotifyEnableMask；不影响后续数组特征扫描。");

    status = kswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.state.callbackGlobals.pspCreateProcessNotifyRoutine,
            pdbProfile.state.callbackGlobalSources.pspCreateProcessNotifyRoutine,
            sizeof(ULONG_PTR),
            &processArray);
    if (NT_SUCCESS(status)) {
        addedCount = kswordArkCallbackEnumAddNotifyArray(
            builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
            KSWORD_ARK_PROCESS_OP_CREATE,
            processArray,
            L"PspCreateProcessNotifyRoutine",
            &kGKswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.state.callbackGlobals.pspCreateProcessNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspCreateProcessNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.state.callbackGlobals.pspCreateProcessNotifyRoutine,
                (PVOID)(ULONG_PTR)processArray);
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                L"PspCreateProcessNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS kPdbStatus = status;
        status = kswordArkCallbackEnumLocatePspCreateProcessNotifyRoutine(&processArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsSetCreateProcessNotifyRoutine 特征定位进程 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)kPdbStatus,
                (unsigned long)pdbProfile.state.callbackProfileActive,
                (unsigned long)pdbProfile.state.callbackGlobals.pspCreateProcessNotifyRoutine,
                (unsigned long)pdbProfile.state.callbackGlobalSources.pspCreateProcessNotifyRoutine);
        }
        kswordArkCallbackEnumAddLocateRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
            L"PspCreateProcessNotifyRoutine",
            processArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspCreateProcessNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = kswordArkCallbackEnumAddNotifyArray(
                builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                KSWORD_ARK_PROCESS_OP_CREATE,
                processArray,
                L"PspCreateProcessNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                kswordArkCallbackEnumAddUnsupportedRow(
                    builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                    L"PspCreateProcessNotifyRoutine empty",
                    L"已定位进程 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    status = kswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.state.callbackGlobals.pspCreateThreadNotifyRoutine,
            pdbProfile.state.callbackGlobalSources.pspCreateThreadNotifyRoutine,
            sizeof(ULONG_PTR),
            &threadArray);
    if (NT_SUCCESS(status)) {
        addedCount = kswordArkCallbackEnumAddNotifyArray(
            builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
            KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
            threadArray,
            L"PspCreateThreadNotifyRoutine",
            &kGKswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.state.callbackGlobals.pspCreateThreadNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspCreateThreadNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.state.callbackGlobals.pspCreateThreadNotifyRoutine,
                (PVOID)(ULONG_PTR)threadArray);
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                L"PspCreateThreadNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS kPdbStatus = status;
        status = kswordArkCallbackEnumLocatePspCreateThreadNotifyRoutine(&threadArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsRemoveCreateThreadNotifyRoutine 特征定位线程 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)kPdbStatus,
                (unsigned long)pdbProfile.state.callbackProfileActive,
                (unsigned long)pdbProfile.state.callbackGlobals.pspCreateThreadNotifyRoutine,
                (unsigned long)pdbProfile.state.callbackGlobalSources.pspCreateThreadNotifyRoutine);
        }
        kswordArkCallbackEnumAddLocateRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
            L"PspCreateThreadNotifyRoutine",
            threadArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspCreateThreadNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = kswordArkCallbackEnumAddNotifyArray(
                builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
                threadArray,
                L"PspCreateThreadNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                kswordArkCallbackEnumAddUnsupportedRow(
                    builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                    L"PspCreateThreadNotifyRoutine empty",
                    L"已定位线程 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    status = kswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.state.callbackGlobals.pspLoadImageNotifyRoutine,
            pdbProfile.state.callbackGlobalSources.pspLoadImageNotifyRoutine,
            sizeof(ULONG_PTR),
            &imageArray);
    if (NT_SUCCESS(status)) {
        addedCount = kswordArkCallbackEnumAddNotifyArray(
            builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
            KSWORD_ARK_IMAGE_OP_LOAD,
            imageArray,
            L"PspLoadImageNotifyRoutine",
            &kGKswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.state.callbackGlobals.pspLoadImageNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspLoadImageNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.state.callbackGlobals.pspLoadImageNotifyRoutine,
                (PVOID)(ULONG_PTR)imageArray);
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                L"PspLoadImageNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS kPdbStatus = status;
        status = kswordArkCallbackEnumLocatePspLoadImageNotifyRoutine(&imageArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsSetLoadImageNotifyRoutineEx 特征定位镜像 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)kPdbStatus,
                (unsigned long)pdbProfile.state.callbackProfileActive,
                (unsigned long)pdbProfile.state.callbackGlobals.pspLoadImageNotifyRoutine,
                (unsigned long)pdbProfile.state.callbackGlobalSources.pspLoadImageNotifyRoutine);
        }
        kswordArkCallbackEnumAddLocateRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
            L"PspLoadImageNotifyRoutine",
            imageArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspLoadImageNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = kswordArkCallbackEnumAddNotifyArray(
                builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                KSWORD_ARK_IMAGE_OP_LOAD,
                imageArray,
                L"PspLoadImageNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                kswordArkCallbackEnumAddUnsupportedRow(
                    builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                    L"PspLoadImageNotifyRoutine empty",
                    L"已定位镜像 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    if (NT_SUCCESS(kswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.state.callbackGlobals.cmCallbackListHead,
            pdbProfile.state.callbackGlobalSources.cmCallbackListHead,
            sizeof(LIST_ENTRY),
            &cmListHead))) {
        addedCount = kswordArkCallbackEnumAddRegistryList(
            builder,
            &moduleCache,
            cmListHead,
            &kGKswordArkCallbackEnumPdbRegistrySourceContext,
            pdbProfile.state.callbackGlobals.cmCallbackListHead);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 CmCallbackListHead VA 0x%p，但链表为空或字段恢复未稳定。",
                (unsigned long)pdbProfile.state.callbackGlobals.cmCallbackListHead,
                (PVOID)(ULONG_PTR)cmListHead);
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
                L"CmCallbackListHead empty",
                detailText);
        }
    }
    else {
        status = kswordArkCallbackEnumLocateCmCallbackListHead(&cmListHead);
        kswordArkCallbackEnumAddLocateRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
            L"CmCallbackListHead",
            cmListHead,
            status,
            NT_SUCCESS(status)
                ? L"已定位 CmCallbackListHead 私有链表，开始保守遍历并识别 Function/Altitude。"
                : L"未能通过 CmUnRegisterCallback 特征定位注册表回调链表头。");
        if (NT_SUCCESS(status)) {
            addedCount = kswordArkCallbackEnumAddRegistryList(
                builder,
                &moduleCache,
                cmListHead,
                NULL,
                0UL);
            if (addedCount == 0UL) {
                kswordArkCallbackEnumAddUnsupportedRow(
                    builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
                    L"CmCallbackListHead empty",
                    L"已定位注册表回调链表头，但未找到能解析到模块的 Function 字段。");
            }
        }
    }

    status = kswordArkCallbackEnumLocateObpCallPreOperationCallbacks(&moduleCache, &obpCallPreOperationCallbacks);
    kswordArkCallbackEnumAddLocateRow(
        builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
        L"ObpCallPreOperationCallbacks",
        obpCallPreOperationCallbacks,
        status,
        NT_SUCCESS(status)
            ? L"已定位 ObpCallPreOperationCallbacks 内部例程；对象回调项继续从 OBJECT_TYPE CallbackList 启发式枚举。"
            : L"未能通过 ntoskrnl 特征定位 ObpCallPreOperationCallbacks；仍会尝试 OBJECT_TYPE 链表启发式枚举。");

    addedCount = 0UL;
    if (PsProcessType != NULL && *PsProcessType != NULL) {
        addedCount += kswordArkCallbackEnumAddObjectTypeCallbackList(
            builder,
            &moduleCache,
            *PsProcessType,
            KSWORD_ARK_OBJECT_OP_TYPE_PROCESS,
            L"Process",
            &pdbProfile,
            pdbProfile.active ? &kGKswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (PsThreadType != NULL && *PsThreadType != NULL) {
        addedCount += kswordArkCallbackEnumAddObjectTypeCallbackList(
            builder,
            &moduleCache,
            *PsThreadType,
            KSWORD_ARK_OBJECT_OP_TYPE_THREAD,
            L"Thread",
            &pdbProfile,
            pdbProfile.active ? &kGKswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (ExDesktopObjectType != NULL && *ExDesktopObjectType != NULL) {
        addedCount += kswordArkCallbackEnumAddObjectTypeCallbackList(
            builder,
            &moduleCache,
            *ExDesktopObjectType,
            KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP,
            L"Desktop",
            &pdbProfile,
            pdbProfile.active ? &kGKswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (addedCount == 0UL) {
        if (pdbProfile.active &&
            kswordArkCallbackEnumPdbOffsetAvailable(
                pdbProfile.state.callbackOffsets.objectTypeCallbackList,
                pdbProfile.state.callbackOffsetSources.objectTypeCallbackList)) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已尝试 PDB _OBJECT_TYPE.CallbackList offset 0x%08lX 及 _CALLBACK_ENTRY_ITEM offsets [EntryList=0x%08lX,Pre=0x%08lX,Post=0x%08lX,Ops=0x%08lX,CallbackEntry=0x%08lX]；未能识别非空对象回调链表。",
                (unsigned long)pdbProfile.state.callbackOffsets.objectTypeCallbackList,
                (unsigned long)pdbProfile.state.callbackOffsets.callbackEntryItemEntryList,
                (unsigned long)pdbProfile.state.callbackOffsets.callbackEntryItemPreOperation,
                (unsigned long)pdbProfile.state.callbackOffsets.callbackEntryItemPostOperation,
                (unsigned long)pdbProfile.state.callbackOffsets.callbackEntryItemOperations,
                (unsigned long)pdbProfile.state.callbackOffsets.callbackEntryItemCallbackEntry);
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
                L"OBJECT_TYPE CallbackList empty",
                detailText);
        }
        else {
            kswordArkCallbackEnumAddUnsupportedRow(
                builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
                L"OBJECT_TYPE CallbackList empty",
                L"未能在 Process/Thread/Desktop OBJECT_TYPE 私有区域识别非空 CallbackList；对象回调结构随版本变化较大。");
        }
    }

    if (notifyMaskValue != 0UL) {
        KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = kswordArkCallbackEnumReserveEntry(builder);
        if (entry != NULL) {
            entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS;
            entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
            entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
            entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
            entry->contextAddress = notifyMaskValue;
            entry->registrationAddress = notifyEnableMask;
            kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), L"PspNotifyEnableMask value");
            (VOID)RtlStringCbPrintfW(
                entry->detail,
                sizeof(entry->detail),
                L"PspNotifyEnableMask=0x%08lX，Address=0x%p；该值仅用于诊断 notify 路径启用状态。",
                (unsigned long)notifyMaskValue,
                (PVOID)(ULONG_PTR)notifyEnableMask);
        }
    }

    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}

static VOID
kswordArkCallbackEnumAddSystemInformerDynDataRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Write callback-related fields from System Informer DynData to the diagnostic line. Note: Ksword has
    already vendored kphdyn data; this line explicitly shows whether the ETW private structure offset matches.

Arguments:

    Builder - Enum response builder.

Return Value:

    No return value.

--*/
{
    KswDynState dynState;
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = ((dynState.capabilityMask & KSW_CAP_ETW_GUID_FIELDS) != 0ULL)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->lastStatus = dynState.lastStatus;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    entry->contextAddress = ((ULONG64)dynState.kernel.egeGuid << 32) |
        (ULONG64)dynState.kernel.ereGuidEntry;
    kswordArkCallbackEnumCopyWide(
        entry->name,
        RTL_NUMBER_OF(entry->name),
        L"System Informer DynData: ETW offsets");
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"已复用 third_party/systeminformer_dyn/kphdyn 数据；NtosActive=%lu，EgeGuid=0x%08lX，EreGuidEntry=0x%08lX，cap=0x%llX。",
        (unsigned long)(dynState.ntosActive ? 1UL : 0UL),
        (unsigned long)dynState.kernel.egeGuid,
        (unsigned long)dynState.kernel.ereGuidEntry,
        dynState.capabilityMask);
}

static VOID
kswordArkCallbackEnumAddUnsupportedKinds(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Add a description row for categories not yet covered. Note: Process, thread, image, registry, object, and
    WFP are handled by other phases; this section retains only ETW, which still lacks a secure global entry.

Arguments:

    Builder - Enum response builder.

Return Value:

    No return value.

--*/
{
    kswordArkCallbackEnumAddSystemInformerDynDataRow(builder);
    kswordArkCallbackEnumAddUnsupportedRow(
        builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER,
        L"ETW providers/consumers",
        L"System Informer DynData 暴露 EgeGuid/EreGuidEntry 偏移，但仍需安全定位 ETW 全局表入口；当前仅标记未支持。");
}

NTSTATUS
kswordArkCallbackEnumRevalidateObjectRemoveRequest(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* requestPacket,
    _In_ BOOLEAN requireGenerationMatch,
    _Out_ BOOLEAN* matchPresentOut,
    _Out_opt_ ULONG* matchedFieldFlagsOut,
    _Out_opt_ ULONG64* matchedRegistrationAddressOut,
    _Out_opt_ ULONG64* currentGenerationOut
    )
/*++

Routine Description:

    Rebuilds the same complete ordered callback snapshot exposed by the default
    V3 R3 enumeration and matches one exact Object Callback row. No private
    address supplied by R3 is dereferenced by this routine.

--*/
{
    KswordArkCallbackEnumBuilder builder;

    if (requestPacket == NULL || matchPresentOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *matchPresentOut = FALSE;
    if (matchedFieldFlagsOut != NULL) {
        *matchedFieldFlagsOut = 0UL;
    }
    if (matchedRegistrationAddressOut != NULL) {
        *matchedRegistrationAddressOut = 0ULL;
    }
    if (currentGenerationOut != NULL) {
        *currentGenerationOut = 0ULL;
    }

    RtlZeroMemory(&builder, sizeof(builder));
    builder.lastStatus = STATUS_SUCCESS;
    builder.removeMatchRequest = requestPacket;
    kswordArkCallbackEnumSnapshotBegin(&builder);
    kswordArkCallbackEnumAddSelfCallbacks(&builder);
    kswordArkCallbackEnumAddMinifilters(&builder);
    kswordArkCallbackEnumAddPrivateCallbacks(&builder);
    kswordArkCallbackExtendedAddSpecialCallbacks(&builder);
    kswordArkCallbackExternalAddCallbacks(&builder);
    kswordArkCallbackEnumAddUnsupportedKinds(&builder);
    kswordArkCallbackEnumSnapshotFinalize(&builder);

    if (builder.snapshotRowCount != builder.totalCount || !NT_SUCCESS(builder.lastStatus)) {
        return NT_SUCCESS(builder.lastStatus) ? STATUS_DATA_ERROR : builder.lastStatus;
    }
    if (currentGenerationOut != NULL) {
        *currentGenerationOut = builder.snapshotHash;
    }
    if (requireGenerationMatch &&
        requestPacket->enumerationGeneration != builder.snapshotHash) {
        return STATUS_RETRY;
    }
    if (builder.removeMatchCount > 1UL) {
        return STATUS_DATA_ERROR;
    }
    if (builder.removeMatchCount == 1UL) {
        *matchPresentOut = TRUE;
        if (matchedFieldFlagsOut != NULL) {
            *matchedFieldFlagsOut = builder.removeMatchedFieldFlags |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;
        }
        if (matchedRegistrationAddressOut != NULL) {
            *matchedRegistrationAddressOut = builder.removeMatchedRegistrationAddress;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackIoctlEnumCallbacks(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_ENUM_CALLBACKS. Note: This IOCTL performs a read-only traversal of currently stable
    callback information, prioritizing Ksword's own registered entries and the Filter Manager minifilter list.

Arguments:

    Request - current WDF request.
    InputBufferLength: Length of the input buffer.
    OutputBufferLength - Length of the output buffer.
    CompleteBytesOut: Actual number of output bytes completed.

Return Value:

    Returns STATUS_SUCCESS on success; returns the corresponding NTSTATUS if parameters or buffers are invalid.

--*/
{
    /* Note: The following variables are initialized to the most conservative default values first; responses are written only after protocol negotiation completes. */
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t inputLength = 0U;
    size_t outputLength = 0U;
    ULONG requestFlags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL;
    ULONG requestMaxEntries = KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES;
    ULONG requestStartIndex = 0UL;
    ULONG requestVersion = 0UL;
    ULONG snapshotPolicy = KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE;
    ULONG expectedTotalCount = 0UL;
    ULONG responseHeaderBytes = 0UL;
    ULONG outputCapacity = 0UL;
    ULONG nextIndex = 0UL;
    ULONG legacyEntryIndex = 0UL;
    ULONG64 expectedSnapshotHash = 0ULL;
    BOOLEAN snapshotChanged = FALSE;
    KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2* requestPacketV2 = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_REQUEST* requestPacket = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2* responsePacketV2 = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* responsePacket = NULL;
    KswordArkCallbackEnumBuilder builder;

    /* Note: WDF completion length is a required output; all failure paths must leave it zero. */
    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (inputBufferLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2) ||
        outputBufferLength < kGKswordArkCallbackEnumHeaderBytesV2) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Note: Retrieve the buffer using the shortest V2 request first to allow new drivers to serve old R3. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacketV2 = (KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2*)inputBuffer;
    requestVersion = requestPacketV2->version;
    /* Note: Snapshot contract fields are read only in V3; V2 strictly maintains the historical 24-byte layout. */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        if (inputLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        requestPacket = (KSWORD_ARK_ENUM_CALLBACKS_REQUEST*)inputBuffer;
        if (requestPacket->size < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST)) {
            return STATUS_INVALID_PARAMETER;
        }
        expectedSnapshotHash = requestPacket->expectedSnapshotHash;
        expectedTotalCount = requestPacket->expectedTotalCount;
        snapshotPolicy = requestPacket->snapshotPolicy;
        responseHeaderBytes = kGKswordArkCallbackEnumHeaderBytesV3;
    }
    else if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2) {
        if (requestPacketV2->size < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2)) {
            return STATUS_INVALID_PARAMETER;
        }
        responseHeaderBytes = kGKswordArkCallbackEnumHeaderBytesV2;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Unknown snapshot policies and strong-match requests lacking the expected hash are rejected immediately. */
    if (snapshotPolicy != KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE &&
        snapshotPolicy != KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH) {
        return STATUS_INVALID_PARAMETER;
    }
    if (snapshotPolicy == KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH &&
        expectedSnapshotHash == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < responseHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Note: The response header length follows the negotiated version; prevent writing V3 fields into a V2 buffer. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        responseHeaderBytes,
        &outputBuffer,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outputLength < responseHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Note: normalize enumeration category, page size, and start index to limit per-call kernel workload. */
    requestFlags = requestPacketV2->flags;
    if (requestFlags == 0UL) {
        requestFlags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL;
    }
    if ((requestFlags & (~KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestPacketV2->maxEntries != 0UL) {
        requestMaxEntries = requestPacketV2->maxEntries;
    }
    requestStartIndex = requestPacketV2->startIndex;
    if (requestMaxEntries > KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES) {
        requestMaxEntries = KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES;
    }

    /* Note: Zero the entire output buffer first, then initialize only the response header corresponding to the negotiated version. */
    RtlZeroMemory(outputBuffer, outputLength);
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        responsePacket = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)outputBuffer;
        responsePacket->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
        responsePacket->version = requestVersion;
        responsePacket->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        responsePacket->lastStatus = STATUS_SUCCESS;
    }
    else {
        responsePacketV2 = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2*)outputBuffer;
        responsePacketV2->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2);
        responsePacketV2->version = requestVersion;
        responsePacketV2->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        responsePacketV2->lastStatus = STATUS_SUCCESS;
    }

    /* Note: The actual page capacity is constrained by both the output buffer and the request limit. */
    if (outputLength > responseHeaderBytes) {
        outputCapacity = (ULONG)((outputLength - responseHeaderBytes) / sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
    }
    if (outputCapacity > requestMaxEntries) {
        outputCapacity = requestMaxEntries;
    }

    /* Note: All categories must be fully logically enumerated; entries outside pagination participate in hashing via ScratchEntry. */
    RtlZeroMemory(&builder, sizeof(builder));
    builder.entries = (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
        ? responsePacket->entries
        : responsePacketV2->entries;
    builder.entryCapacity = outputCapacity;
    builder.startIndex = requestStartIndex;
    builder.lastStatus = STATUS_SUCCESS;
    kswordArkCallbackEnumSnapshotBegin(&builder);

    /* Note: Category flags only affect logical dataset composition, not the snapshot algorithm. */
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_KSWORD_SELF) != 0UL) {
        kswordArkCallbackEnumAddSelfCallbacks(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_MINIFILTERS) != 0UL) {
        kswordArkCallbackEnumAddMinifilters(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_PRIVATE) != 0UL) {
        kswordArkCallbackEnumAddPrivateCallbacks(&builder);
        kswordArkCallbackExtendedAddSpecialCallbacks(&builder);
        kswordArkCallbackExternalAddCallbacks(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_UNSUPPORTED) != 0UL) {
        kswordArkCallbackEnumAddUnsupportedKinds(&builder);
    }

    /* Note: Finalization commits the tail row, row identities, and the hash of the entire ordered snapshot. */
    kswordArkCallbackEnumSnapshotFinalize(&builder);
    /* Note: Internal count inconsistency indicates the enumerator missed submitting rows; expose a data error to R3. */
    if (builder.snapshotRowCount != builder.totalCount) {
        builder.lastStatus = STATUS_DATA_ERROR;
    }
    /* Note: Do not return mixed data if the continuation page contract does not match; prompt R3 to retry from the first page. */
    if (snapshotPolicy == KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH &&
        (builder.snapshotHash != expectedSnapshotHash ||
         builder.totalCount != expectedTotalCount)) {
        snapshotChanged = TRUE;
        builder.flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED;
        builder.lastStatus = STATUS_RETRY;
        builder.returnedCount = 0UL;
    }
    /* Note: The legacy protocol must not publish V3-exclusive flags to maintain predictable behavior for legacy clients. */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2) {
        /* Note: The hash field in V2 rows was historically reserved as zero; compatible responses must clear V3-derived values. */
        for (legacyEntryIndex = 0UL;
             legacyEntryIndex < builder.returnedCount;
             ++legacyEntryIndex) {
            builder.entries[legacyEntryIndex].enumerationGeneration = 0ULL;
            builder.entries[legacyEntryIndex].identityHash = 0ULL;
            builder.entries[legacyEntryIndex].fieldFlags &=
                ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH |
                  KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION);
        }
        builder.flags &=
            ~(KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID |
              KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID |
              KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED);
    }

    /* Note: Calculate the next page index; explicitly zero out when the snapshot changes to trigger a full restart. */
    if (!snapshotChanged &&
        requestStartIndex <= builder.totalCount &&
        builder.returnedCount <= (builder.totalCount - requestStartIndex)) {
        nextIndex = requestStartIndex + builder.returnedCount;
    }
    else if (snapshotChanged) {
        nextIndex = 0UL;
    }
    else {
        nextIndex = builder.totalCount;
    }
    if (!snapshotChanged && nextIndex < builder.totalCount) {
        builder.flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA;
    }

    /* Note: Write headers based on negotiated version; V3 additionally publishes generation and snapshot hash. */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        responsePacket->totalCount = builder.totalCount;
        responsePacket->returnedCount = builder.returnedCount;
        responsePacket->flags = builder.flags;
        responsePacket->lastStatus = builder.lastStatus;
        responsePacket->nextIndex = nextIndex;
        responsePacket->enumerationGeneration = builder.snapshotHash;
        responsePacket->snapshotHash = builder.snapshotHash;
    }
    else {
        responsePacketV2->totalCount = builder.totalCount;
        responsePacketV2->returnedCount = builder.returnedCount;
        responsePacketV2->flags = builder.flags;
        responsePacketV2->lastStatus = builder.lastStatus;
        responsePacketV2->nextIndex = nextIndex;
    }
    /* Note: WDF completion length includes only the response header and the actual returned contiguous entries. */
    *completeBytesOut = (size_t)responseHeaderBytes +
        ((size_t)builder.returnedCount * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));

    /* Note: Enumeration-level exceptions are conveyed via the lastStatus response, while the IOCTL transmission itself remains successful. */
    return STATUS_SUCCESS;
}
