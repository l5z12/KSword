/*++

Module Name:

    dyndata_fallback_resolver.c

Abstract:

    This file recovers kernel layouts that previously required an exact PDB
    profile. It starts from public WDK layouts or an ntoskrnl export and then
    validates every private KLDR offset against the live KSword driver entry.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "dyndata_fallback_resolver.h"
#include "kernel_cache_fallback.h"
#include "runtime_signature_scan.h"
#include "../features/kernel/ssdt_fallback.h"

#define KSW_RUNTIME_KLDR_SCAN_BYTES 0x0100U
#define KSW_RUNTIME_KLDR_WALK_BUDGET 0x1000U
#define KSW_RUNTIME_KLDR_NAME_CHARS 0x0200U

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_ PCCH routineName
    );

static VOID
kswordArkDriverInitializeKernelFallbackLayout(
    _Out_ PkswRuntimeKernelLayout layout
    )
/*++

Routine Description:

    initialize every signed fallback result to the unavailable sentinel.

Arguments:

    Layout - Output scalar layout.

Return Value:

    None.

--*/
{
    LONG* field = NULL;
    SIZE_T index = 0U;

    if (layout == NULL) {
        return;
    }
    field = (LONG*)layout;
    for (index = 0U; index < sizeof(*layout) / sizeof(*field); ++index) {
        field[index] = -1;
    }
}

static BOOLEAN
kswordArkDriverFallbackReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    )
/*++

Routine Description:

    Copy a small kernel-memory scalar or structure through the shared
    MmCopyMemory-based safe reader.

Arguments:

    Address - Candidate source address.
    Buffer - Caller-owned output buffer.
    Size - Exact bounded byte count.

Return Value:

    TRUE when the complete read succeeded; otherwise FALSE.

--*/
{
    // Note: Candidate chain addresses may be unmapped; use MmCopyMemory uniformly to avoid triggering bugcheck 0x50 via direct access.
    return kswordArkRuntimeReadMemory(address, buffer, size);
}

static BOOLEAN
kswordArkDriverFallbackAddressInImage(
    _In_ ULONG_PTR address,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _In_ SIZE_T requiredBytes
    )
/*++

Routine Description:

    Check that an address range is contained by the identity-matched ntoskrnl image.

Arguments:

    Address - Candidate virtual address.
    Identity - Current loaded ntoskrnl identity.
    RequiredBytes - Minimum contained byte count.

Return Value:

    TRUE when the full range is inside the non-wrapping image interval.

--*/
{
    ULONG_PTR imageBase = 0U;
    ULONG_PTR imageEnd = 0U;

    if (identity == NULL || identity->present == 0UL ||
        identity->imageBase == 0ULL || identity->sizeOfImage == 0UL) {
        return FALSE;
    }
    imageBase = (ULONG_PTR)identity->imageBase;
    if (imageBase > MAXULONG_PTR - identity->sizeOfImage) {
        return FALSE;
    }
    imageEnd = imageBase + identity->sizeOfImage;
    if (address < imageBase || address >= imageEnd || requiredBytes > imageEnd - address) {
        return FALSE;
    }
    return TRUE;
}

static PLIST_ENTRY
kswordArkDriverResolveLoadedModuleListExport(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _Out_ LONG* rvaOut
    )
/*++

Routine Description:

    Resolve the exported PsLoadedModuleList data address and validate its
    reciprocal list-head links. The export identity is stronger than a broad
    image signature and remains fully offline.

Arguments:

    Identity - Current loaded ntoskrnl identity.
    RvaOut - Receives the non-negative image RVA when validated.

Return Value:

    Validated list-head address or NULL.

--*/
{
    PLIST_ENTRY listHead = NULL;
    LIST_ENTRY headSnapshot;
    LIST_ENTRY firstSnapshot;
    LIST_ENTRY lastSnapshot;
    ULONG_PTR imageBase = 0U;
    ULONG_PTR address = 0U;

    if (rvaOut == NULL) {
        return NULL;
    }
    *rvaOut = -1;
    if (identity == NULL || identity->imageBase == 0ULL) {
        return NULL;
    }
    imageBase = (ULONG_PTR)identity->imageBase;
    listHead = (PLIST_ENTRY)RtlFindExportedRoutineByName(
        (PVOID)imageBase,
        "PsLoadedModuleList");
    address = (ULONG_PTR)listHead;
    if (listHead == NULL ||
        !kswordArkDriverFallbackAddressInImage(address, identity, sizeof(*listHead)) ||
        !kswordArkDriverFallbackReadMemory(listHead, &headSnapshot, sizeof(headSnapshot)) ||
        headSnapshot.Flink == NULL || headSnapshot.Blink == NULL ||
        !kswordArkDriverFallbackReadMemory(headSnapshot.Flink, &firstSnapshot, sizeof(firstSnapshot)) ||
        !kswordArkDriverFallbackReadMemory(headSnapshot.Blink, &lastSnapshot, sizeof(lastSnapshot)) ||
        firstSnapshot.Blink != listHead || lastSnapshot.Flink != listHead ||
        address - imageBase > MAXLONG) {
        return NULL;
    }
    *rvaOut = (LONG)(address - imageBase);
    return listHead;
}

static BOOLEAN
kswordArkDriverValidateKldrListOffset(
    _In_ const UCHAR* driverSection,
    _In_ ULONG candidateOffset,
    _In_ const LIST_ENTRY* loadedModuleListHead
    )
/*++

Routine Description:

    Walk a candidate KLDR list entry until it reaches PsLoadedModuleList.
    Reciprocal links are checked at every step and the walk is strictly bounded.

Arguments:

    DriverSection - Live KLDR entry stored in DRIVER_OBJECT.DriverSection.
    CandidateOffset - Candidate embedded LIST_ENTRY offset.
    LoadedModuleListHead - Validated exported list head.

Return Value:

    TRUE when the candidate belongs to the exported loaded-module list.

--*/
{
    ULONG_PTR currentAddress = (ULONG_PTR)driverSection + candidateOffset;
    LIST_ENTRY currentEntry;
    ULONG step = 0UL;

    if (driverSection == NULL || loadedModuleListHead == NULL ||
        !kswordArkDriverFallbackReadMemory(
            (const VOID*)currentAddress,
            &currentEntry,
            sizeof(currentEntry))) {
        return FALSE;
    }

    for (step = 0UL; step < KSW_RUNTIME_KLDR_WALK_BUDGET; ++step) {
        ULONG_PTR nextAddress = (ULONG_PTR)currentEntry.Flink;
        LIST_ENTRY nextEntry;

        if (nextAddress == (ULONG_PTR)loadedModuleListHead) {
            if (!kswordArkDriverFallbackReadMemory(
                    loadedModuleListHead,
                    &nextEntry,
                    sizeof(nextEntry)) ||
                (ULONG_PTR)nextEntry.Blink != currentAddress) {
                return FALSE;
            }
            return TRUE;
        }
        if (nextAddress == 0U ||
            !kswordArkDriverFallbackReadMemory(
                (const VOID*)nextAddress,
                &nextEntry,
                sizeof(nextEntry)) ||
            (ULONG_PTR)nextEntry.Blink != currentAddress) {
            return FALSE;
        }
        currentAddress = nextAddress;
        currentEntry = nextEntry;
    }
    return FALSE;
}

static LONG
kswordArkDriverResolveUniqueKldrListOffset(
    _In_ const UCHAR* driverSection,
    _In_ const LIST_ENTRY* loadedModuleListHead
    )
/*++

Routine Description:

    Find the unique embedded KLDR list entry that reaches PsLoadedModuleList.

Arguments:

    DriverSection - Live validation entry.
    LoadedModuleListHead - Validated exported list head.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    for (offset = 0UL;
         offset + sizeof(LIST_ENTRY) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        if (!kswordArkDriverValidateKldrListOffset(
                driverSection,
                offset,
                loadedModuleListHead)) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static LONG
kswordArkDriverResolveUniquePointerField(
    _In_reads_bytes_(KSW_RUNTIME_KLDR_SCAN_BYTES) const UCHAR* object,
    _In_ ULONG_PTR expectedValue
    )
/*++

Routine Description:

    Find one unique pointer-sized field equal to a trusted live value.

Arguments:

    Object - Bounded object body.
    ExpectedValue - Trusted pointer value expected in the object.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (object == NULL || expectedValue == 0U) {
        return -1;
    }
    for (offset = 0UL;
         offset + sizeof(ULONG_PTR) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR value = 0U;

        if (!kswordArkDriverFallbackReadMemory(object + offset, &value, sizeof(value)) ||
            value != expectedValue) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static LONG
kswordArkDriverResolveKldrSizeField(
    _In_reads_bytes_(KSW_RUNTIME_KLDR_SCAN_BYTES) const UCHAR* driverSection,
    _In_ LONG dllBaseOffset,
    _In_ ULONG expectedSize
    )
/*++

Routine Description:

    Find the unique image-size scalar immediately following the validated DllBase field.

Arguments:

    DriverSection - Live KLDR entry.
    DllBaseOffset - Previously validated DllBase field offset.
    ExpectedSize - DRIVER_OBJECT.DriverSize value.

Return Value:

    Non-negative unique offset or -1.

--*/
{
    ULONG startOffset = 0UL;
    ULONG endOffset = 0UL;
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (driverSection == NULL || dllBaseOffset < 0 || expectedSize == 0UL) {
        return -1;
    }
    startOffset = (ULONG)dllBaseOffset + (ULONG)sizeof(PVOID);
    endOffset = startOffset + 0x20UL;
    if (endOffset > KSW_RUNTIME_KLDR_SCAN_BYTES - sizeof(ULONG)) {
        endOffset = KSW_RUNTIME_KLDR_SCAN_BYTES - sizeof(ULONG);
    }
    for (offset = startOffset; offset <= endOffset; offset += sizeof(ULONG)) {
        ULONG value = 0UL;

        if (!kswordArkDriverFallbackReadMemory(driverSection + offset, &value, sizeof(value)) ||
            value != expectedSize) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

static BOOLEAN
kswordArkDriverReadKldrUnicodeString(
    _In_ const UCHAR* driverSection,
    _In_ ULONG offset,
    _Out_ UNICODE_STRING* stringOut
    )
/*++

Routine Description:

    Read and bound one candidate KLDR UNICODE_STRING descriptor.

Arguments:

    DriverSection - Live KLDR entry.
    Offset - Candidate descriptor offset.
    StringOut - Receives the validated descriptor.

Return Value:

    TRUE when lengths and backing storage are readable and bounded.

--*/
{
    WCHAR probe = L'\0';

    if (driverSection == NULL || stringOut == NULL ||
        offset + sizeof(*stringOut) > KSW_RUNTIME_KLDR_SCAN_BYTES) {
        return FALSE;
    }
    RtlZeroMemory(stringOut, sizeof(*stringOut));
    if (!kswordArkDriverFallbackReadMemory(
            driverSection + offset,
            stringOut,
            sizeof(*stringOut)) ||
        stringOut->Buffer == NULL || stringOut->Length == 0U ||
        (stringOut->Length & 1U) != 0U ||
        stringOut->MaximumLength < stringOut->Length ||
        stringOut->MaximumLength > KSW_RUNTIME_KLDR_NAME_CHARS * sizeof(WCHAR) ||
        !kswordArkDriverFallbackReadMemory(stringOut->Buffer, &probe, sizeof(probe)) ||
        !kswordArkDriverFallbackReadMemory(
            (const UCHAR*)stringOut->Buffer + stringOut->Length - sizeof(WCHAR),
            &probe,
            sizeof(probe))) {
        RtlZeroMemory(stringOut, sizeof(*stringOut));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkDriverKldrNamesMatch(
    _In_ const UNICODE_STRING* fullName,
    _In_ const UNICODE_STRING* baseName
    )
/*++

Routine Description:

    Verify that BaseName is a path-free, case-insensitive suffix of FullName.

Arguments:

    FullName - Candidate full module path.
    BaseName - Candidate base module name.

Return Value:

    TRUE when the relationship and both backing buffers validate.

--*/
{
    UNICODE_STRING suffix;
    USHORT index = 0U;
    BOOLEAN fullHasSeparator = FALSE;

    if (fullName == NULL || baseName == NULL ||
        fullName->Length <= baseName->Length || baseName->Length < 4U) {
        return FALSE;
    }
    __try {
        for (index = 0U; index < fullName->Length / sizeof(WCHAR); ++index) {
            if (fullName->Buffer[index] == L'\\' || fullName->Buffer[index] == L'/') {
                fullHasSeparator = TRUE;
                break;
            }
        }
        for (index = 0U; index < baseName->Length / sizeof(WCHAR); ++index) {
            if (baseName->Buffer[index] == L'\\' || baseName->Buffer[index] == L'/') {
                return FALSE;
            }
        }
        suffix.Length = baseName->Length;
        suffix.MaximumLength = baseName->Length;
        suffix.Buffer = fullName->Buffer +
            ((fullName->Length - baseName->Length) / sizeof(WCHAR));
        return (fullHasSeparator && RtlEqualUnicodeString(&suffix, baseName, TRUE))
            ? TRUE
            : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static VOID
kswordArkDriverResolveKldrNameOffsets(
    _In_ const UCHAR* driverSection,
    _Out_ LONG* fullNameOffsetOut,
    _Out_ LONG* baseNameOffsetOut
    )
/*++

Routine Description:

    Find a unique full-path/base-name UNICODE_STRING pair in a live KLDR entry.

Arguments:

    DriverSection - Live validation entry.
    FullNameOffsetOut - Receives the full-name descriptor offset.
    BaseNameOffsetOut - Receives the base-name descriptor offset.

Return Value:

    None. Both outputs remain unavailable unless exactly one pair validates.

--*/
{
    ULONG fullOffset = 0UL;
    LONG foundFullOffset = -1;
    LONG foundBaseOffset = -1;

    if (fullNameOffsetOut == NULL || baseNameOffsetOut == NULL) {
        return;
    }
    *fullNameOffsetOut = -1;
    *baseNameOffsetOut = -1;

    for (fullOffset = 0UL;
         fullOffset + sizeof(UNICODE_STRING) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
         fullOffset += (ULONG)sizeof(PVOID)) {
        UNICODE_STRING fullName;
        ULONG baseOffset = 0UL;

        if (!kswordArkDriverReadKldrUnicodeString(driverSection, fullOffset, &fullName)) {
            continue;
        }
        for (baseOffset = 0UL;
             baseOffset + sizeof(UNICODE_STRING) <= KSW_RUNTIME_KLDR_SCAN_BYTES;
             baseOffset += (ULONG)sizeof(PVOID)) {
            UNICODE_STRING baseName;

            if (baseOffset == fullOffset ||
                !kswordArkDriverReadKldrUnicodeString(driverSection, baseOffset, &baseName) ||
                !kswordArkDriverKldrNamesMatch(&fullName, &baseName)) {
                continue;
            }
            if (foundFullOffset >= 0) {
                return;
            }
            foundFullOffset = (LONG)fullOffset;
            foundBaseOffset = (LONG)baseOffset;
        }
    }

    *fullNameOffsetOut = foundFullOffset;
    *baseNameOffsetOut = foundBaseOffset;
}

static VOID
kswordArkDriverResolvePublicDriverObjectLayout(
    _In_opt_ PDRIVER_OBJECT validationDriverObject,
    _Inout_ PkswRuntimeKernelLayout layout
    )
/*++

Routine Description:

    Publish WDK-defined DRIVER_OBJECT member offsets after cross-checking a live object.

Arguments:

    ValidationDriverObject - Live KSword driver object.
    Layout - Mutable fallback result.

Return Value:

    None.

--*/
{
    PVOID driverStart = NULL;
    ULONG driverSize = 0UL;

    if (validationDriverObject == NULL || layout == NULL ||
        !kswordArkDriverFallbackReadMemory(
            &validationDriverObject->DriverStart,
            &driverStart,
            sizeof(driverStart)) ||
        !kswordArkDriverFallbackReadMemory(
            &validationDriverObject->DriverSize,
            &driverSize,
            sizeof(driverSize)) ||
        driverStart == NULL || driverSize == 0UL) {
        return;
    }

    layout->doDriverStart = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverStart);
    layout->doDriverSize = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSize);
    layout->doDriverSection = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSection);
    layout->doMajorFunction = (LONG)FIELD_OFFSET(DRIVER_OBJECT, MajorFunction);
    layout->doFastIoDispatch = (LONG)FIELD_OFFSET(DRIVER_OBJECT, FastIoDispatch);
    layout->doDriverUnload = (LONG)FIELD_OFFSET(DRIVER_OBJECT, DriverUnload);
}

static VOID
kswordArkDriverResolvePublicAvlLayout(
    _Inout_ PkswRuntimeKernelLayout layout
    )
/*++

Routine Description:

    Publish WDK-defined RTL_AVL_TABLE offsets and exact public type size.

Arguments:

    Layout - Mutable fallback result.

Return Value:

    None.

--*/
{
    if (layout == NULL) {
        return;
    }
    layout->rtlAvlBalancedRoot = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, BalancedRoot);
    layout->rtlAvlOrderedPointer = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, OrderedPointer);
    layout->rtlAvlWhichOrderedElement = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, WhichOrderedElement);
    layout->rtlAvlNumberGenericTableElements =
        (LONG)FIELD_OFFSET(RTL_AVL_TABLE, NumberGenericTableElements);
    layout->rtlAvlDepthOfTree = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, DepthOfTree);
    layout->rtlAvlRestartKey = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, RestartKey);
    layout->rtlAvlDeleteCount = (LONG)FIELD_OFFSET(RTL_AVL_TABLE, DeleteCount);
    layout->rtlAvlTypeSize = (LONG)sizeof(RTL_AVL_TABLE);
}

VOID
kswordArkDriverResolveKernelFallbackLayout(
    _In_opt_ PDRIVER_OBJECT validationDriverObject,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity,
    _Out_ PkswRuntimeKernelLayout layoutOut
    )
/*++

Routine Description:

    Resolve all currently supported non-PDB kernel layout facts in one pass.
    PDB data remains preferred by the caller; these results fill only missing
    fields and carry runtime-pattern provenance.

Arguments:

    ValidationDriverObject - Live KSword driver object used for structure checks.
    NtoskrnlIdentity - Current loaded ntoskrnl image identity.
    LayoutOut - Receives signed offsets and RVAs.

Return Value:

    None.

--*/
{
    PLIST_ENTRY loadedModuleList = NULL;
    const UCHAR* driverSection = NULL;

    if (layoutOut == NULL) {
        return;
    }
    kswordArkDriverInitializeKernelFallbackLayout(layoutOut);
    kswordArkDriverResolvePublicDriverObjectLayout(validationDriverObject, layoutOut);
    kswordArkDriverResolvePublicAvlLayout(layoutOut);
    kswordArkDriverResolveKernelCacheFallback(ntoskrnlIdentity, layoutOut);
    layoutOut->keServiceDescriptorTableShadowRva =
        kswordArkDriverResolveShadowSsdtRva(ntoskrnlIdentity);

    loadedModuleList = kswordArkDriverResolveLoadedModuleListExport(
        ntoskrnlIdentity,
        &layoutOut->psLoadedModuleListRva);
    if (validationDriverObject == NULL || loadedModuleList == NULL) {
        return;
    }
    driverSection = (const UCHAR*)validationDriverObject->DriverSection;
    if (driverSection == NULL || validationDriverObject->DriverStart == NULL ||
        validationDriverObject->DriverSize == 0UL) {
        return;
    }

    layoutOut->kldrInLoadOrderLinks = kswordArkDriverResolveUniqueKldrListOffset(
        driverSection,
        loadedModuleList);
    layoutOut->kldrDllBase = kswordArkDriverResolveUniquePointerField(
        driverSection,
        (ULONG_PTR)validationDriverObject->DriverStart);
    layoutOut->kldrSizeOfImage = kswordArkDriverResolveKldrSizeField(
        driverSection,
        layoutOut->kldrDllBase,
        validationDriverObject->DriverSize);
    kswordArkDriverResolveKldrNameOffsets(
        driverSection,
        &layoutOut->kldrFullDllName,
        &layoutOut->kldrBaseDllName);
}
