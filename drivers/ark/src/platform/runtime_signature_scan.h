#pragma once

#include <ntddk.h>

EXTERN_C_START

#define KSW_RUNTIME_IMAGE_MAX_SECTIONS 64UL
#define KSW_RUNTIME_SIGNATURE_MAX_ROUTINES 64UL

typedef struct KswRuntimeImageSection
{
    ULONG_PTR start;
    ULONG_PTR end;
    ULONG characteristics;
} KswRuntimeImageSection, *PkswRuntimeImageSection;

typedef struct KswRuntimeImageView
{
    ULONG_PTR base;
    ULONG size;
    ULONG sectionCount;
    KswRuntimeImageSection sections[KSW_RUNTIME_IMAGE_MAX_SECTIONS];
} KswRuntimeImageView, *PkswRuntimeImageView;

typedef struct KswRuntimeDataReference
{
    ULONG_PTR address;
    ULONG_PTR routineAddress;
    ULONG_PTR instructionAddress;
} KswRuntimeDataReference, *PkswRuntimeDataReference;

BOOLEAN
kswordArkRuntimeReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    );

BOOLEAN
kswordArkRuntimeInitializeImageView(
    _In_ PVOID imageBase,
    _In_ ULONG imageSize,
    _Out_ PkswRuntimeImageView viewOut
    );

BOOLEAN
kswordArkRuntimeAddressInImage(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    );

BOOLEAN
kswordArkRuntimeAddressIsExecutable(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    );

BOOLEAN
kswordArkRuntimeAddressIsWritableData(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    );

PVOID
kswordArkRuntimeFindExport(
    _In_ const KswRuntimeImageView* view,
    _In_z_ PCSTR exportName
    );

ULONG
kswordArkRuntimeCollectAnchoredDataReferences(
    _In_ const KswRuntimeImageView* view,
    _In_reads_(anchorCount) PCSTR const* anchorNames,
    _In_ ULONG anchorCount,
    _In_ ULONG maxCallDepth,
    _In_ ULONG routineScanBytes,
    _Out_writes_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity
    );

ULONG
kswordArkRuntimeCollectExecutableDataReferences(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG scanByteBudget,
    _Out_writes_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity
    );

EXTERN_C_END
