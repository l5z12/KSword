#pragma once

#include "ark/ark_driver.h"
#include "hook_scan_support.h"

EXTERN_C_START

typedef struct KswDriverIntegrityBuilder
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response;
    ULONG capacity;
    ULONG rowLimit;
} KswDriverIntegrityBuilder, *PkswDriverIntegrityBuilder;

typedef struct KswDriverIntegrityLdrTarget
{
    BOOLEAN available;
    BOOLEAN found;
    ULONGLONG listHeadAddress;
    ULONGLONG entryAddress;
    ULONGLONG linkAddress;
    ULONGLONG dllBase;
    ULONG sizeOfImage;
    WCHAR baseDllName[KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS];
} KswDriverIntegrityLdrTarget, *PkswDriverIntegrityLdrTarget;

KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*
kswordArkDriverIntegrityAddEvidence(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ ULONG evidenceClass,
    _In_ ULONGLONG objectAddress,
    _In_ ULONGLONG targetAddress,
    _In_ ULONG riskFlags,
    _In_ ULONG sourceMask,
    _In_ ULONG confidence,
    _In_ ULONG processorGroup,
    _In_ ULONG processorNumber,
    _In_ ULONG vector,
    _In_opt_ const KswHookSystemModuleEntry* ownerModule,
    _In_opt_z_ PCWSTR detailText
    );

const KswHookSystemModuleEntry*
kswordArkDriverIntegrityFindModuleForAddress(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG address
    );

BOOLEAN
kswordArkDriverIntegrityIsCoreKernelModule(
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry
    );

VOID
kswordArkDriverIntegrityCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    );

BOOLEAN
kswordArkDriverIntegrityOffsetPresent(
    _In_ ULONG offset
    );

ULONGLONG
kswordArkDriverIntegrityNtosAddressFromRva(
    _In_ const KswDynState* dynState,
    _In_ ULONG rva,
    _In_ SIZE_T probeBytes
    );

NTSTATUS
kswordArkDriverIntegrityFindLoadedModule(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG driverStart,
    _Out_ KswDriverIntegrityLdrTarget* targetOut
    );

EXTERN_C_END
