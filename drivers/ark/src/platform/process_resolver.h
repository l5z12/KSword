#pragma once

#include "ark/ark_driver.h"

typedef NTSTATUS(NTAPI* KswordPsSuspendProcessFn)(
    _In_ PEPROCESS process
    );

typedef BOOLEAN(NTAPI* KswordPsIsProtectedProcessFn)(
    _In_ PEPROCESS process
    );

typedef BOOLEAN(NTAPI* KswordPsIsProtectedProcessLightFn)(
    _In_ PEPROCESS process
    );

typedef NTSTATUS(NTAPI* KswordZwOrNtSuspendProcessFn)(
    _In_ HANDLE processHandle
    );

typedef NTSTATUS(NTAPI* KswordPsResumeProcessFn)(
    _In_ PEPROCESS process
    );

typedef NTSTATUS(NTAPI* KswordZwOrNtResumeProcessFn)(
    _In_ HANDLE processHandle
    );

typedef NTSTATUS(NTAPI* KswordZwSetInformationProcessFn)(
    _In_ HANDLE processHandle,
    _In_ ULONG processInformationClass,
    _In_reads_bytes_(processInformationLength) PVOID processInformation,
    _In_ ULONG processInformationLength
    );

// KswordRuntimeDyndataOffsets carries only offsets recovered from exported
// read-only accessors and validated against live process/thread objects.
// A negative member is unavailable; callers must preserve stronger SI/PDB data.
typedef struct KswordRuntimeDyndataOffsets
{
    LONG epUniqueProcessId;
    LONG epActiveProcessLinks;
    LONG epThreadListHead;
    LONG epImageFileName;
    LONG epToken;
    LONG epFlags;
    LONG epCreateTime;
    LONG epExitStatus;
    LONG epPeb;
    LONG epWin32Process;
    LONG epWow64Process;
    LONG epInheritedFromUniqueProcessId;
    LONG epSectionBaseAddress;
    LONG epJob;
    LONG epDebugPort;
    LONG epPriorityClass;
    LONG epActiveThreads;
    LONG epWin32WindowStation;
    LONG epSecurityPort;
    LONG tokUserAndGroupCount;
    LONG tokUserAndGroups;
    LONG tokIntegrityLevelIndex;
    LONG tokMandatoryPolicy;
    LONG etCid;
    LONG etThreadListEntry;
    LONG etStartAddress;
    LONG etWin32StartAddress;
    LONG ktProcess;
    LONG ktInitialStack;
    LONG ktStackLimit;
    LONG ktStackBase;
} KswordRuntimeDyndataOffsets, *PkswordRuntimeDyndataOffsets;

KswordPsSuspendProcessFn
kswordArkDriverResolvePsSuspendProcess(
    VOID
    );

KswordZwOrNtSuspendProcessFn
kswordArkDriverResolveZwOrNtSuspendProcess(
    VOID
    );

KswordPsResumeProcessFn
kswordArkDriverResolvePsResumeProcess(
    VOID
    );

KswordZwOrNtResumeProcessFn
kswordArkDriverResolveZwOrNtResumeProcess(
    VOID
    );

KswordPsIsProtectedProcessFn
kswordArkDriverResolvePsIsProtectedProcess(
    VOID
    );

KswordPsIsProtectedProcessLightFn
kswordArkDriverResolvePsIsProtectedProcessLight(
    VOID
    );

LONG
kswordArkDriverResolveProcessProtectionOffset(
    VOID
    );

LONG
kswordArkDriverResolveProcessSignatureLevelOffset(
    VOID
    );

LONG
kswordArkDriverResolveProcessSectionSignatureLevelOffset(
    VOID
    );

LONG
kswordArkDriverResolveProcessFlagsOffset(
    _In_ PEPROCESS process
    );

LONG
kswordArkDriverResolveProcessSectionObjectOffset(
    VOID
    );

LONG
kswordArkDriverResolveProcessObjectTableOffset(
    VOID
    );

VOID
kswordArkDriverResolveReadOnlyDynDataOffsets(
    _Out_ PkswordRuntimeDyndataOffsets offsets
    );

KswordZwSetInformationProcessFn
kswordArkDriverResolveZwSetInformationProcess(
    VOID
    );
