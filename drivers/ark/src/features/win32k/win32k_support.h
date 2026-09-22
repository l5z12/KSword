#pragma once

#include "ark/ark_driver.h"
#include "ark/ark_ioctl.h"
#include "../kernel/hook_scan_support.h"

typedef PEPROCESS(NTAPI* KswordWiN32KPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef PETHREAD(NTAPI* KswordWiN32KPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef PVOID(NTAPI* KswordWiN32KPsGetThreadWiN32ThreadFn)(
    _In_ PETHREAD thread
    );

typedef ULONG(NTAPI* KswordWiN32KPsGetProcessSessionIdFn)(
    _In_ PEPROCESS process
    );

typedef struct KswordArkWiN32KGuiThreadMapEntry
{
    ULONG64 threadInfo;
    ULONG processId;
    ULONG threadId;
    ULONG sessionId;
} KswordArkWiN32KGuiThreadMapEntry;

// Each private Win32k layout entry must place this identity structure as the first field.
// Windows version is used for 'most recent previous version' sorting; PE identity is used for precise matching.
typedef struct KswordArkWiN32KLayoutProfileIdentity
{
    ULONG windowsMajorVersion;
    ULONG windowsMinorVersion;
    ULONG windowsBuildNumber;
    ULONG windowsRevision;
    ULONG win32kbaseTimeDateStamp;
    ULONG win32kbaseImageSize;
    ULONG win32kfullTimeDateStamp;
    ULONG win32kfullImageSize;
} KswordArkWiN32KLayoutProfileIdentity;

typedef struct KswordArkWiN32KLayoutSelection
{
    ULONG profileIndex;
    ULONG source;
    ULONG currentWindowsMajorVersion;
    ULONG currentWindowsMinorVersion;
    ULONG currentWindowsBuildNumber;
    ULONG currentWindowsRevision;
    KswordArkWiN32KLayoutProfileIdentity selectedIdentity;
} KswordArkWiN32KLayoutSelection;

#define KSWORD_ARK_WIN32K_LAYOUT_SELECTION_NONE             0UL
#define KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY   1UL
#define KSWORD_ARK_WIN32K_LAYOUT_SELECTION_NEAREST_PREVIOUS 2UL

BOOLEAN
kswordArkWin32kSelectLayoutProfile(
    _In_reads_bytes_(profileCount * profileStride) const VOID* profileTable,
    _In_ ULONG profileCount,
    _In_ SIZE_T profileStride,
    _In_ ULONG currentWin32kbaseTimeDateStamp,
    _In_ ULONG currentWin32kbaseImageSize,
    _In_ ULONG currentWin32kfullTimeDateStamp,
    _In_ ULONG currentWin32kfullImageSize,
    _Out_ KswordArkWiN32KLayoutSelection* selection
    );

VOID
kswordArkWin32kInitializeOffsets(
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* offsets
    );

ULONG
kswordArkWin32kNormalizeMaxEntries(
    _In_ ULONG requestedMaxEntries
    );

VOID
kswordArkWin32kCopyWideText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_z_ PCWSTR source
    );

KswordWiN32KPsGetNextProcessFn
kswordArkWin32kResolvePsGetNextProcess(
    VOID
    );

KswordWiN32KPsGetNextProcessThreadFn
kswordArkWin32kResolvePsGetNextProcessThread(
    VOID
    );

KswordWiN32KPsGetThreadWiN32ThreadFn
kswordArkWin32kResolvePsGetThreadWin32Thread(
    VOID
    );

KswordWiN32KPsGetProcessSessionIdFn
kswordArkWin32kResolvePsGetProcessSessionId(
    VOID
    );

NTSTATUS
kswordArkWin32kBuildGuiThreadMap(
    _In_ ULONG maximumEntries,
    _In_ ULONG poolTag,
    _Outptr_result_buffer_(*countOut) KswordArkWiN32KGuiThreadMapEntry** mapOut,
    _Out_ ULONG* countOut,
    _Out_ BOOLEAN* truncatedOut
    );

BOOLEAN
kswordArkWin32kFindModuleByName(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCSTR moduleName,
    _Out_ KswHookSystemModuleEntry* moduleEntryOut
    );

VOID
kswordArkWin32kFillModuleState(
    _Out_ KSWORD_ARK_WIN32K_MODULE_STATE* moduleState,
    _In_z_ PCWSTR moduleName,
    _In_ BOOLEAN loaded,
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry
    );

ULONG64
kswordArkWin32kModuleCapabilityMask(
    _In_ BOOLEAN win32kLoaded,
    _In_ BOOLEAN win32kbaseLoaded,
    _In_ BOOLEAN win32kfullLoaded,
    _In_opt_ const KswHookSystemModuleEntry* win32kbaseEntry,
    _Out_ ULONG64* missingCapabilityMaskOut,
    _Out_ ULONG64* userGetSiloGlobalsOut
    );

VOID
kswordArkWin32kCollectSessionSummary(
    _Inout_ KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request
    );
