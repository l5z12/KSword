/*++

Module Name:

    win32k_support.c

Abstract:

    Shared helper routines for read-only win32k GUI audit collectors.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_support.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_WIN32K_SYSTEM_PROCESS_INFORMATION_CLASS 5UL
#define KSWORD_ARK_WIN32K_PROCESS_SNAPSHOT_SLACK (64UL * 1024UL)
#define KSWORD_ARK_WIN32K_PROCESS_SNAPSHOT_LIMIT (64UL * 1024UL * 1024UL)

typedef struct KswordArkWiN32KSystemThreadInformation
{
    LARGE_INTEGER kernelTime;
    LARGE_INTEGER userTime;
    LARGE_INTEGER createTime;
    ULONG waitTime;
    PVOID startAddress;
    CLIENT_ID clientId;
    KPRIORITY priority;
    LONG basePriority;
    ULONG contextSwitches;
    ULONG threadState;
    ULONG waitReason;
} KswordArkWiN32KSystemThreadInformation;

typedef struct KswordArkWiN32KSystemProcessInformation
{
    ULONG nextEntryOffset;
    ULONG numberOfThreads;
    UCHAR reserved1[48];
    UNICODE_STRING imageName;
    KPRIORITY basePriority;
    HANDLE uniqueProcessId;
    PVOID reserved2;
    ULONG handleCount;
    ULONG sessionId;
    PVOID reserved3;
    SIZE_T peakVirtualSize;
    SIZE_T virtualSize;
    ULONG reserved4;
    SIZE_T peakWorkingSetSize;
    SIZE_T workingSetSize;
    PVOID reserved5;
    SIZE_T quotaPagedPoolUsage;
    PVOID reserved6;
    SIZE_T quotaNonPagedPoolUsage;
    SIZE_T pagefileUsage;
    SIZE_T peakPagefileUsage;
    SIZE_T privatePageCount;
    LARGE_INTEGER reserved7[6];
    KswordArkWiN32KSystemThreadInformation threads[1];
} KswordArkWiN32KSystemProcessInformation;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_z_ PCSTR routineName
    );

static BOOLEAN
kswordArkWin32kQueryWindowsRevision(
    _Out_ ULONG* revisionOut
    )
{
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    UCHAR valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer;
    ULONG resultLength = 0UL;
    ULONG revision = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (revisionOut == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    *revisionOut = 0UL;

    RtlInitUnicodeString(
        &keyName,
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    RtlInitUnicodeString(&valueName, L"UBR");
    InitializeObjectAttributes(
        &attributes,
        &keyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueBuffer,
        sizeof(valueBuffer),
        &resultLength);
    ZwClose(keyHandle);
    if (!NT_SUCCESS(status) ||
        resultLength < FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG) ||
        valueInfo->Type != REG_DWORD ||
        valueInfo->DataLength < sizeof(ULONG)) {
        return FALSE;
    }

    RtlCopyMemory(&revision, valueInfo->Data, sizeof(revision));
    *revisionOut = revision;
    return TRUE;
}

static LONG
kswordArkWin32kCompareProfileVersions(
    _In_ const KswordArkWiN32KLayoutProfileIdentity* Left,
    _In_ const KswordArkWiN32KLayoutProfileIdentity* Right
    )
{
#define KSW_COMPARE_PROFILE_FIELD(FieldName) \
    if (Left->FieldName < Right->FieldName) { return -1; } \
    if (Left->FieldName > Right->FieldName) { return 1; }
    KSW_COMPARE_PROFILE_FIELD(windowsMajorVersion);
    KSW_COMPARE_PROFILE_FIELD(windowsMinorVersion);
    KSW_COMPARE_PROFILE_FIELD(windowsBuildNumber);
    KSW_COMPARE_PROFILE_FIELD(windowsRevision);
#undef KSW_COMPARE_PROFILE_FIELD
    return 0;
}

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
    )
/*++

Routine Description:

    Select an exact Win32k PE layout first. If no exact identity exists, use
    the newest profile whose Windows version is not newer than the running
    system. PE timestamps are deliberately not ordered because modern Windows
    images use reproducible-build hashes rather than chronological timestamps.

--*/
{
    const UCHAR* profileBytes = (const UCHAR*)profileTable;
    KswordArkWiN32KLayoutProfileIdentity currentVersion;
    const KswordArkWiN32KLayoutProfileIdentity* bestProfile = NULL;
    ULONG bestIndex = 0UL;
    ULONG index = 0UL;

    if (profileTable == NULL || profileCount == 0UL ||
        profileStride < sizeof(KswordArkWiN32KLayoutProfileIdentity) ||
        selection == NULL) {
        return FALSE;
    }
    RtlZeroMemory(selection, sizeof(*selection));

    for (index = 0UL; index < profileCount; ++index) {
        const KswordArkWiN32KLayoutProfileIdentity* profile =
            (const KswordArkWiN32KLayoutProfileIdentity*)(profileBytes +
                ((SIZE_T)index * profileStride));
        if (profile->win32kbaseTimeDateStamp == currentWin32kbaseTimeDateStamp &&
            profile->win32kbaseImageSize == currentWin32kbaseImageSize &&
            profile->win32kfullTimeDateStamp == currentWin32kfullTimeDateStamp &&
            profile->win32kfullImageSize == currentWin32kfullImageSize) {
            selection->profileIndex = index;
            selection->source = KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY;
            selection->selectedIdentity = *profile;
            (VOID)PsGetVersion(
                &selection->currentWindowsMajorVersion,
                &selection->currentWindowsMinorVersion,
                &selection->currentWindowsBuildNumber,
                NULL);
            (VOID)kswordArkWin32kQueryWindowsRevision(
                &selection->currentWindowsRevision);
            return TRUE;
        }
    }

    RtlZeroMemory(&currentVersion, sizeof(currentVersion));
    (VOID)PsGetVersion(
        &currentVersion.windowsMajorVersion,
        &currentVersion.windowsMinorVersion,
        &currentVersion.windowsBuildNumber,
        NULL);
    if (!kswordArkWin32kQueryWindowsRevision(&currentVersion.windowsRevision)) {
        currentVersion.windowsRevision = MAXULONG;
    }
    if (currentVersion.windowsMajorVersion == 0UL ||
        currentVersion.windowsBuildNumber == 0UL) {
        return FALSE;
    }

    for (index = 0UL; index < profileCount; ++index) {
        const KswordArkWiN32KLayoutProfileIdentity* profile =
            (const KswordArkWiN32KLayoutProfileIdentity*)(profileBytes +
                ((SIZE_T)index * profileStride));
        if (kswordArkWin32kCompareProfileVersions(profile, &currentVersion) > 0) {
            continue;
        }
        if (bestProfile == NULL ||
            kswordArkWin32kCompareProfileVersions(profile, bestProfile) >= 0) {
            bestProfile = profile;
            bestIndex = index;
        }
    }
    if (bestProfile == NULL) {
        return FALSE;
    }

    selection->profileIndex = bestIndex;
    selection->source = KSWORD_ARK_WIN32K_LAYOUT_SELECTION_NEAREST_PREVIOUS;
    selection->currentWindowsMajorVersion = currentVersion.windowsMajorVersion;
    selection->currentWindowsMinorVersion = currentVersion.windowsMinorVersion;
    selection->currentWindowsBuildNumber = currentVersion.windowsBuildNumber;
    selection->currentWindowsRevision = currentVersion.windowsRevision;
    selection->selectedIdentity = *bestProfile;
    return TRUE;
}

VOID
kswordArkWin32kInitializeOffsets(
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* offsets
    )
/*++

Routine Description:

    Fill every Win32k private-field offset with the shared unavailable sentinel.

Arguments:

    Offsets - Receives an initialized offset packet.

Return Value:

    None. NULL input is ignored.

--*/
{
    if (offsets == NULL) {
        return;
    }

    RtlFillMemory(offsets, sizeof(*offsets), 0xFF);
}

ULONG
kswordArkWin32kNormalizeMaxEntries(
    _In_ ULONG requestedMaxEntries
    )
/*++

Routine Description:

    normalize caller supplied traversal limits for all Win32k snapshots.

Arguments:

    RequestedMaxEntries - Optional caller budget.

Return Value:

    A bounded entry count that is never zero.

--*/
{
    if (requestedMaxEntries == 0UL) {
        return KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    }
    if (requestedMaxEntries > KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES) {
        return KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES;
    }
    return requestedMaxEntries;
}

VOID
kswordArkWin32kCopyWideText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_z_ PCWSTR source
    )
/*++

Routine Description:

    Copy a constant WCHAR string into a fixed protocol field.

Arguments:

    Destination - Protocol text field.
    DestinationChars - Protocol text field capacity in WCHARs.
    Source - Constant source string.

Return Value:

    None. The output is always terminated when capacity is nonzero.

--*/
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyW(destination, destinationChars, source);
    destination[destinationChars - 1UL] = L'\0';
}

KswordWiN32KPsGetNextProcessFn
kswordArkWin32kResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically for read-only process walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswordWiN32KPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

KswordWiN32KPsGetNextProcessThreadFn
kswordArkWin32kResolvePsGetNextProcessThread(
    VOID
    )
/*++

Routine Description:

    Resolve psGetNextProcessThread dynamically for read-only thread walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswordWiN32KPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

KswordWiN32KPsGetThreadWiN32ThreadFn
kswordArkWin32kResolvePsGetThreadWin32Thread(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetThreadWin32Thread for safe GUI-thread discovery.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetThreadWin32Thread");
    return (KswordWiN32KPsGetThreadWiN32ThreadFn)MmGetSystemRoutineAddress(&routineName);
}

KswordWiN32KPsGetProcessSessionIdFn
kswordArkWin32kResolvePsGetProcessSessionId(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetProcessSessionId so session labels remain optional and fail-soft.

Arguments:

    None.

Return Value:

    Function pointer when exported; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetProcessSessionId");
    return (KswordWiN32KPsGetProcessSessionIdFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkWin32kCaptureProcessSnapshot(
    _Outptr_result_bytebuffer_(*snapshotBytesOut) PVOID* snapshotOut,
    _Out_ ULONG* snapshotBytesOut
    )
{
    PVOID snapshot = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG returnedBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (snapshotOut == NULL || snapshotBytesOut == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;
    *snapshotBytesOut = 0UL;

    status = ZwQuerySystemInformation(
        KSWORD_ARK_WIN32K_SYSTEM_PROCESS_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        !NT_SUCCESS(status)) {
        return status;
    }

    for (attempt = 0UL; attempt < 3UL; ++attempt) {
        if (requiredBytes < sizeof(KswordArkWiN32KSystemProcessInformation)) {
            requiredBytes = 256UL * 1024UL;
        }
        if (requiredBytes > KSWORD_ARK_WIN32K_PROCESS_SNAPSHOT_LIMIT ||
            requiredBytes > MAXULONG - KSWORD_ARK_WIN32K_PROCESS_SNAPSHOT_SLACK) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + KSWORD_ARK_WIN32K_PROCESS_SNAPSHOT_SLACK;
        snapshot = kswordArkAllocateNonPagedPool(
            allocationBytes,
            'sWkW');
        if (snapshot == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);

        returnedBytes = 0UL;
        status = ZwQuerySystemInformation(
            KSWORD_ARK_WIN32K_SYSTEM_PROCESS_INFORMATION_CLASS,
            snapshot,
            allocationBytes,
            &returnedBytes);
        if (NT_SUCCESS(status)) {
            if (returnedBytes == 0UL || returnedBytes > allocationBytes) {
                returnedBytes = allocationBytes;
            }
            *snapshotOut = snapshot;
            *snapshotBytesOut = returnedBytes;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(snapshot, 'sWkW');
        snapshot = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            return status;
        }
        requiredBytes = returnedBytes > allocationBytes
            ? returnedBytes
            : allocationBytes;
    }

    return status;
}

NTSTATUS
kswordArkWin32kBuildGuiThreadMap(
    _In_ ULONG maximumEntries,
    _In_ ULONG poolTag,
    _Outptr_result_buffer_(*countOut) KswordArkWiN32KGuiThreadMapEntry** mapOut,
    _Out_ ULONG* countOut,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Build a bounded map from PsGetThreadWin32Thread values to PID, TID and
    Session ID. Older kernels with public process walkers use those walkers.
    Current kernels that do not export PsGetNextProcess fall back to the stable
    SystemProcessInformation PID/TID snapshot and PsLookupThreadByThreadId.

--*/
{
    KswordWiN32KPsGetNextProcessFn psGetNextProcess = NULL;
    KswordWiN32KPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordWiN32KPsGetThreadWiN32ThreadFn psGetThreadWin32Thread = NULL;
    KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId = NULL;
    KswordArkWiN32KGuiThreadMapEntry* map = NULL;
    ULONG count = 0UL;
    BOOLEAN truncated = FALSE;

    if (mapOut == NULL || countOut == NULL || truncatedOut == NULL ||
        maximumEntries == 0UL ||
        maximumEntries > MAXULONG / sizeof(*map) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *mapOut = NULL;
    *countOut = 0UL;
    *truncatedOut = FALSE;

    map = (KswordArkWiN32KGuiThreadMapEntry*)kswordArkAllocateNonPagedPool(
        sizeof(*map) * maximumEntries,
        poolTag);
    if (map == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(map, sizeof(*map) * maximumEntries);

    psGetNextProcess = kswordArkWin32kResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkWin32kResolvePsGetNextProcessThread();
    psGetThreadWin32Thread = kswordArkWin32kResolvePsGetThreadWin32Thread();
    psGetProcessSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
    if (psGetThreadWin32Thread == NULL) {
        ExFreePoolWithTag(map, poolTag);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (psGetNextProcess != NULL && psGetNextProcessThread != NULL) {
        PEPROCESS processCursor = psGetNextProcess(NULL);

        while (processCursor != NULL) {
            PEPROCESS nextProcess = psGetNextProcess(processCursor);
            PETHREAD threadCursor = psGetNextProcessThread(processCursor, NULL);
            ULONG processId = HandleToULong(PsGetProcessId(processCursor));
            ULONG sessionId = psGetProcessSessionId != NULL
                ? psGetProcessSessionId(processCursor)
                : 0UL;

            while (threadCursor != NULL) {
                PETHREAD nextThread = psGetNextProcessThread(processCursor, threadCursor);
                PVOID threadInfo = psGetThreadWin32Thread(threadCursor);

                if (threadInfo != NULL) {
                    if (count >= maximumEntries) {
                        truncated = TRUE;
                    }
                    else {
                        map[count].threadInfo = (ULONG64)(ULONG_PTR)threadInfo;
                        map[count].processId = processId;
                        map[count].threadId = HandleToULong(PsGetThreadId(threadCursor));
                        map[count].sessionId = sessionId;
                        count += 1UL;
                    }
                }
                ObDereferenceObject(threadCursor);
                threadCursor = nextThread;
            }
            ObDereferenceObject(processCursor);
            processCursor = nextProcess;
        }
    }
    else {
        PVOID snapshot = NULL;
        ULONG snapshotBytes = 0UL;
        ULONG processOffset = 0UL;
        NTSTATUS status = kswordArkWin32kCaptureProcessSnapshot(
            &snapshot,
            &snapshotBytes);

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(map, poolTag);
            return status;
        }

#if defined(_WIN64)
        C_ASSERT(FIELD_OFFSET(KswordArkWiN32KSystemProcessInformation, threads) == 0x100);
        C_ASSERT(sizeof(KswordArkWiN32KSystemThreadInformation) == 0x50);
#endif
        while (processOffset < snapshotBytes) {
            KswordArkWiN32KSystemProcessInformation* processInfo =
                (KswordArkWiN32KSystemProcessInformation*)((PUCHAR)snapshot + processOffset);
            ULONG remainingBytes = snapshotBytes - processOffset;
            ULONG entryBytes = processInfo->nextEntryOffset != 0UL
                ? processInfo->nextEntryOffset
                : remainingBytes;
            ULONG threadCapacity = 0UL;
            ULONG threadCount = 0UL;
            ULONG threadIndex = 0UL;

            if (remainingBytes < (ULONG)FIELD_OFFSET(KswordArkWiN32KSystemProcessInformation, threads) ||
                entryBytes < (ULONG)FIELD_OFFSET(KswordArkWiN32KSystemProcessInformation, threads) ||
                entryBytes > remainingBytes) {
                truncated = TRUE;
                break;
            }
            threadCapacity = (entryBytes -
                FIELD_OFFSET(KswordArkWiN32KSystemProcessInformation, threads)) /
                sizeof(KswordArkWiN32KSystemThreadInformation);
            threadCount = processInfo->numberOfThreads;
            if (threadCount > threadCapacity) {
                threadCount = threadCapacity;
                truncated = TRUE;
            }

            for (threadIndex = 0UL; threadIndex < threadCount; ++threadIndex) {
                PETHREAD threadObject = NULL;
                HANDLE threadId = processInfo->threads[threadIndex].clientId.UniqueThread;

                status = PsLookupThreadByThreadId(threadId, &threadObject);
                if (NT_SUCCESS(status) && threadObject != NULL) {
                    PVOID threadInfo = psGetThreadWin32Thread(threadObject);

                    if (threadInfo != NULL) {
                        if (count >= maximumEntries) {
                            truncated = TRUE;
                        }
                        else {
                            map[count].threadInfo = (ULONG64)(ULONG_PTR)threadInfo;
                            map[count].processId = HandleToULong(processInfo->uniqueProcessId);
                            map[count].threadId = HandleToULong(threadId);
                            map[count].sessionId = processInfo->sessionId;
                            count += 1UL;
                        }
                    }
                    ObDereferenceObject(threadObject);
                }
            }

            if (processInfo->nextEntryOffset == 0UL) {
                break;
            }
            processOffset += processInfo->nextEntryOffset;
        }
        ExFreePoolWithTag(snapshot, 'sWkW');
    }

    *mapOut = map;
    *countOut = count;
    *truncatedOut = truncated;
    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkWin32kFindModuleByName(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCSTR moduleName,
    _Out_ KswHookSystemModuleEntry* moduleEntryOut
    )
/*++

Routine Description:

    Locate one loaded kernel module by basename in a SystemModuleInformation snapshot.

Arguments:

    ModuleInfo - Module snapshot.
    ModuleName - ASCII basename to match.
    ModuleEntryOut - Receives the matching row.

Return Value:

    TRUE on match; FALSE otherwise.

--*/
{
    ULONG moduleIndex = 0UL;

    if (moduleInfo == NULL || moduleName == NULL || moduleEntryOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(moduleEntryOut, sizeof(*moduleEntryOut));

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswHookSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;

        kswordArkHookGetModuleFileName(moduleEntry, &fileName, &fileNameBytes);
        if (kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, moduleName)) {
            RtlCopyMemory(moduleEntryOut, moduleEntry, sizeof(*moduleEntryOut));
            return TRUE;
        }
    }

    return FALSE;
}

VOID
kswordArkWin32kFillModuleState(
    _Out_ KSWORD_ARK_WIN32K_MODULE_STATE* moduleState,
    _In_z_ PCWSTR moduleName,
    _In_ BOOLEAN loaded,
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry
    )
/*++

Routine Description:

    Populate one fixed module-state row for win32k, win32kbase, or win32kfull.

Arguments:

    ModuleState - Output module-state packet.
    ModuleName - Protocol display name.
    Loaded - TRUE when SystemModuleInformation contained this module.
    ModuleEntry - Optional loaded module evidence.

Return Value:

    None. Invalid output input is ignored.

--*/
{
    if (moduleState == NULL) {
        return;
    }

    RtlZeroMemory(moduleState, sizeof(*moduleState));
    moduleState->loaded = loaded ? 1UL : 0UL;
    moduleState->profileState = loaded
        ? KSWORD_ARK_WIN32K_PROFILE_STATE_MISSING
        : KSWORD_ARK_WIN32K_PROFILE_STATE_NOT_LOADED;
    kswordArkWin32kCopyWideText(
        moduleState->moduleName,
        KSWORD_ARK_WIN32K_MODULE_NAME_CHARS,
        moduleName);

    if (loaded && moduleEntry != NULL) {
        moduleState->imageBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
        moduleState->imageSize = moduleEntry->imageSize;
    }
}

ULONG64
kswordArkWin32kModuleCapabilityMask(
    _In_ BOOLEAN win32kLoaded,
    _In_ BOOLEAN win32kbaseLoaded,
    _In_ BOOLEAN win32kfullLoaded,
    _In_opt_ const KswHookSystemModuleEntry* win32kbaseEntry,
    _Out_ ULONG64* missingCapabilityMaskOut,
    _Out_ ULONG64* userGetSiloGlobalsOut
    )
/*++

Routine Description:

    Build current module/profile capability evidence without claiming profile support.

Arguments:

    Win32kLoaded - win32k.sys module presence.
    Win32kbaseLoaded - win32kbase.sys module presence.
    Win32kfullLoaded - win32kfull.sys module presence.
    Win32kbaseEntry - Optional win32kbase module entry for export lookup.
    MissingCapabilityMaskOut - Receives PDB capability gaps.
    UserGetSiloGlobalsOut - Receives resolved UserGetSiloGlobals address.

Return Value:

    Capability bitmask for the current kernel state.

--*/
{
    ULONG64 capabilityMask = 0ULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG_PTR userGetSiloGlobals = 0U;

    if (win32kLoaded) {
        capabilityMask |= KSWORD_ARK_WIN32K_CAP_WIN32K_LOADED;
    }
    if (win32kbaseLoaded) {
        capabilityMask |= KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED;
    }
    if (win32kfullLoaded) {
        capabilityMask |= KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED;
    }

    if (win32kbaseLoaded && win32kbaseEntry != NULL && win32kbaseEntry->imageBase != NULL) {
        userGetSiloGlobals = (ULONG_PTR)RtlFindExportedRoutineByName(
            win32kbaseEntry->imageBase,
            "UserGetSiloGlobals");
        if (userGetSiloGlobals != 0U) {
            capabilityMask |= KSWORD_ARK_WIN32K_CAP_USER_GET_SILO_GLOBALS;
        }
    }

    if (kswordArkWin32kResolvePsGetThreadWin32Thread() != NULL) {
        capabilityMask |= KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC;
    }

    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_HOTKEY_PROFILE;
    missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_HOOK_PROFILE;

    if (missingCapabilityMaskOut != NULL) {
        *missingCapabilityMaskOut = missingCapabilityMask;
    }
    if (userGetSiloGlobalsOut != NULL) {
        *userGetSiloGlobalsOut = (ULONG64)userGetSiloGlobals;
    }
    return capabilityMask;
}

static KSWORD_ARK_WIN32K_SESSION_ENTRY*
kswordArkWin32kFindOrAppendSession(
    _Inout_ KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ ULONG sessionId
    )
/*++

Routine Description:

    Return a per-session summary row, appending it when first observed.

Arguments:

    Response - Mutable profile/status response.
    EntryCapacity - Writable session-entry capacity.
    SessionId - Session id from PsGetProcessSessionId.

Return Value:

    Session row pointer, or NULL if the output buffer is full.

--*/
{
    ULONG index = 0UL;

    if (response == NULL) {
        return NULL;
    }

    for (index = 0UL; index < response->returnedCount; ++index) {
        if (response->entries[index].sessionId == sessionId) {
            return &response->entries[index];
        }
    }

    response->totalCount += 1UL;
    if ((size_t)response->returnedCount >= entryCapacity) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        return NULL;
    }

    RtlZeroMemory(&response->entries[response->returnedCount], sizeof(response->entries[0]));
    response->entries[response->returnedCount].sessionId = sessionId;
    response->entries[response->returnedCount].status =
        (response->capabilityMask &
            (KSWORD_ARK_WIN32K_CAP_TAGWND_SIGNATURE |
             KSWORD_ARK_WIN32K_CAP_TAGQ_SIGNATURE)) != 0ULL
        ? KSWORD_ARK_WIN32K_STATUS_PARTIAL
        : KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->entries[response->returnedCount].capabilityMask = response->capabilityMask;
    response->entries[response->returnedCount].lastStatus = STATUS_SUCCESS;
    kswordArkWin32kCopyWideText(
        response->entries[response->returnedCount].detail,
        KSWORD_ARK_WIN32K_DETAIL_CHARS,
        L"Session observed; private-symbol fields remain unavailable while validated runtime-signature capabilities are reported separately.");
    response->returnedCount += 1UL;
    return &response->entries[response->returnedCount - 1UL];
}

VOID
kswordArkWin32kCollectSessionSummary(
    _Inout_ KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request
    )
/*++

Routine Description:

    Build a bounded per-session summary from PsGetNextProcess/psGetNextProcessThread.

Arguments:

    Response - Mutable profile/status response.
    EntryCapacity - Writable session-entry capacity.
    Request - Optional caller filter.

Return Value:

    None. Failures are recorded in the response status and lastStatus fields.

--*/
{
    KswordWiN32KPsGetNextProcessFn psGetNextProcess = NULL;
    KswordWiN32KPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordWiN32KPsGetThreadWiN32ThreadFn psGetThreadWin32Thread = NULL;
    KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId = NULL;
    PEPROCESS processCursor = NULL;
    ULONG maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    ULONG visitedProcesses = 0UL;

    psGetNextProcess = kswordArkWin32kResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkWin32kResolvePsGetNextProcessThread();
    psGetThreadWin32Thread = kswordArkWin32kResolvePsGetThreadWin32Thread();
    psGetProcessSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
    if (psGetNextProcess == NULL ||
        psGetNextProcessThread == NULL ||
        psGetThreadWin32Thread == NULL ||
        psGetProcessSessionId == NULL) {
        KswordArkWiN32KGuiThreadMapEntry* threadMap = NULL;
        ULONG threadMapCount = 0UL;
        ULONG mapIndex = 0UL;
        BOOLEAN mapTruncated = FALSE;
        NTSTATUS mapStatus = STATUS_SUCCESS;

        if (request != NULL) {
            maxEntries = kswordArkWin32kNormalizeMaxEntries(request->maxEntries);
        }
        mapStatus = kswordArkWin32kBuildGuiThreadMap(
            maxEntries,
            'pWkW',
            &threadMap,
            &threadMapCount,
            &mapTruncated);
        if (!NT_SUCCESS(mapStatus) || threadMap == NULL) {
            response->lastStatus = NT_SUCCESS(mapStatus)
                ? STATUS_PROCEDURE_NOT_FOUND
                : mapStatus;
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            return;
        }
        for (mapIndex = 0UL; mapIndex < threadMapCount; ++mapIndex) {
            KSWORD_ARK_WIN32K_SESSION_ENTRY* sessionEntry = NULL;
            ULONG priorIndex = 0UL;
            BOOLEAN processAlreadyCounted = FALSE;

            if (request != NULL && request->sessionId != 0UL &&
                request->sessionId != threadMap[mapIndex].sessionId) {
                continue;
            }
            if (request != NULL && request->sessionId == 0UL &&
                (request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL &&
                psGetProcessSessionId != NULL &&
                psGetProcessSessionId(PsGetCurrentProcess()) !=
                    threadMap[mapIndex].sessionId) {
                continue;
            }
            sessionEntry = kswordArkWin32kFindOrAppendSession(
                response,
                entryCapacity,
                threadMap[mapIndex].sessionId);
            if (sessionEntry == NULL) {
                continue;
            }
            for (priorIndex = 0UL; priorIndex < mapIndex; ++priorIndex) {
                if (threadMap[priorIndex].sessionId == threadMap[mapIndex].sessionId &&
                    threadMap[priorIndex].processId == threadMap[mapIndex].processId) {
                    processAlreadyCounted = TRUE;
                    break;
                }
            }
            if (!processAlreadyCounted) {
                sessionEntry->processCount += 1UL;
            }
            sessionEntry->guiThreadCount += 1UL;
            if (sessionEntry->representativeProcessId == 0UL) {
                sessionEntry->representativeProcessId = threadMap[mapIndex].processId;
                sessionEntry->representativeThreadId = threadMap[mapIndex].threadId;
            }
        }
        ExFreePoolWithTag(threadMap, 'pWkW');
        response->lastStatus = mapTruncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        if (mapTruncated) {
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        }
        return;
    }

    if (request != NULL) {
        maxEntries = kswordArkWin32kNormalizeMaxEntries(request->maxEntries);
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL && visitedProcesses < maxEntries) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        ULONG sessionId = psGetProcessSessionId(processCursor);
        KSWORD_ARK_WIN32K_SESSION_ENTRY* sessionEntry = NULL;
        PETHREAD threadCursor = NULL;

        if (request != NULL &&
            request->sessionId != 0UL &&
            request->sessionId != sessionId) {
            ObDereferenceObject(processCursor);
            processCursor = nextProcess;
            visitedProcesses += 1UL;
            continue;
        }

        sessionEntry = kswordArkWin32kFindOrAppendSession(response, entryCapacity, sessionId);
        if (sessionEntry != NULL) {
            sessionEntry->processCount += 1UL;
            if (sessionEntry->representativeProcessId == 0UL) {
                sessionEntry->representativeProcessId = HandleToULong(PsGetProcessId(processCursor));
            }

            threadCursor = psGetNextProcessThread(processCursor, NULL);
            while (threadCursor != NULL) {
                PETHREAD nextThread = psGetNextProcessThread(processCursor, threadCursor);
                PVOID threadInfo = psGetThreadWin32Thread(threadCursor);

                if (threadInfo != NULL) {
                    sessionEntry->guiThreadCount += 1UL;
                    if (sessionEntry->representativeThreadId == 0UL) {
                        sessionEntry->representativeThreadId = HandleToULong(PsGetThreadId(threadCursor));
                    }
                }
                ObDereferenceObject(threadCursor);
                threadCursor = nextThread;
            }
        }

        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
        visitedProcesses += 1UL;
    }

    if (processCursor != NULL) {
        ObDereferenceObject(processCursor);
        processCursor = NULL;
        response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
}
