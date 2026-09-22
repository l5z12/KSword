/*++

Module Name:

    bugcheck_runtime.c

Abstract:

    Bugcheck callback registration and nonpaged diagnostic state for the
    fail-closed physical BGP panel.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_decode.h"
#include "bugcheck_bgp.h"
#include "bugcheck_panel.h"
#include "bugcheck_preparation_log.h"
#include "../../platform/pool_compat.h"

#include <aux_klib.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_BUGCHECK_POOL_TAG 'cbSK'
#define KSWORD_ARK_BUGCHECK_SECONDARY_SIGNATURE 0x4442534BUL /* 'KSBD' */

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

typedef PEPROCESS
(NTAPI* KswordArkBugcheckPsGetNextProcess)(
    _In_opt_ PEPROCESS process
    );

typedef struct KswordArkBugcheckSecondaryData
{
    ULONG signature;
    ULONG version;
    ULONG size;
    ULONG reserved;
    KswordArkBugcheckDiagnostics diagnostics;
    KswordArkBgpDumpState bgpState;
} KswordArkBugcheckSecondaryData;

#define KSWORD_ARK_BUGCHECK_CALLBACK_CLASSIC   0x00000001UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_SECONDARY 0x00000002UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_DUMP_IO   0x00000004UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_TRIAGE    0x00000008UL

KswordArkBugcheckState gKswordArkBugcheckState;
UCHAR gKswordArkBugcheckBitmapPixels[KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES];

static UCHAR gKswordArkBugcheckComponent[] = "KswordARK";
static KswordArkBugcheckSecondaryData gKswordArkBugcheckSecondaryData;
static const GUID kGKswordArkBugcheckSecondaryGuid =
{ 0x956d0947, 0x326a, 0x4ba7, { 0x92, 0xf1, 0x4c, 0x8b, 0x5a, 0x5c, 0x71, 0x2d } };

static ULONG
kswordArkBugcheckCallbackMask(
    VOID
    )
{
    ULONG callbackMask;

    callbackMask = 0;
    if (gKswordArkBugcheckState.classicRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_CLASSIC;
    }
    if (gKswordArkBugcheckState.secondaryRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_SECONDARY;
    }
    if (gKswordArkBugcheckState.dumpIoRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_DUMP_IO;
    }
    if (gKswordArkBugcheckState.triageRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_TRIAGE;
    }
    return callbackMask;
}

static VOID
kswordArkBugcheckUpdateSecondaryData(
    VOID
    )
{
    gKswordArkBugcheckSecondaryData.signature =
        KSWORD_ARK_BUGCHECK_SECONDARY_SIGNATURE;
    gKswordArkBugcheckSecondaryData.version = 4UL;
    gKswordArkBugcheckSecondaryData.size =
        sizeof(gKswordArkBugcheckSecondaryData);
    RtlCopyMemory(
        &gKswordArkBugcheckSecondaryData.diagnostics,
        &gKswordArkBugcheckState.diagnostics,
        sizeof(gKswordArkBugcheckSecondaryData.diagnostics));
    kswordArkBugcheckBgpSnapshot(
        &gKswordArkBugcheckSecondaryData.bgpState);
}

static CHAR
kswordArkBugcheckLowerA(
    _In_ CHAR value
    )
{
    return (value >= 'A' && value <= 'Z') ? (CHAR)(value - 'A' + 'a') : value;
}

static BOOLEAN
kswordArkBugcheckEqualsNoCaseA(
    _In_z_ PCSTR left,
    _In_z_ PCSTR right
    )
{
    if (left == NULL || right == NULL) {
        return FALSE;
    }

    while (*left != '\0' && *right != '\0') {
        if (kswordArkBugcheckLowerA(*left) != kswordArkBugcheckLowerA(*right)) {
            return FALSE;
        }
        ++left;
        ++right;
    }

    return (*left == '\0' && *right == '\0') ? TRUE : FALSE;
}

static BOOLEAN
kswordArkBugcheckStartsWithNoCaseA(
    _In_z_ PCSTR text,
    _In_z_ PCSTR prefix
    )
{
    if (text == NULL || prefix == NULL) {
        return FALSE;
    }

    while (*prefix != '\0') {
        if (*text == '\0' ||
            kswordArkBugcheckLowerA(*text) != kswordArkBugcheckLowerA(*prefix)) {
            return FALSE;
        }
        ++text;
        ++prefix;
    }
    return TRUE;
}

static BOOLEAN
kswordArkBugcheckContainsNoCaseA(
    _In_z_ PCSTR text,
    _In_z_ PCSTR needle
    )
{
    PCSTR cursor;

    if (text == NULL || needle == NULL || needle[0] == '\0') {
        return FALSE;
    }

    for (cursor = text; *cursor != '\0'; ++cursor) {
        if (kswordArkBugcheckStartsWithNoCaseA(cursor, needle)) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG
kswordArkBugcheckClassifyModuleName(
    _In_z_ PCSTR name
    )
{
    static const PCSTR kKnownMicrosoftModules[] = {
        "ntoskrnl.exe", "hal.dll", "kdcom.dll", "bootvid.dll", "ci.dll",
        "clfs.sys", "cng.sys", "acpi.sys", "pci.sys", "partmgr.sys",
        "volmgr.sys", "volsnap.sys", "disk.sys", "classpnp.sys",
        "storport.sys", "stornvme.sys", "ntfs.sys", "fltmgr.sys",
        "ndis.sys", "tcpip.sys", "afd.sys", "wdf01000.sys",
        "watchdog.sys", "dxgkrnl.sys", "basicdisplay.sys",
        "basicrender.sys", "win32k.sys"
    };
    ULONG index;

    if (name == NULL || name[0] == '\0') {
        return KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    }

    if (kswordArkBugcheckEqualsNoCaseA(name, "KswordARK.sys") ||
        kswordArkBugcheckContainsNoCaseA(name, "kswordark")) {
        return KSWORD_ARK_BUGCHECK_MODULE_OURS;
    }

    for (index = 0; index < RTL_NUMBER_OF(kKnownMicrosoftModules); ++index) {
        if (kswordArkBugcheckEqualsNoCaseA(name, kKnownMicrosoftModules[index])) {
            return KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT;
        }
    }

    if (kswordArkBugcheckStartsWithNoCaseA(name, "win32k") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "dxgmms") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "ksec") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "msrpc") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "netio") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "spaceport") ||
        kswordArkBugcheckStartsWithNoCaseA(name, "iorate")) {
        return KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT;
    }

    return KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY;
}

static VOID
kswordArkBugcheckPublishModule(
    _In_ ULONG_PTR base,
    _In_ ULONG size,
    _In_z_ PCSTR name
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG targetIndex;
    PkswordArkBugcheckModuleEntry entry;

    if (base < 0x10000ULL || size == 0 || name == NULL || name[0] == '\0' ||
        InterlockedCompareExchange(
            &gKswordArkBugcheckState.trackingReady,
            1,
            1) == 0) {
        return;
    }

    KeAcquireSpinLock(&gKswordArkBugcheckState.moduleCacheLock, &oldIrql);
    targetIndex = MAXULONG;
    for (index = 0; index < KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT; ++index) {
        ULONG_PTR existingBase;
        ULONG_PTR existingEnd;
        ULONG_PTR newEnd;

        entry = &gKswordArkBugcheckState.modules[index];
        existingBase = entry->base;
        if (existingBase == 0 || entry->size == 0) {
            if (targetIndex == MAXULONG) {
                targetIndex = index;
            }
            continue;
        }
        existingEnd = existingBase + entry->size;
        newEnd = base + size;
        if (existingBase == base ||
            (base < existingEnd && existingBase < newEnd)) {
            targetIndex = index;
            break;
        }
    }
    if (targetIndex == MAXULONG) {
        targetIndex = gKswordArkBugcheckState.moduleNextSlot %
            KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT;
        ++gKswordArkBugcheckState.moduleNextSlot;
    }

    entry = &gKswordArkBugcheckState.modules[targetIndex];
    if (entry->base == 0 &&
        gKswordArkBugcheckState.moduleCount <
            KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT) {
        ++gKswordArkBugcheckState.moduleCount;
    }
    (VOID)InterlockedIncrement(&entry->sequence);
    KeMemoryBarrier();
    entry->base = base;
    entry->size = size;
    entry->classification = kswordArkBugcheckClassifyModuleName(name);
    (VOID)RtlStringCbCopyA(entry->name, sizeof(entry->name), name);
    entry->name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL] = '\0';
    KeMemoryBarrier();
    (VOID)InterlockedIncrement(&entry->sequence);
    KeReleaseSpinLock(&gKswordArkBugcheckState.moduleCacheLock, oldIrql);
}

static BOOLEAN
kswordArkBugcheckCopyUnicodeBaseNameA(
    _In_opt_ PCUNICODE_STRING fullImageName,
    _Out_writes_z_(capacity) PCHAR name,
    _In_ ULONG capacity
    )
{
    USHORT characterCount;
    USHORT start;
    USHORT index;
    ULONG copied;

    if (name == NULL || capacity == 0) {
        return FALSE;
    }
    name[0] = '\0';
    if (fullImageName == NULL || fullImageName->Buffer == NULL ||
        fullImageName->Length < sizeof(WCHAR)) {
        return FALSE;
    }

    characterCount = fullImageName->Length / sizeof(WCHAR);
    start = 0;
    for (index = 0; index < characterCount; ++index) {
        if (fullImageName->Buffer[index] == L'\\' ||
            fullImageName->Buffer[index] == L'/') {
            start = (USHORT)(index + 1U);
        }
    }
    copied = 0;
    for (index = start;
         index < characterCount && copied + 1UL < capacity;
         ++index) {
        WCHAR value;

        value = fullImageName->Buffer[index];
        name[copied++] = value >= 0x20 && value <= 0x7E
            ? (CHAR)value
            : '?';
    }
    name[copied] = '\0';
    return copied != 0 ? TRUE : FALSE;
}

VOID
kswordArkBugcheckTrackLoadedImage(
    _In_opt_ PUNICODE_STRING fullImageName,
    _In_ HANDLE processId,
    _In_ PIMAGE_INFO imageInfo
    )
{
    CHAR name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];

    UNREFERENCED_PARAMETER(processId);
    if (imageInfo == NULL || !imageInfo->SystemModeImage ||
        imageInfo->ImageBase == NULL || imageInfo->ImageSize == 0 ||
        imageInfo->ImageSize > MAXULONG ||
        !kswordArkBugcheckCopyUnicodeBaseNameA(
            fullImageName,
            name,
            (ULONG)RTL_NUMBER_OF(name))) {
        return;
    }
    kswordArkBugcheckPublishModule(
        (ULONG_PTR)imageInfo->ImageBase,
        (ULONG)imageInfo->ImageSize,
        name);
}

static VOID
kswordArkBugcheckPublishProcess(
    _In_ PEPROCESS process,
    _In_ HANDLE processId,
    _In_ BOOLEAN exiting
    )
{
    CHAR name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
    PCSTR imageName;
    KIRQL oldIrql;
    ULONG index;
    ULONG targetIndex;
    ULONG exitingIndex;
    PkswordArkBugcheckProcessEntry entry;

    if (process == NULL ||
        InterlockedCompareExchange(
            &gKswordArkBugcheckState.trackingReady,
            1,
            1) == 0) {
        return;
    }
    RtlZeroMemory(name, sizeof(name));
    imageName = PsGetProcessImageFileName(process);
    if (imageName != NULL) {
        (VOID)RtlStringCbCopyA(name, sizeof(name), imageName);
    }
    name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';

    KeAcquireSpinLock(&gKswordArkBugcheckState.processCacheLock, &oldIrql);
    targetIndex = MAXULONG;
    exitingIndex = MAXULONG;
    for (index = 0; index < KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT; ++index) {
        entry = &gKswordArkBugcheckState.processes[index];
        if (entry->object == process) {
            targetIndex = index;
            break;
        }
        if (entry->object == NULL && targetIndex == MAXULONG) {
            targetIndex = index;
        } else if (entry->exiting && exitingIndex == MAXULONG) {
            exitingIndex = index;
        }
    }
    if (targetIndex == MAXULONG) {
        targetIndex = exitingIndex != MAXULONG
            ? exitingIndex
            : gKswordArkBugcheckState.processNextSlot %
                KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT;
        ++gKswordArkBugcheckState.processNextSlot;
    }

    entry = &gKswordArkBugcheckState.processes[targetIndex];
    if (entry->object == NULL &&
        gKswordArkBugcheckState.processCount <
            KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT) {
        ++gKswordArkBugcheckState.processCount;
    }
    (VOID)InterlockedIncrement(&entry->sequence);
    KeMemoryBarrier();
    entry->object = process;
    entry->processId = (ULONG_PTR)processId;
    entry->exiting = exiting;
    if (name[0] != '\0' || entry->name[0] == '\0') {
        (VOID)RtlStringCbCopyA(entry->name, sizeof(entry->name), name);
    }
    entry->name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';
    KeMemoryBarrier();
    (VOID)InterlockedIncrement(&entry->sequence);
    KeReleaseSpinLock(&gKswordArkBugcheckState.processCacheLock, oldIrql);
}

VOID
kswordArkBugcheckTrackProcess(
    _In_ PEPROCESS process,
    _In_ HANDLE processId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo
    )
{
    kswordArkBugcheckPublishProcess(
        process,
        processId,
        createInfo == NULL ? TRUE : FALSE);
}

static VOID
kswordArkBugcheckRefreshProcessCache(
    VOID
    )
{
    UNICODE_STRING routineName;
    KswordArkBugcheckPsGetNextProcess getNextProcess;
    PEPROCESS process;
    ULONG visited;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    getNextProcess = (KswordArkBugcheckPsGetNextProcess)
        MmGetSystemRoutineAddress(&routineName);
    if (getNextProcess == NULL) {
        return;
    }

    visited = 0;
    process = getNextProcess(NULL);
    while (process != NULL && visited < 65536UL) {
        PEPROCESS nextProcess;

        if (!NT_SUCCESS(kswordArkBugcheckControlCheckAbort())) {
            break;
        }

        nextProcess = getNextProcess(process);
        kswordArkBugcheckPublishProcess(
            process,
            PsGetProcessId(process),
            FALSE);
        ObDereferenceObject(process);
        process = nextProcess;
        ++visited;
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }
}

PCSTR
kswordArkBugcheckName(
    _In_ ULONG bugCheckCode
    )
{
    switch (bugCheckCode) {
    case 0x0000000A: return "IRQL_NOT_LESS_OR_EQUAL";
    case 0x0000001A: return "MEMORY_MANAGEMENT";
    case 0x0000001E: return "KMODE_EXCEPTION_NOT_HANDLED";
    case 0x00000024: return "NTFS_FILE_SYSTEM";
    case 0x0000002E: return "DATA_BUS_ERROR";
    case 0x0000003B: return "SYSTEM_SERVICE_EXCEPTION";
    case 0x00000050: return "PAGE_FAULT_IN_NONPAGED_AREA";
    case 0x0000007E: return "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED";
    case 0x0000007F: return "UNEXPECTED_KERNEL_MODE_TRAP";
    case 0x0000009F: return "DRIVER_POWER_STATE_FAILURE";
    case 0x000000A0: return "INTERNAL_POWER_ERROR";
    case 0x000000BE: return "ATTEMPTED_WRITE_TO_READONLY_MEMORY";
    case 0x000000C2: return "BAD_POOL_CALLER";
    case 0x000000C4: return "DRIVER_VERIFIER_DETECTED_VIOLATION";
    case 0x000000C5: return "DRIVER_CORRUPTED_EXPOOL";
    case 0x000000C9: return "DRIVER_VERIFIER_IOMANAGER_VIOLATION";
    case 0x000000D1: return "DRIVER_IRQL_NOT_LESS_OR_EQUAL";
    case 0x000000D5: return "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL";
    case 0x000000EA: return "THREAD_STUCK_IN_DEVICE_DRIVER";
    case 0x000000EF: return "CRITICAL_PROCESS_DIED";
    case 0x000000F7: return "DRIVER_OVERRAN_STACK_BUFFER";
    case 0x00000109: return "CRITICAL_STRUCTURE_CORRUPTION";
    case 0x00000116: return "VIDEO_TDR_FAILURE";
    case 0x00000117: return "VIDEO_TDR_TIMEOUT_DETECTED";
    case 0x00000119: return "VIDEO_SCHEDULER_INTERNAL_ERROR";
    case 0x00000124: return "WHEA_UNCORRECTABLE_ERROR";
    case 0x00000133: return "DPC_WATCHDOG_VIOLATION";
    case 0x00000139: return "KERNEL_SECURITY_CHECK_FAILURE";
    case 0x0000013A: return "KERNEL_MODE_HEAP_CORRUPTION";
    default: return "UNKNOWN_BUGCHECK_CODE";
    }
}

PCSTR
kswordArkBugcheckModuleClassText(
    _In_ ULONG classification
    )
{
    switch (classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS: return "OUR_DRIVER";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT: return "MICROSOFT_KNOWN";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY: return "THIRD_PARTY";
    default: return "UNKNOWN";
    }
}

PCSTR
kswordArkBugcheckConfidenceText(
    _In_ ULONG confidence
    )
{
    switch (confidence) {
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH: return "HIGH";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM: return "MEDIUM";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_LOW: return "LOW";
    default: return "NONE";
    }
}

PCSTR
kswordArkBugcheckVerdictText(
    _In_ ULONG classification
    )
{
    switch (classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS:
        return "KswordARK may be involved. Capture this page and attach the crash dump when reporting the issue.";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT:
        return "The available crash parameters point to a known Microsoft kernel component.";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY:
        return "The available crash parameters point to another third-party kernel component.";
    default:
        return "The faulting component is unknown. Capture this page and preserve the crash dump.";
    }
}

PCSTR
kswordArkBugcheckDumpTypeText(
    _In_ ULONG dumpType
    )
{
    switch (dumpType) {
    case KbDumpIoHeader: return "Header";
    case KbDumpIoBody: return "Body";
    case KbDumpIoSecondaryData: return "SecondaryData";
    case KbDumpIoComplete: return "Complete";
    default: return "Unknown";
    }
}

PCSTR
kswordArkBugcheckReasonText(
    _In_ ULONG reason
    )
{
    switch (reason) {
    case KbCallbackInvalid: return "Invalid";
    case KbCallbackSecondaryDumpData: return "SecondaryDumpData";
    case KbCallbackDumpIo: return "DumpIo";
    case KbCallbackAddPages: return "AddPages";
    case KbCallbackSecondaryMultiPartDumpData: return "SecondaryMultiPartDumpData";
    case KbCallbackRemovePages: return "RemovePages";
    case KbCallbackTriageDumpData: return "TriageDumpData";
    default: return "Unknown";
    }
}

static VOID
kswordArkBugcheckRefreshModuleCache(
    VOID
    )
{
    NTSTATUS status;
    ULONG bytes = 0;
    ULONG count;
    ULONG index;
    PAUX_MODULE_EXTENDED_INFO modules;
    PCSTR name;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return;
    }

    status = AuxKlibQueryModuleInformation(
        &bytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || bytes == 0) {
        return;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)kswordArkAllocateNonPagedPool(
        bytes,
        KSWORD_ARK_BUGCHECK_POOL_TAG);
    if (modules == NULL) {
        return;
    }

    RtlZeroMemory(modules, bytes);
    status = AuxKlibQueryModuleInformation(
        &bytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, KSWORD_ARK_BUGCHECK_POOL_TAG);
        return;
    }

    count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    for (index = 0; index < count; ++index) {
        if (!NT_SUCCESS(kswordArkBugcheckControlCheckAbort())) {
            break;
        }
        name = (PCSTR)modules[index].FullPathName;
        if (modules[index].FileNameOffset < AUX_KLIB_MODULE_PATH_LEN) {
            name = (PCSTR)&modules[index].FullPathName[modules[index].FileNameOffset];
        }

        kswordArkBugcheckPublishModule(
            (ULONG_PTR)modules[index].BasicInfo.ImageBase,
            modules[index].ImageSize,
            name);
    }
    ExFreePoolWithTag(modules, KSWORD_ARK_BUGCHECK_POOL_TAG);
}

static BOOLEAN
kswordArkBugcheckFindModuleForAddress(
    _In_ ULONG_PTR address,
    _Out_ PkswordArkBugcheckModuleEntry module
    )
{
    ULONG index;
    ULONG moduleCount;

    if (address < 0x10000ULL || module == NULL) {
        return FALSE;
    }
    RtlZeroMemory(module, sizeof(*module));
    moduleCount = gKswordArkBugcheckState.moduleCount;
    if (moduleCount > KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT) {
        moduleCount = KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT;
    }

    for (index = 0; index < moduleCount; ++index) {
        PkswordArkBugcheckModuleEntry entry;
        LONG sequenceBefore;
        LONG sequenceAfter;
        ULONG_PTR base;
        ULONG size;
        ULONG classification;
        CHAR name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];

        entry = &gKswordArkBugcheckState.modules[index];
        sequenceBefore = InterlockedCompareExchange(&entry->sequence, 0, 0);
        if ((sequenceBefore & 1L) != 0) {
            continue;
        }
        base = entry->base;
        size = entry->size;
        classification = entry->classification;
        RtlCopyMemory(name, entry->name, sizeof(name));
        name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL] = '\0';
        KeMemoryBarrier();
        sequenceAfter = InterlockedCompareExchange(&entry->sequence, 0, 0);
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1L) != 0) {
            continue;
        }
        if (base != 0 && size != 0 &&
            address >= base && address - base < size) {
            module->base = base;
            module->size = size;
            module->classification = classification;
            (VOID)RtlStringCbCopyA(module->name, sizeof(module->name), name);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkBugcheckFindProcessForObject(
    _In_ PVOID processObject,
    _Out_ PULONG_PTR processIdArg,
    _Out_writes_z_(nameCapacity) PCHAR name,
    _In_ ULONG nameCapacity
    )
{
    ULONG index;

    if (processObject == NULL || processIdArg == NULL || name == NULL ||
        nameCapacity == 0) {
        return FALSE;
    }
    *processIdArg = 0;
    name[0] = '\0';

    for (index = 0; index < KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT; ++index) {
        PkswordArkBugcheckProcessEntry entry;
        LONG sequenceBefore;
        LONG sequenceAfter;
        PVOID object;
        ULONG_PTR processId;
        CHAR processName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];

        entry = &gKswordArkBugcheckState.processes[index];
        sequenceBefore = InterlockedCompareExchange(&entry->sequence, 0, 0);
        if ((sequenceBefore & 1L) != 0) {
            continue;
        }
        object = entry->object;
        processId = entry->processId;
        RtlCopyMemory(processName, entry->name, sizeof(processName));
        processName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';
        KeMemoryBarrier();
        sequenceAfter = InterlockedCompareExchange(&entry->sequence, 0, 0);
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1L) != 0 ||
            object != processObject) {
            continue;
        }

        *processIdArg = processId;
        (VOID)RtlStringCbCopyA(name, nameCapacity, processName);
        return processName[0] != '\0' ? TRUE : FALSE;
    }
    return FALSE;
}

static VOID
kswordArkBugcheckResolveProcessContext(
    _Inout_ PkswordArkBugcheckDiagnostics diagnostics
    )
{
    PVOID processObject;

    diagnostics->processObject = 0;
    diagnostics->processId = 0;
    diagnostics->processSource = KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_NONE;
    diagnostics->processName[0] = '\0';
    if (diagnostics->bugCheckCode == 0x000000EF &&
        diagnostics->parameter1 != 0) {
        processObject = (PVOID)diagnostics->parameter1;
        diagnostics->processSource =
            KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CRITICAL;
    } else {
        processObject = PsGetCurrentProcess();
        diagnostics->processSource =
            KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CONTEXT;
    }
    diagnostics->processObject = (ULONG_PTR)processObject;
    (VOID)kswordArkBugcheckFindProcessForObject(
        processObject,
        &diagnostics->processId,
        diagnostics->processName,
        (ULONG)sizeof(diagnostics->processName));
}

static VOID
kswordArkBugcheckSetCandidate(
    _Inout_ PkswordArkBugcheckDiagnostics diagnostics,
    _In_ PkswordArkBugcheckModuleEntry module,
    _In_ ULONG_PTR address,
    _In_ ULONG confidence,
    _In_ ULONG parameterIndex,
    _In_z_ PCSTR source
    )
{
    diagnostics->candidateAddress = address;
    diagnostics->candidateModuleBase = module->base;
    diagnostics->candidateModuleSize = module->size;
    diagnostics->candidateModuleOffset = address >= module->base
        ? address - module->base
        : 0;
    diagnostics->candidateParameter = parameterIndex;
    diagnostics->candidateClass = module->classification;
    diagnostics->candidateConfidence = confidence;
    (VOID)RtlStringCbCopyA(
        diagnostics->candidateModule,
        sizeof(diagnostics->candidateModule),
        module->name);
    (VOID)RtlStringCbCopyA(
        diagnostics->candidateSource,
        sizeof(diagnostics->candidateSource),
        source);
}

static VOID
kswordArkBugcheckResolveCandidate(
    _Inout_ PkswordArkBugcheckDiagnostics diagnostics
    )
{
    ULONG_PTR primaryAddress;
    ULONG primaryParameter;
    ULONG primaryConfidence;
    KswordArkBugcheckModuleEntry module;

    diagnostics->candidateAddress = 0;
    diagnostics->candidateModuleBase = 0;
    diagnostics->candidateModuleOffset = 0;
    diagnostics->candidateModuleSize = 0;
    diagnostics->candidateParameter = 0;
    diagnostics->candidateClass = KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    diagnostics->candidateConfidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;
    (VOID)RtlStringCbCopyA(
        diagnostics->candidateModule,
        sizeof(diagnostics->candidateModule),
        "(none)");
    (VOID)RtlStringCbCopyA(
        diagnostics->candidateSource,
        sizeof(diagnostics->candidateSource),
        "none");
    diagnostics->faultAddress = 0;
    diagnostics->faultParameter = 0;
    (VOID)RtlStringCbCopyA(
        diagnostics->faultMeaning,
        sizeof(diagnostics->faultMeaning),
        "not classified");

    if (kswordArkBugcheckDecodePrimaryAddress(
            diagnostics,
            &primaryAddress,
            &primaryParameter,
            &primaryConfidence)) {
        if (kswordArkBugcheckFindModuleForAddress(primaryAddress, &module)) {
            kswordArkBugcheckSetCandidate(
                diagnostics,
                &module,
                primaryAddress,
                primaryConfidence,
                primaryParameter,
                "bugcheck-specific address parameter");
            return;
        }
    }
}

static VOID
kswordArkBugcheckCaptureData(
    _In_opt_ PKBUGCHECK_TRIAGE_DUMP_DATA triageData,
    _In_ ULONG reason,
    _In_ ULONG dumpType,
    _In_ ULONG64 dumpOffset,
    _In_ ULONG dumpBufferLength
    )
{
    KBUGCHECK_DATA bugData;
    PkswordArkBugcheckDiagnostics diagnostics =
        &gKswordArkBugcheckState.diagnostics;

    RtlZeroMemory(&bugData, sizeof(bugData));
    bugData.BugCheckDataSize = sizeof(bugData);

    if (triageData != NULL) {
        diagnostics->bugCheckCode = triageData->BugCheckCode;
        diagnostics->parameter1 = triageData->BugCheckParameter1;
        diagnostics->parameter2 = triageData->BugCheckParameter2;
        diagnostics->parameter3 = triageData->BugCheckParameter3;
        diagnostics->parameter4 = triageData->BugCheckParameter4;
    } else if (NT_SUCCESS(AuxKlibGetBugCheckData(&bugData)) &&
               bugData.BugCheckDataSize >= sizeof(bugData)) {
        diagnostics->bugCheckCode = bugData.BugCheckCode;
        diagnostics->parameter1 = bugData.Parameter1;
        diagnostics->parameter2 = bugData.Parameter2;
        diagnostics->parameter3 = bugData.Parameter3;
        diagnostics->parameter4 = bugData.Parameter4;
    }

    diagnostics->lastReason = reason;
    diagnostics->lastDumpType = dumpType;
    diagnostics->dumpOffset = dumpOffset;
    diagnostics->dumpBufferLength = dumpBufferLength;
    diagnostics->irql = (ULONG)KeGetCurrentIrql();
    diagnostics->cpu = KeGetCurrentProcessorNumber();
    diagnostics->perfCounter = KeQueryPerformanceCounter(NULL);
    kswordArkBugcheckResolveProcessContext(diagnostics);
    kswordArkBugcheckResolveCandidate(diagnostics);
    InterlockedExchange(&diagnostics->captured, 1);

    kswordArkBugcheckUpdateSecondaryData();
}

static VOID
kswordArkBugcheckClassicCallback(
    _In_ PVOID buffer,
    _In_ ULONG length
    )
{
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(length);

    // Windows can paint over the classic callback. The late dump-I/O callback
    // owns the actual panel draw, so this callback intentionally performs no I/O.
    (VOID)InterlockedCompareExchange(
        &gKswordArkBugcheckState.classicDisplayStarted,
        1,
        0);
}

static VOID
kswordArkBugcheckReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON reason,
    _In_ PKBUGCHECK_REASON_CALLBACK_RECORD record,
    _Inout_ PVOID reasonSpecificData,
    _In_ ULONG reasonSpecificDataLength
    )
{
    PKBUGCHECK_SECONDARY_DUMP_DATA secondaryData;
    PKBUGCHECK_DUMP_IO dumpIoData;
    PKBUGCHECK_TRIAGE_DUMP_DATA triageData;
    ULONG dumpLength;

    UNREFERENCED_PARAMETER(record);

    if (reasonSpecificData == NULL ||
        InterlockedCompareExchange(&gKswordArkBugcheckState.active, 1, 1) == 0) {
        return;
    }

    if (reason == KbCallbackSecondaryDumpData) {
        if (reasonSpecificDataLength < sizeof(KBUGCHECK_SECONDARY_DUMP_DATA)) {
            return;
        }
        kswordArkBugcheckUpdateSecondaryData();
        secondaryData = (PKBUGCHECK_SECONDARY_DUMP_DATA)reasonSpecificData;
        dumpLength = sizeof(gKswordArkBugcheckSecondaryData);
        if (dumpLength > secondaryData->MaximumAllowed) {
            dumpLength = secondaryData->MaximumAllowed;
        }
        secondaryData->Guid = kGKswordArkBugcheckSecondaryGuid;
        secondaryData->OutBuffer = &gKswordArkBugcheckSecondaryData;
        secondaryData->OutBufferLength = dumpLength;
        return;
    }

    if (reason == KbCallbackTriageDumpData) {
        if (reasonSpecificDataLength < sizeof(KBUGCHECK_TRIAGE_DUMP_DATA)) {
            return;
        }
        triageData = (PKBUGCHECK_TRIAGE_DUMP_DATA)reasonSpecificData;
        kswordArkBugcheckCaptureData(
            triageData,
            reason,
            KbDumpIoInvalid,
            0,
            0);
        return;
    }

    if (reason == KbCallbackDumpIo) {
        if (reasonSpecificDataLength < sizeof(KBUGCHECK_DUMP_IO)) {
            return;
        }
        dumpIoData = (PKBUGCHECK_DUMP_IO)reasonSpecificData;
        kswordArkBugcheckCaptureData(
            NULL,
            reason,
            dumpIoData->Type,
            dumpIoData->Offset,
            dumpIoData->BufferLength);
        if ((dumpIoData->Type == KbDumpIoHeader ||
             dumpIoData->Type == KbDumpIoBody ||
             dumpIoData->Type == KbDumpIoSecondaryData) &&
            InterlockedCompareExchange(
                &gKswordArkBugcheckState.dumpDisplayStarted,
                1,
                0) == 0) {
            (VOID)kswordArkBugcheckPanelDraw(
                &gKswordArkBugcheckState.diagnostics,
                kswordArkBugcheckCallbackMask(),
                gKswordArkBugcheckState.moduleCount);
        }
    }
}

NTSTATUS
kswordArkBugcheckInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ WDFDEVICE controlDevice
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(ControlDevice);
    return STATUS_NOT_SUPPORTED;
#else
    NTSTATUS bgpStatus;
    NTSTATUS callbackStatus;
    NTSTATUS abortStatus;
    NTSTATUS logStatus;
    NTSTATUS panelStatus;

    if (driverObject == NULL || controlDevice == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }

    RtlZeroMemory(&gKswordArkBugcheckState, sizeof(gKswordArkBugcheckState));
    RtlZeroMemory(
        &gKswordArkBugcheckSecondaryData,
        sizeof(gKswordArkBugcheckSecondaryData));
    gKswordArkBugcheckState.driverObject = driverObject;
    gKswordArkBugcheckState.deviceObject =
        WdfDeviceWdmGetDeviceObject(controlDevice);
    gKswordArkBugcheckState.bitmap.brandColorRgb = 0x0078D4UL;
    KeInitializeSpinLock(&gKswordArkBugcheckState.moduleCacheLock);
    KeInitializeSpinLock(&gKswordArkBugcheckState.processCacheLock);
    InterlockedExchange(&gKswordArkBugcheckState.trackingReady, 1);

    panelStatus = STATUS_DEVICE_NOT_READY;
    bgpStatus = kswordArkBugcheckBgpInitialize();
    if (NT_SUCCESS(bgpStatus)) {
        panelStatus = kswordArkBugcheckPanelInitialize();
    } else {
        panelStatus = bgpStatus;
    }

    // Timeout or unloading cancellation constitutes a control-layer termination; no further BugCheck callbacks should be registered.
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }

    kswordArkBugcheckRefreshModuleCache();
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    kswordArkBugcheckRefreshProcessCache();
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    InterlockedExchange(&gKswordArkBugcheckState.active, 1);

    KeInitializeCallbackRecord(&gKswordArkBugcheckState.classicRecord);
    gKswordArkBugcheckState.classicRegistered =
        KeRegisterBugCheckCallback(
            &gKswordArkBugcheckState.classicRecord,
            kswordArkBugcheckClassicCallback,
            &gKswordArkBugcheckSecondaryData,
            sizeof(gKswordArkBugcheckSecondaryData),
            gKswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&gKswordArkBugcheckState.secondaryRecord);
    gKswordArkBugcheckState.secondaryRegistered =
        KeRegisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.secondaryRecord,
            kswordArkBugcheckReasonCallback,
            KbCallbackSecondaryDumpData,
            gKswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&gKswordArkBugcheckState.dumpIoRecord);
    gKswordArkBugcheckState.dumpIoRegistered =
        KeRegisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.dumpIoRecord,
            kswordArkBugcheckReasonCallback,
            KbCallbackDumpIo,
            gKswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&gKswordArkBugcheckState.triageRecord);
    gKswordArkBugcheckState.triageRegistered =
        KeRegisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.triageRecord,
            kswordArkBugcheckReasonCallback,
            KbCallbackTriageDumpData,
            gKswordArkBugcheckComponent);

    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        kswordArkBugcheckUninitialize();
        return abortStatus;
    }

    // Persist both successful and failed preparation results before a target
    // machine can be crashed for display testing.
    callbackStatus =
        gKswordArkBugcheckState.classicRegistered &&
        gKswordArkBugcheckState.secondaryRegistered &&
        gKswordArkBugcheckState.dumpIoRegistered &&
        gKswordArkBugcheckState.triageRegistered
            ? STATUS_SUCCESS
            : STATUS_UNSUCCESSFUL;
    logStatus = kswordArkBugcheckWritePreparationLog(
        bgpStatus,
        panelStatus,
        callbackStatus);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        NT_SUCCESS(logStatus) ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
        "KswordARK: BGP preparation=0x%08lX panel=0x%08lX "
        "callbacks=0x%08lX report=0x%08lX\n",
        (ULONG)bgpStatus,
        (ULONG)panelStatus,
        (ULONG)callbackStatus,
        (ULONG)logStatus);

    if (!gKswordArkBugcheckState.classicRegistered ||
        !gKswordArkBugcheckState.secondaryRegistered ||
        !gKswordArkBugcheckState.dumpIoRegistered ||
        !gKswordArkBugcheckState.triageRegistered) {
        kswordArkBugcheckUninitialize();
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
#endif
}

VOID
kswordArkBugcheckUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    InterlockedExchange(&gKswordArkBugcheckState.trackingReady, 0);
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBugcheckState.active, 0);
    InterlockedExchange(&gKswordArkBugcheckState.bitmap.valid, 0);

    if (gKswordArkBugcheckState.triageRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.triageRecord);
        gKswordArkBugcheckState.triageRegistered = FALSE;
    }
    if (gKswordArkBugcheckState.dumpIoRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.dumpIoRecord);
        gKswordArkBugcheckState.dumpIoRegistered = FALSE;
    }
    if (gKswordArkBugcheckState.secondaryRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &gKswordArkBugcheckState.secondaryRecord);
        gKswordArkBugcheckState.secondaryRegistered = FALSE;
    }
    if (gKswordArkBugcheckState.classicRegistered) {
        (VOID)KeDeregisterBugCheckCallback(
            &gKswordArkBugcheckState.classicRecord);
        gKswordArkBugcheckState.classicRegistered = FALSE;
    }

    kswordArkBugcheckPanelShutdown();
    kswordArkBugcheckBgpShutdown();
#endif
}
