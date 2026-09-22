/*++

Module Name:

    driver_unload.c

Abstract:

    Force DriverObject unload by name.

Environment:

    Kernel-mode Driver Framework

--*/

#define KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL 1
#include "../callback/callback_external_core.h"

#include "ark/ark_driver.h"
#include "ark/ark_thread.h"
#include "driver_integrity.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* Note: Wait for the DriverUnload system thread for 3 seconds by default to prevent infinite UI blocking. */
#define KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS 3000UL
/* Note: Maximum wait time is 30 seconds to prevent malicious or abnormal DriverUnload from hanging the caller. */
#define KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS 30000UL
/* Note: The unload thread context uses an independent tag to facilitate pool leak debugging. */
#define KSW_DRIVER_UNLOAD_TAG 'uDsK'
/* Note: enumerate object directory buffer tag as fallback when service name and DriverObject name differ. */
#define KSW_DRIVER_UNLOAD_DIRECTORY_TAG 'dDsK'
/* Note: DeviceObject cleanup traverses at most 128 nodes to avoid corrupting the linked list and causing an infinite loop. */
#define KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT 128UL
/* Note: Object directory single-query buffer is 16KB, sufficient to hold abnormally long object names. */
#define KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES (16UL * 1024UL)
/* Note: Scan up to 4096 entries per directory to prevent abnormal object directories from causing prolonged IOCTL occupation. */
#define KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES 4096UL
/* Note: Forcefully clean up at most 256 callbacks by module base address to prevent abnormal enumeration from causing prolonged IOCTL occupation. */
#define KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT 256UL
/* Note: Thread evidence scanning traverses at most 4096 processes to avoid hanging the IOCTL due to abnormal system linkages. */
#define KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES 4096UL
/* Note: Thread scan/force termination traverses at most 65536 threads. */
#define KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS 65536UL
/* Note: Forcefully wait 1 second per thread; do not continue calling the target DriverUnload if the exit is not confirmed. */
#define KSW_DRIVER_UNLOAD_THREAD_TERMINATE_WAIT_MS 1000UL
/* Note: After closing the entry, perform at most three termination/rescan passes to converge on target driver threads created concurrently. */
#define KSW_DRIVER_UNLOAD_THREAD_TERMINATE_PASSES 3UL

/* Note: SystemModuleInformation is used to map callback addresses to kernel module base addresses. */
#define KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS 11UL
/* Note: Inspect at most 128 DeviceObject instances before a forced unload, matching the deletion limit. */
#define KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT
/* Note: The large read-only workspace for pre-check uses an independent tag to avoid consuming kernel thread stack space. */
#define KSW_DRIVER_UNLOAD_PREFLIGHT_TAG 'pDsK'
/* Note: Briefly retry after releasing the last DriverObject reference to wait for the object manager/loader to complete synchronous cleanup. */
#define KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES 5UL
/* Note: Wait 20ms between each closed-loop verification to avoid prolonged IOCTL occupation. */
#define KSW_DRIVER_UNLOAD_POST_VERIFY_DELAY_MS 20UL

#ifndef STATUS_REQUEST_NOT_ACCEPTED
/* Note: Strategy to supplement missing status codes when old WDK headers are absent, used for preflight rejection. */
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#ifndef STATUS_DRIVER_BLOCKED_CRITICAL
/* Note: Supplement core driver rejection status codes when old WDK headers are missing. */
#define STATUS_DRIVER_BLOCKED_CRITICAL ((NTSTATUS)0xC000036BL)
#endif

#ifndef THREAD_ALL_ACCESS
/* Note: Supplement missing thread full access mask in older WDK headers for use by PsCreateSystemThread. */
#define THREAD_ALL_ACCESS 0x001FFFFFUL
#endif

#ifndef DIRECTORY_QUERY
/* Note: Some WDK headers do not expose directory object access flags; define DIRECTORY_QUERY per NT definitions. */
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
/* Note: ZwQueryDirectoryObject often returns this warning status when the scan ends. */
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef STATUS_IMAGE_ALREADY_LOADED
/* Note: Supplement the failure status for 'image still in loader list' when older WDK headers are missing. */
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif

/* Note: Layout of a single object directory information entry returned by ZwQueryDirectoryObject. */
typedef struct KswObjectDirectoryInformation
{
    UNICODE_STRING name;
    UNICODE_STRING typeName;
} KswObjectDirectoryInformation, *PkswObjectDirectoryInformation;

/* Note: Naming DriverObject to reference the entry point, maintaining the same policy as in driver_object_query.c. */
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

/* Note: IoDriverObjectType provides type constraints for ObReferenceObjectByName. */
extern POBJECT_TYPE* IoDriverObjectType;

/* Note: ObMakeTemporaryObject allows the object manager to reclaim the named object once its reference count reaches zero. */
NTSYSAPI
VOID
NTAPI
ObMakeTemporaryObject(
    _In_ PVOID object
    );

/* Note: Prefer using the native Windows I/O manager unload path instead of manually calling DriverUnload. */
NTSYSAPI
NTSTATUS
NTAPI
ZwUnloadDriver(
    _In_ PUNICODE_STRING driverServiceName
    );

/* Note: Open the NT object directory to fall back to finding the DriverObject by ServiceKeyName. */
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE directoryHandle,
    _In_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_ATTRIBUTES objectAttributes
    );

/* Note: enumerate NT object directory entries, following the SKT64 directory scanning approach but using public Zw APIs. */
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE directoryHandle,
    _Out_writes_bytes_opt_(length) PVOID buffer,
    _In_ ULONG length,
    _In_ BOOLEAN returnSingleEntry,
    _In_ BOOLEAN restartScan,
    _Inout_ PULONG context,
    _Out_opt_ PULONG returnLength
    );

/* Note: Query the system module table to verify the callback function address belongs to the target module. */
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

/* Note: Dynamically resolve PsGetNextProcess for strong unload preflight to read-only scan for thread residency evidence. */
typedef PEPROCESS(NTAPI* KswDriverUnloadPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

/* Note: Dynamically resolve psGetNextProcessThread for strong unload preflight to scan and retain evidence from resident threads. */
typedef PETHREAD(NTAPI* KswDriverUnloadPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

/* Note: The unload thread context is held by both the parent thread and the worker thread; the last reference is responsible for releasing it. */
typedef struct KswDriverUnloadContext
{
    volatile LONG referenceCount;
    PDRIVER_OBJECT driverObject;
    ULONG flags;
    NTSTATUS unloadStatus;
    NTSTATUS cleanupStatus;
    PDRIVER_UNLOAD driverUnload;
    ULONG deletedDeviceCount;
    ULONG detachedDeviceCount;
    ULONG threadCandidates;
    ULONG threadsTerminated;
    ULONG threadFailures;
    NTSTATUS threadLastStatus;
    ULONG callbackCandidates;
    ULONG callbacksRemoved;
    ULONG callbackFailures;
    NTSTATUS callbackLastStatus;
    ULONG cleanupFlagsApplied;
    BOOLEAN attemptDirectUnload;
    ULONGLONG driverStart;
    ULONGLONG driverEnd;
    WCHAR serviceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KswDriverUnloadContext, *PkswDriverUnloadContext;

/* Note: Save DriverObject entry points and device flags to enable rollback if forced removal fails before unloading. */
typedef struct KswDriverUnloadEntryTransaction
{
    PFAST_IO_DISPATCH originalFastIoDispatch;
    PDRIVER_DISPATCH originalMajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1UL];
    PDEVICE_OBJECT deviceObjects[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG originalDeviceFlags[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG deviceCount;
    BOOLEAN applied;
} KswDriverUnloadEntryTransaction, *PkswDriverUnloadEntryTransaction;

/* Note: Result of processing target image resident threads during the DriverObject force-removal phase. */
typedef struct KswDriverUnloadThreadCleanupResult
{
    ULONG candidates;
    ULONG terminated;
    ULONG failures;
    NTSTATUS lastStatus;
} KswDriverUnloadThreadCleanupResult, *PkswDriverUnloadThreadCleanupResult;

/* Note: The ZwUnloadDriver thread context does not retain the DriverObject to avoid blocking system unloading with extra object references. */
typedef struct KswDriverUnloadZwContext
{
    volatile LONG referenceCount;
    NTSTATUS unloadStatus;
    WCHAR serviceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KswDriverUnloadZwContext, *PkswDriverUnloadZwContext;
static VOID
kswordArkDriverUnloadReleaseContext(
    _Inout_ PkswDriverUnloadContext context
    )
{
    if (context != NULL &&
        InterlockedDecrement(&context->referenceCount) == 0L) {
        ExFreePoolWithTag(context, KSW_DRIVER_UNLOAD_TAG);
    }
}

static VOID
kswordArkDriverUnloadReleaseZwContext(
    _Inout_ PkswDriverUnloadZwContext context
    )
{
    if (context != NULL &&
        InterlockedDecrement(&context->referenceCount) == 0L) {
        ExFreePoolWithTag(context, KSW_DRIVER_UNLOAD_TAG);
    }
}

/* Note: Layout of a single entry from ZwQuerySystemInformation(SystemModuleInformation). */
typedef struct KswDriverUnloadSystemModuleEntry
{
    HANDLE section;
    PVOID mappedBase;
    PVOID imageBase;
    ULONG imageSize;
    ULONG flags;
    USHORT loadOrderIndex;
    USHORT initOrderIndex;
    USHORT loadCount;
    USHORT offsetToFileName;
    UCHAR fullPathName[256];
} KswDriverUnloadSystemModuleEntry, *PkswDriverUnloadSystemModuleEntry;

/* Note: System module table header; Modules is the first element of a variable-length array. */
typedef struct KswDriverUnloadSystemModuleInformation
{
    ULONG numberOfModules;
    KswDriverUnloadSystemModuleEntry modules[1];
} KswDriverUnloadSystemModuleInformation, *PkswDriverUnloadSystemModuleInformation;

/* Note: Aggregated count for forceful cleanup callbacks, eventually written back to the R3 response. */
typedef struct KswDriverUnloadCallbackCleanupResult
{
    ULONG candidates;
    ULONG removed;
    ULONG failures;
    NTSTATUS lastStatus;
} KswDriverUnloadCallbackCleanupResult, *PkswDriverUnloadCallbackCleanupResult;

/* Note: Strong unload preflight targets module callback resident evidence without directly rewriting the callback table. */
typedef struct KswDriverUnloadCallbackEvidenceResult
{
    ULONG enumerated;
    ULONG matched;
    ULONG removable;
    ULONG nonRemovable;
    NTSTATUS lastStatus;
    BOOLEAN truncated;
} KswDriverUnloadCallbackEvidenceResult, *PkswDriverUnloadCallbackEvidenceResult;

/* Note: Evidence for read-only consistency between the loader chain and the PE header of the image; no chain unloading or header erasure is performed. */
typedef struct KswDriverUnloadLoaderImageEvidence
{
    NTSTATUS loaderLinkStatus;
    NTSTATUS imageHeaderStatus;
    ULONG imageHeaderSizeOfImage;
    ULONG imageNtHeaderOffset;
    BOOLEAN loaderLinkChecked;
    BOOLEAN loaderLinkMismatch;
    BOOLEAN imageHeaderChecked;
    BOOLEAN invalidImageHeader;
} KswDriverUnloadLoaderImageEvidence, *PkswDriverUnloadLoaderImageEvidence;

/* Note: Pre-flight unload result; all fields are used solely to determine whether to allow destructive steps. */
typedef struct KswDriverUnloadPreflightResult
{
    BOOLEAN allowZwUnload;
    BOOLEAN allowDirectUnload;
    BOOLEAN allowDestructiveCleanup;
    BOOLEAN hasServiceRegistryPath;
    BOOLEAN hasDriverUnload;
    BOOLEAN hasValidDynData;
    BOOLEAN hasPdbBackedDynData;
    BOOLEAN hasValidDriverObjectOffsets;
    BOOLEAN hasValidLoaderEvidence;
    BOOLEAN hasDeviceChain;
    BOOLEAN hasCrossDriverAttach;
    BOOLEAN hasDeviceLoop;
    BOOLEAN hasAttachedDevice;
    BOOLEAN hasBusyDeviceReference;
    BOOLEAN hasThreadScan;
    BOOLEAN hasModuleResidentThreads;
    BOOLEAN hasCallbackScan;
    BOOLEAN hasModuleCallbacks;
    BOOLEAN hasNonRemovableModuleCallbacks;
    BOOLEAN hasLoaderLinkCheck;
    BOOLEAN hasLoaderLinkMismatch;
    BOOLEAN hasImageHeaderCheck;
    BOOLEAN hasInvalidImageHeader;
    BOOLEAN isCoreKernelModule;
    BOOLEAN isSelfModule;
    ULONGLONG driverStart;
    ULONGLONG driverEnd;
    ULONGLONG loaderEntryAddress;
    ULONGLONG loaderDllBase;
    ULONG loaderSizeOfImage;
    ULONG scannedProcessCount;
    ULONG scannedThreadCount;
    ULONG moduleResidentThreadCount;
    NTSTATUS threadScanStatus;
    ULONG callbackEnumeratedCount;
    ULONG moduleCallbackCount;
    ULONG removableModuleCallbackCount;
    ULONG nonRemovableModuleCallbackCount;
    NTSTATUS callbackScanStatus;
    NTSTATUS loaderLinkStatus;
    NTSTATUS imageHeaderStatus;
    ULONG imageHeaderSizeOfImage;
    ULONG imageNtHeaderOffset;
    NTSTATUS status;
    WCHAR serviceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KswDriverUnloadPreflightResult, *PkswDriverUnloadPreflightResult;

/* Note: DynData snapshots and device access tables are uniformly allocated in non-paged pool during nested evidence scanning. */
typedef struct KswDriverUnloadPreflightWorkspace
{
    KswDynState dynState;
    PDEVICE_OBJECT visitedDevices[KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT];
} KswDriverUnloadPreflightWorkspace, *PkswDriverUnloadPreflightWorkspace;

/* Note: Compress internal preflight results into a diagnostic snapshot printable by the handler. */
static VOID
kswordArkDriverUnloadCapturePreflightDiagnostics(
    _Out_ KswDriverUnloadDiagnostics* diagnostics,
    _In_ const KswDriverUnloadPreflightResult* preflight
    )
{
    if (diagnostics == NULL || preflight == NULL) {
        return;
    }

    diagnostics->preflightStatus = preflight->status;
    diagnostics->allowZwUnload = preflight->allowZwUnload;
    diagnostics->allowDirectUnload = preflight->allowDirectUnload;
    diagnostics->allowDestructiveCleanup = preflight->allowDestructiveCleanup;
    diagnostics->hasServiceRegistryPath = preflight->hasServiceRegistryPath;
    diagnostics->hasDriverUnload = preflight->hasDriverUnload;
    diagnostics->hasValidDynData = preflight->hasValidDynData;
    diagnostics->hasPdbBackedDynData = preflight->hasPdbBackedDynData;
    diagnostics->hasValidDriverObjectOffsets = preflight->hasValidDriverObjectOffsets;
    diagnostics->hasValidLoaderEvidence = preflight->hasValidLoaderEvidence;
    diagnostics->hasDeviceChain = preflight->hasDeviceChain;
    diagnostics->hasCrossDriverAttach = preflight->hasCrossDriverAttach;
    diagnostics->hasDeviceLoop = preflight->hasDeviceLoop;
    diagnostics->hasAttachedDevice = preflight->hasAttachedDevice;
    diagnostics->hasBusyDeviceReference = preflight->hasBusyDeviceReference;
    diagnostics->hasThreadScan = preflight->hasThreadScan;
    diagnostics->hasModuleResidentThreads = preflight->hasModuleResidentThreads;
    diagnostics->hasCallbackScan = preflight->hasCallbackScan;
    diagnostics->hasModuleCallbacks = preflight->hasModuleCallbacks;
    diagnostics->hasNonRemovableModuleCallbacks = preflight->hasNonRemovableModuleCallbacks;
    diagnostics->hasLoaderLinkCheck = preflight->hasLoaderLinkCheck;
    diagnostics->hasLoaderLinkMismatch = preflight->hasLoaderLinkMismatch;
    diagnostics->hasImageHeaderCheck = preflight->hasImageHeaderCheck;
    diagnostics->hasInvalidImageHeader = preflight->hasInvalidImageHeader;
    diagnostics->isCoreKernelModule = preflight->isCoreKernelModule;
    diagnostics->isSelfModule = preflight->isSelfModule;
    diagnostics->driverStart = preflight->driverStart;
    diagnostics->loaderEntryAddress = preflight->loaderEntryAddress;
    diagnostics->loaderDllBase = preflight->loaderDllBase;
    diagnostics->loaderSizeOfImage = preflight->loaderSizeOfImage;
    diagnostics->scannedProcessCount = preflight->scannedProcessCount;
    diagnostics->scannedThreadCount = preflight->scannedThreadCount;
    diagnostics->moduleResidentThreadCount = preflight->moduleResidentThreadCount;
    diagnostics->threadScanStatus = preflight->threadScanStatus;
    diagnostics->callbackEnumeratedCount = preflight->callbackEnumeratedCount;
    diagnostics->moduleCallbackCount = preflight->moduleCallbackCount;
    diagnostics->removableModuleCallbackCount = preflight->removableModuleCallbackCount;
    diagnostics->nonRemovableModuleCallbackCount = preflight->nonRemovableModuleCallbackCount;
    diagnostics->callbackScanStatus = preflight->callbackScanStatus;
    diagnostics->loaderLinkStatus = preflight->loaderLinkStatus;
    diagnostics->imageHeaderStatus = preflight->imageHeaderStatus;
    diagnostics->imageHeaderSizeOfImage = preflight->imageHeaderSizeOfImage;
    diagnostics->imageNtHeaderOffset = preflight->imageNtHeaderOffset;
}

/* Note: Process Ex notify function signature, used to call public Ps* removal APIs during batch removal. */
typedef VOID
(*KswDriverUnloadProcessNotifyEx)(
    _Inout_ PEPROCESS process,
    _In_ HANDLE processId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo
    );

/* Note: Thread notify function signature for use with PsRemoveCreateThreadNotifyRoutine. */
typedef VOID
(*KswDriverUnloadThreadNotify)(
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ BOOLEAN create
    );

/* Note: Signature for the image load notification function, used by PsRemoveLoadImageNotifyRoutine. */
typedef VOID
(*KswDriverUnloadImageNotify)(
    _In_opt_ PUNICODE_STRING fullImageName,
    _In_ HANDLE processId,
    _In_ PIMAGE_INFO imageInfo
    );

/* Note: ASCII-range wide-character uppercase conversion is used exclusively for comparing NT object directory names and service names. */
static WCHAR
kswordArkDriverUnloadUpcaseAscii(
    _In_ WCHAR character
    )
{
    if (character >= L'a' && character <= L'z') {
        return (WCHAR)(character - L'a' + L'A');
    }
    return character;
}

/* Note: Compare the prefix of two NUL-terminated wide strings, ignoring ASCII case. */
static BOOLEAN
kswordArkDriverUnloadStartsWithInsensitive(
    _In_z_ const WCHAR* text,
    _In_z_ const WCHAR* prefix
    )
{
    ULONG index = 0UL;

    // Input: two NUL-terminated strings; Processing: per-character ASCII case normalization.
    // Returns TRUE if Text has the Prefix prefix; returns FALSE if any argument is null or characters do not match.
    if (text == NULL || prefix == NULL) {
        return FALSE;
    }

    while (prefix[index] != L'\0') {
        if (kswordArkDriverUnloadUpcaseAscii(text[index]) !=
            kswordArkDriverUnloadUpcaseAscii(prefix[index])) {
            return FALSE;
        }
        ++index;
    }

    return TRUE;
}

/* Note: Compare if a limited-length ANSI filename ends with a specified suffix, ignoring case. */
static BOOLEAN
kswordArkDriverUnloadAnsiEndsWithInsensitive(
    _In_reads_bytes_(textBytes) const UCHAR* text,
    _In_ ULONG textBytes,
    _In_z_ PCSTR suffix
    )
{
    ULONG textChars = 0UL;
    ULONG suffixChars = 0UL;
    ULONG index = 0UL;

    // Input: A finite-length ANSI filename and a NUL-terminated suffix from SystemModuleInformation.
    // Handling: Calculate the actual length first, then compare characters from the end in lowercase ASCII.
    // Return: TRUE if Text ends with the suffix; FALSE if input is invalid, length is insufficient, or mismatch occurs.
    if (text == NULL || textBytes == 0UL || suffix == NULL) {
        return FALSE;
    }
    while (textChars < textBytes && text[textChars] != '\0') {
        ++textChars;
    }
    while (suffix[suffixChars] != '\0') {
        ++suffixChars;
    }
    if (suffixChars == 0UL || textChars < suffixChars) {
        return FALSE;
    }
    for (index = 0UL; index < suffixChars; ++index) {
        CHAR left = (CHAR)text[textChars - suffixChars + index];
        CHAR right = suffix[index];
        if (left >= 'A' && left <= 'Z') {
            left = (CHAR)(left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (CHAR)(right + ('a' - 'A'));
        }
        if (left != right) {
            return FALSE;
        }
    }
    return TRUE;
}

/* Note: Check if the NT object path has the specified prefix; comparison is case-insensitive. */
static BOOLEAN
kswordArkDriverUnloadNameHasPrefix(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _In_z_ const WCHAR* prefix
    )
{
    ULONG index = 0UL;

    if (objectName == NULL || prefix == NULL) {
        return FALSE;
    }

    while (prefix[index] != L'\0') {
        WCHAR left = kswordArkDriverUnloadUpcaseAscii(objectName[index]);
        WCHAR right = kswordArkDriverUnloadUpcaseAscii(prefix[index]);

        if (left != right) {
            return FALSE;
        }
        ++index;
    }

    return TRUE;
}

/* Note: Extract the leaf name from \Driver\X or \FileSystem\Filters\X. */
static NTSTATUS
kswordArkDriverUnloadExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _Out_writes_(leafChars) PWCHAR leafName,
    _In_ ULONG leafChars
    )
{
    ULONG index = 0UL;
    ULONG leafStart = 0UL;

    if (objectName == NULL || leafName == NULL || leafChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    leafName[0] = L'\0';
    while (index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        objectName[index] != L'\0') {
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

/* Note: Calculate the length of a fixed NUL-terminated WCHAR string, checking up to the protocol-allowed length. */
static ULONG
kswordArkDriverUnloadCountFixedStringChars(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* text
    )
{
    ULONG chars = 0UL;

    if (text == NULL) {
        return 0UL;
    }

    while (chars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        text[chars] != L'\0') {
        ++chars;
    }
    return chars;
}

/* Note: Safely copy UNICODE_STRING to a NUL-terminated fixed buffer. */
static NTSTATUS
kswordArkDriverUnloadCopyUnicodeToFixed(
    _In_opt_ PCUNICODE_STRING sourceName,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
{
    ULONG charsToCopy = 0UL;

    // Input: kernel UNICODE_STRING and fixed output buffer.
    // Processing: Limit copy by Length; SourceName itself does not need to be NUL-terminated.
    // Returns: STATUS_SUCCESS on successful copy; parameter error if the source is missing or the buffer is invalid.
    if (sourceName == NULL ||
        sourceName->Buffer == NULL ||
        sourceName->Length == 0 ||
        destination == NULL ||
        destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    charsToCopy = (ULONG)(sourceName->Length / sizeof(WCHAR));
    if (charsToCopy == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (charsToCopy >= destinationChars) {
        charsToCopy = destinationChars - 1UL;
    }

    RtlCopyMemory(destination, sourceName->Buffer, (SIZE_T)charsToCopy * sizeof(WCHAR));
    destination[charsToCopy] = L'\0';
    return STATUS_SUCCESS;
}

/* Note: Forward declaration for reusing the last-level object name extraction logic in registry path construction. */
static NTSTATUS
kswordArkDriverUnloadExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _Out_writes_(leafChars) PWCHAR leafName,
    _In_ ULONG leafChars
    );

/* Note: Derive the service registry path required by ZwUnloadDriver from DriverObject/ServiceKeyName. */
static NTSTATUS
kswordArkDriverUnloadBuildServiceRegistryPath(
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* normalizedDriverName,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
{
    WCHAR serviceName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    // Input: referenced DriverObject and normalized object name.
    // Handling: Prefer DriverExtension->ServiceKeyName; if it is already an absolute registry path, use it as-is;
    //      Otherwise, append to HKLM\SYSTEM\CurrentControlSet\Services using the service name.
    // Return: Complete NT registry path on success; returns corresponding NTSTATUS on failure.
    if (destination == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destination[0] = L'\0';

    __try {
        if (driverObject != NULL && driverObject->DriverExtension != NULL) {
            status = kswordArkDriverUnloadCopyUnicodeToFixed(
                &driverObject->DriverExtension->ServiceKeyName,
                serviceName,
                RTL_NUMBER_OF(serviceName));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) || serviceName[0] == L'\0') {
        if (normalizedDriverName != NULL &&
            NT_SUCCESS(kswordArkDriverUnloadExtractLeafName(
                normalizedDriverName,
                serviceName,
                RTL_NUMBER_OF(serviceName)))) {
            status = STATUS_SUCCESS;
        }
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    if (kswordArkDriverUnloadStartsWithInsensitive(
        serviceName,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchCopyW(destination, destinationChars, serviceName);
    }
    if (kswordArkDriverUnloadStartsWithInsensitive(serviceName, L"System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchPrintfW(
            destination,
            destinationChars,
            L"\\Registry\\Machine\\%ws",
            serviceName);
    }
    if (kswordArkDriverUnloadStartsWithInsensitive(serviceName, L"\\System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchPrintfW(
            destination,
            destinationChars,
            L"\\Registry\\Machine%ws",
            serviceName);
    }

    return RtlStringCchPrintfW(
        destination,
        destinationChars,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws",
        serviceName);
}

/* Note: Compares the last component of the UNICODE_STRING with a fixed string, ignoring ASCII case. */
static BOOLEAN
kswordArkDriverUnloadUnicodeLeafEqualsFixed(
    _In_opt_ PCUNICODE_STRING sourceName,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* expectedLeaf
    )
{
    ULONG sourceChars = 0UL;
    ULONG expectedChars = 0UL;
    ULONG leafStart = 0UL;
    ULONG leafChars = 0UL;
    ULONG index = 0UL;

    if (sourceName == NULL ||
        sourceName->Buffer == NULL ||
        sourceName->Length == 0 ||
        expectedLeaf == NULL) {
        return FALSE;
    }

    sourceChars = (ULONG)(sourceName->Length / sizeof(WCHAR));
    expectedChars = kswordArkDriverUnloadCountFixedStringChars(expectedLeaf);
    if (sourceChars == 0UL || expectedChars == 0UL ||
        expectedChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return FALSE;
    }

    for (index = 0UL; index < sourceChars; ++index) {
        if (sourceName->Buffer[index] == L'\\') {
            leafStart = index + 1UL;
        }
    }
    if (leafStart >= sourceChars) {
        return FALSE;
    }

    leafChars = sourceChars - leafStart;
    if (leafChars != expectedChars) {
        return FALSE;
    }

    for (index = 0UL; index < expectedChars; ++index) {
        WCHAR left = kswordArkDriverUnloadUpcaseAscii(sourceName->Buffer[leafStart + index]);
        WCHAR right = kswordArkDriverUnloadUpcaseAscii(expectedLeaf[index]);

        if (left != right) {
            return FALSE;
        }
    }

    return TRUE;
}

/* Note: Check if a referenced DriverObject belongs to the specified service name. */
static BOOLEAN
kswordArkDriverUnloadDriverObjectMatchesServiceLeaf(
    _In_ PDRIVER_OBJECT driverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* serviceLeaf
    )
{
    BOOLEAN matches = FALSE;

    if (driverObject == NULL || serviceLeaf == NULL) {
        return FALSE;
    }

    __try {
        if (driverObject->DriverExtension != NULL &&
            kswordArkDriverUnloadUnicodeLeafEqualsFixed(
                &driverObject->DriverExtension->ServiceKeyName,
                serviceLeaf)) {
            matches = TRUE;
        }
        else if (kswordArkDriverUnloadUnicodeLeafEqualsFixed(
            &driverObject->DriverName,
            serviceLeaf)) {
            matches = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }

    return matches;
}

/* Note: Copy the name from the shared protocol into the full DriverObject object path. */
static NTSTATUS
kswordArkDriverUnloadBuildObjectName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* sourceName,
    _Out_writes_(destinationChars) PWCHAR destinationName,
    _In_ ULONG destinationChars
    )
{
    ULONG inputChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (sourceName == NULL || destinationName == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destinationName[0] = L'\0';

    while (inputChars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        sourceName[inputChars] != L'\0') {
        ++inputChars;
    }
    if (inputChars == 0UL || inputChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (sourceName[0] == L'\\') {
        /*
         * Note: When R3 manually inputs a complete object path, keep it as-is. Supports real
         * DriverObject names such as \Driver\X, \FileSystem\X, and \FileSystem\Filters\X.
         */
        status = RtlStringCchCopyNW(
            destinationName,
            destinationChars,
            sourceName,
            inputChars);
    }
    else {
        status = RtlStringCchPrintfW(
            destinationName,
            destinationChars,
            L"\\Driver\\%ws",
            sourceName);
    }

    return status;
}

/* Note: Open an object directory and return the underlying NTSTATUS on failure. */
static NTSTATUS
kswordArkDriverUnloadOpenDirectory(
    _In_z_ const WCHAR* directoryNameArg,
    _Out_ HANDLE* directoryHandleOut
    )
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (directoryNameArg == NULL || directoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *directoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, directoryNameArg);
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    return ZwOpenDirectoryObject(
        directoryHandleOut,
        DIRECTORY_QUERY,
        &objectAttributes);
}

/* Note: Attempt to reference a complete DriverObject path; return the referenced object upon success. */
static NTSTATUS
kswordArkDriverUnloadReferenceCandidateName(
    _In_z_ const WCHAR* candidateName,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    UNICODE_STRING objectName;
    NTSTATUS status = STATUS_SUCCESS;

    if (candidateName == NULL ||
        driverObjectOut == NULL ||
        normalizedNameOut == NULL ||
        nameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    status = RtlStringCchCopyW(normalizedNameOut, nameChars, candidateName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&objectName, normalizedNameOut);
    /* Note: ObReferenceObjectByName returns an object reference, not a handle, so OBJ_KERNEL_HANDLE must not be used. */
    status = ObReferenceObjectByName(
        &objectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)driverObjectOut);
    if (!NT_SUCCESS(status)) {
        *driverObjectOut = NULL;
    }
    return status;
}

/* Note: Concatenate 'directory path + sub-object name' to form the complete candidate DriverObject path. */
static NTSTATUS
kswordArkDriverUnloadBuildDirectoryCandidateName(
    _In_z_ const WCHAR* directoryName,
    _In_ PCUNICODE_STRING entryName,
    _Out_writes_(candidateChars) PWCHAR candidateName,
    _In_ ULONG candidateChars
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG directoryChars = 0UL;

    if (directoryName == NULL ||
        entryName == NULL ||
        entryName->Buffer == NULL ||
        entryName->Length == 0 ||
        candidateName == NULL ||
        candidateChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    candidateName[0] = L'\0';
    status = RtlStringCchCopyW(candidateName, candidateChars, directoryName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    directoryChars = kswordArkDriverUnloadCountFixedStringChars(candidateName);
    if (directoryChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (candidateName[directoryChars - 1UL] != L'\\') {
        status = RtlStringCchCatW(candidateName, candidateChars, L"\\");
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return RtlStringCchCatNW(
        candidateName,
        candidateChars,
        entryName->Buffer,
        (size_t)(entryName->Length / sizeof(WCHAR)));
}

/* Note: Fallback search for DriverObject by ServiceKeyName/DriverName within an object directory. */
static NTSTATUS
kswordArkDriverUnloadReferenceByServiceLeafInDirectory(
    _In_z_ const WCHAR* directoryName,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* serviceLeaf,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    HANDLE directoryHandle = NULL;
    PkswObjectDirectoryInformation entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;

    if (directoryName == NULL ||
        serviceLeaf == NULL ||
        driverObjectOut == NULL ||
        normalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    status = kswordArkDriverUnloadOpenDirectory(directoryName, &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    entry = (PkswObjectDirectoryInformation)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (scannedEntries < KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES) {
        WCHAR candidateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        PDRIVER_OBJECT candidateObject = NULL;
        NTSTATUS candidateStatus = STATUS_SUCCESS;

        RtlZeroMemory(entry, KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;
            break;
        }
        if (!NT_SUCCESS(status)) {
            finalStatus = status;
            break;
        }

        ++scannedEntries;
        if (entry->name.Buffer == NULL || entry->name.Length == 0) {
            continue;
        }

        candidateStatus = kswordArkDriverUnloadBuildDirectoryCandidateName(
            directoryName,
            &entry->name,
            candidateName,
            RTL_NUMBER_OF(candidateName));
        if (!NT_SUCCESS(candidateStatus)) {
            finalStatus = candidateStatus;
            continue;
        }

        candidateStatus = kswordArkDriverUnloadReferenceCandidateName(
            candidateName,
            &candidateObject,
            normalizedNameOut,
            nameChars);
        if (!NT_SUCCESS(candidateStatus)) {
            if (candidateStatus != STATUS_OBJECT_TYPE_MISMATCH) {
                finalStatus = candidateStatus;
            }
            continue;
        }

        if (kswordArkDriverUnloadDriverObjectMatchesServiceLeaf(candidateObject, serviceLeaf)) {
            *driverObjectOut = candidateObject;
            ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
            ZwClose(directoryHandle);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(candidateObject);
    }

    ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ZwClose(directoryHandle);
    return finalStatus;
}

/* Note: Reference the SKT64 object directory traversal approach; use ServiceKeyName to handle drivers with inconsistent names. */
static NTSTATUS
kswordArkDriverUnloadReferenceByServiceLeaf(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* serviceLeaf,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    static const WCHAR* const kDirectoriesToScan[] = {
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters"
    };
    ULONG directoryIndex = 0UL;
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

    if (serviceLeaf == NULL || driverObjectOut == NULL || normalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    for (directoryIndex = 0UL;
        directoryIndex < RTL_NUMBER_OF(kDirectoriesToScan);
        ++directoryIndex) {
        NTSTATUS scanStatus = kswordArkDriverUnloadReferenceByServiceLeafInDirectory(
            kDirectoriesToScan[directoryIndex],
            serviceLeaf,
            driverObjectOut,
            normalizedNameOut,
            nameChars);

        if (NT_SUCCESS(scanStatus)) {
            return STATUS_SUCCESS;
        }
        if (scanStatus != STATUS_OBJECT_NAME_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_PATH_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_TYPE_MISMATCH) {
            status = scanStatus;
        }
    }

    return status;
}

/* Note: Check if the DriverObject's image base matches the base in the module table. */
static BOOLEAN
kswordArkDriverUnloadDriverObjectMatchesModuleBase(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONGLONG targetModuleBase
    )
{
    BOOLEAN matches = FALSE;

    if (driverObject == NULL || targetModuleBase == 0ULL) {
        return FALSE;
    }

    __try {
        if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart == targetModuleBase) {
            matches = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }

    return matches;
}

/* Note: Reverse-lookup the DriverObject by module base address within an object directory. */
static NTSTATUS
kswordArkDriverUnloadReferenceByModuleBaseInDirectory(
    _In_z_ const WCHAR* directoryName,
    _In_ ULONGLONG targetModuleBase,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    HANDLE directoryHandle = NULL;
    PkswObjectDirectoryInformation entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN scanComplete = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;
    PDRIVER_OBJECT matchedObject = NULL;
    WCHAR matchedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };

    if (directoryName == NULL ||
        targetModuleBase == 0ULL ||
        driverObjectOut == NULL ||
        normalizedNameOut == NULL ||
        nameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    status = kswordArkDriverUnloadOpenDirectory(directoryName, &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    entry = (PkswObjectDirectoryInformation)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (scannedEntries < KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES) {
        WCHAR candidateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        WCHAR candidateNormalizedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        PDRIVER_OBJECT candidateObject = NULL;
        NTSTATUS candidateStatus = STATUS_SUCCESS;

        RtlZeroMemory(entry, KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* Note: Only after a complete scan can it be proven that the module base address is unique within this directory. */
            scanComplete = TRUE;
            break;
        }
        if (!NT_SUCCESS(status)) {
            /* Note: If directory scanning is interrupted, the first found object cannot be treated as the unique identity. */
            finalStatus = status;
            break;
        }

        ++scannedEntries;
        if (entry->name.Buffer == NULL || entry->name.Length == 0) {
            continue;
        }

        candidateStatus = kswordArkDriverUnloadBuildDirectoryCandidateName(
            directoryName,
            &entry->name,
            candidateName,
            RTL_NUMBER_OF(candidateName));
        if (!NT_SUCCESS(candidateStatus)) {
            finalStatus = candidateStatus;
            continue;
        }

        candidateStatus = kswordArkDriverUnloadReferenceCandidateName(
            candidateName,
            &candidateObject,
            candidateNormalizedName,
            RTL_NUMBER_OF(candidateNormalizedName));
        if (!NT_SUCCESS(candidateStatus)) {
            if (candidateStatus != STATUS_OBJECT_TYPE_MISMATCH) {
                finalStatus = candidateStatus;
            }
            continue;
        }

        if (kswordArkDriverUnloadDriverObjectMatchesModuleBase(candidateObject, targetModuleBase)) {
            /* Note: The second DriverObject with the same base address causes ambiguity in the module base address identity. */
            if (matchedObject != NULL) {
                /* Note: Release the second candidate reference without handing either object to the caller. */
                ObDereferenceObject(candidateObject);
                /* Note: Release the previously retained first match reference. */
                ObDereferenceObject(matchedObject);
                /* Note: Clear local pointers to avoid double-free in the common cleanup path. */
                matchedObject = NULL;
                /* Note: Reject non-unique identities using a stable collision status. */
                finalStatus = STATUS_OBJECT_NAME_COLLISION;
                /* Note: No need to continue scanning; this directory has already proven ambiguity. */
                break;
            }

            /* Note: Temporarily store the first match and continue the full scan to prove uniqueness. */
            matchedObject = candidateObject;
            /* Note: Save only the canonical object name of the truly matched item. */
            (VOID)RtlStringCchCopyW(
                matchedName,
                RTL_NUMBER_OF(matchedName),
                candidateNormalizedName);
            /* Note: The object reference has been transferred to matchedObject; prevent falling through to standard release. */
            candidateObject = NULL;
            /* Note: Continue enumerating other objects in this directory. */
            continue;
        }

        ObDereferenceObject(candidateObject);
    }

    /* Note: Cannot prove uniqueness when reaching the fixed scan limit; close as failure. */
    if (!scanComplete &&
        finalStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
        /* Note: Retain explicit upper-limit status for caller diagnostics. */
        finalStatus = STATUS_BUFFER_OVERFLOW;
    }
    /* Note: Publish reference only if scan is complete and exactly one match is found. */
    if (scanComplete &&
        matchedObject != NULL &&
        finalStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
        /* Note: Transfer ownership of the unique reference to the caller. */
        *driverObjectOut = matchedObject;
        /* Note: Output unique matching canonical object name. */
        (VOID)RtlStringCchCopyW(
            normalizedNameOut,
            nameChars,
            matchedName);
        /* Note: Release temporary directory query buffer. */
        ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        /* Note: Close the object directory handle for this operation. */
        ZwClose(directoryHandle);
        /* Module base addresses in this directory are uniquely identified. */
        return STATUS_SUCCESS;
    }
    /* Note: Release the initial reference held when scanning fails, collides, or is incomplete. */
    if (matchedObject != NULL) {
        /* Note: The failure path must not leak object references to the caller. */
        ObDereferenceObject(matchedObject);
    }
    ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ZwClose(directoryHandle);
    return finalStatus;
}

/* Note: Scans the object directory by module base address, shared by strong unload and communication blocking features for precise DriverObject identity. */
NTSTATUS
kswordArkDriverReferenceObjectByModuleBase(
    _In_ ULONGLONG targetModuleBase,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    static const WCHAR* const kDirectoriesToScan[] = {
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters"
    };
    ULONG directoryIndex = 0UL;
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    PDRIVER_OBJECT matchedObject = NULL;
    WCHAR matchedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };

    if (targetModuleBase == 0ULL ||
        driverObjectOut == NULL ||
        normalizedNameOut == NULL ||
        nameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    /* Note: Object names in the caller's buffer from the previous call are not preserved on the failure path. */
    normalizedNameOut[0] = L'\0';
    for (directoryIndex = 0UL;
        directoryIndex < RTL_NUMBER_OF(kDirectoriesToScan);
        ++directoryIndex) {
        PDRIVER_OBJECT directoryMatch = NULL;
        WCHAR directoryMatchName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        NTSTATUS scanStatus = kswordArkDriverUnloadReferenceByModuleBaseInDirectory(
            kDirectoriesToScan[directoryIndex],
            targetModuleBase,
            &directoryMatch,
            directoryMatchName,
            RTL_NUMBER_OF(directoryMatchName));

        if (NT_SUCCESS(scanStatus)) {
            /* Note: A second object with the same base address in a different directory also constitutes an identity ambiguity. */
            if (matchedObject != NULL) {
                /* Note: Release the reference to the unique match returned by the current directory. */
                ObDereferenceObject(directoryMatch);
                /* Note: Release the previously directory-retained match reference. */
                ObDereferenceObject(matchedObject);
                /* Note: Do not return any ambiguous object to the caller. */
                return STATUS_OBJECT_NAME_COLLISION;
            }

            /* Note: Keep the first directory match and continue scanning other allowed directories. */
            matchedObject = directoryMatch;
            /* Note: Save the first matching canonical object name. */
            (VOID)RtlStringCchCopyW(
                matchedName,
                RTL_NUMBER_OF(matchedName),
                directoryMatchName);
            /* Note: Marked as a candidate found but not yet proven unique across directories. */
            status = STATUS_SUCCESS;
            /* Continue to the next allowed directory. */
            continue;
        }
        /* Note: Fail immediately when a same-base collision is detected within the directory. */
        if (scanStatus == STATUS_OBJECT_NAME_COLLISION) {
            /* Note: Release the unique match that the previous directory may have retained. */
            if (matchedObject != NULL) {
                /* Note: Collision path does not retain reference. */
                ObDereferenceObject(matchedObject);
            }
            /* Note: Return the stable collision status to all callers. */
            return scanStatus;
        }
        if (scanStatus != STATUS_OBJECT_NAME_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_PATH_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_TYPE_MISMATCH) {
            /* Note: If a match is found but other directory scans fail, uniqueness cannot be proven. */
            if (matchedObject != NULL) {
                /* Note: Release the unique candidate reference that has not yet been dispatched. */
                ObDereferenceObject(matchedObject);
                /* Note: Clear local pointers to prevent subsequent erroneous releases. */
                matchedObject = NULL;
            }
            /* Note: If any directory cannot be fully scanned, cross-directory uniqueness cannot be proven. */
            return scanStatus;
        }
    }

    /* Note: Publish unique match after three allowed directories complete full scan. */
    if (matchedObject != NULL && NT_SUCCESS(status)) {
        /* Note: Transfer the sole DriverObject reference to the caller. */
        *driverObjectOut = matchedObject;
        /* Note: Fill back the canonical directory name of the unique object. */
        (VOID)RtlStringCchCopyW(
            normalizedNameOut,
            nameChars,
            matchedName);
        /* Note: Module base address is unique across all allowed directories. */
        return STATUS_SUCCESS;
    }
    /* Note: A failure status leaves no unreleased references. */
    return status;
}

/* Note: Only attempt alternate directories when the object name or path is not found, to avoid masking permission or parameter errors. */
static BOOLEAN
kswordArkDriverUnloadShouldTryAlternateName(
    _In_ NTSTATUS status
    )
{
    return (status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_NOT_FOUND) ? TRUE : FALSE;
}

/* Note: Reference the DriverObject by object name; do not accept addresses passed from R3. */
static NTSTATUS
kswordArkDriverUnloadReferenceByName(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    )
{
    WCHAR firstCandidate[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR leafName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR alternateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || driverObjectOut == NULL || normalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    normalizedNameOut[0] = L'\0';

    if ((request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL &&
        request->targetModuleBase != 0ULL) {
        status = kswordArkDriverReferenceObjectByModuleBase(
            request->targetModuleBase,
            driverObjectOut,
            normalizedNameOut,
            nameChars);
        if (NT_SUCCESS(status) || !kswordArkDriverUnloadShouldTryAlternateName(status)) {
            return status;
        }
    }

    status = kswordArkDriverUnloadBuildObjectName(
        request->driverName,
        firstCandidate,
        RTL_NUMBER_OF(firstCandidate));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverUnloadReferenceCandidateName(
        firstCandidate,
        driverObjectOut,
        normalizedNameOut,
        nameChars);
    if (NT_SUCCESS(status) || !kswordArkDriverUnloadShouldTryAlternateName(status)) {
        return status;
    }

    /*
     * Note: SCM service name is not always equal to the \Driver\ name of the DriverObject.
     * File systems and mini-filters commonly use object directories like \FileSystem\ or
     * \FileSystem\Filters\, so fall back to the last-level name when the object is not found.
     */
    if (!NT_SUCCESS(kswordArkDriverUnloadExtractLeafName(
        firstCandidate,
        leafName,
        RTL_NUMBER_OF(leafName)))) {
        return status;
    }

    if (!kswordArkDriverUnloadNameHasPrefix(firstCandidate, L"\\FileSystem\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverUnloadReferenceCandidateName(
                alternateName,
                driverObjectOut,
                normalizedNameOut,
                nameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!kswordArkDriverUnloadNameHasPrefix(firstCandidate, L"\\FileSystem\\Filters\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\Filters\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverUnloadReferenceCandidateName(
                alternateName,
                driverObjectOut,
                normalizedNameOut,
                nameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!kswordArkDriverUnloadNameHasPrefix(firstCandidate, L"\\Driver\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\Driver\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverUnloadReferenceCandidateName(
                alternateName,
                driverObjectOut,
                normalizedNameOut,
                nameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    status = kswordArkDriverUnloadReferenceByServiceLeaf(
        leafName,
        driverObjectOut,
        normalizedNameOut,
        nameChars);
    if (NT_SUCCESS(status) || !kswordArkDriverUnloadShouldTryAlternateName(status)) {
        return status;
    }

    return status;
}

/* Note: Determine if the callback enumeration entry can be removed via public or controlled paths. */
static BOOLEAN
kswordArkDriverUnloadCallbackEntryIsRemovable(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry
    )
{
    if (entry == NULL) {
        return FALSE;
    }
    if ((entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) == 0UL) {
        return FALSE;
    }
    if (entry->callbackAddress == 0ULL) {
        return FALSE;
    }

    switch (entry->callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return TRUE;
    default:
        return FALSE;
    }
}

/* Note: Convert the callback class enumeration to the class value used for removal IOCTL. */
static ULONG
kswordArkDriverUnloadCallbackClassToRemoveType(
    _In_ ULONG callbackClass
    )
{
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    }
}

/* Note: Build a system module snapshot to strictly attribute callback addresses to the target module. */
static NTSTATUS
kswordArkDriverUnloadBuildModuleSnapshot(
    _Outptr_result_bytebuffer_(*bufferBytesOut) KswDriverUnloadSystemModuleInformation** moduleInfoOut,
    _Out_ ULONG* bufferBytesOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    KswDriverUnloadSystemModuleInformation* moduleInfo = NULL;

    if (moduleInfoOut == NULL || bufferBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *moduleInfoOut = NULL;
    *bufferBytesOut = 0UL;

    status = ZwQuerySystemInformation(
        KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    moduleInfo = (KswDriverUnloadSystemModuleInformation*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        requiredBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS,
        moduleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        return status;
    }

    *moduleInfoOut = moduleInfo;
    *bufferBytesOut = requiredBytes;
    return STATUS_SUCCESS;
}

/* Note: Determine if a given address falls within the image range corresponding to the specified module base address. */
static BOOLEAN
kswordArkDriverUnloadAddressBelongsToModuleBase(
    _In_opt_ const KswDriverUnloadSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG address,
    _In_ ULONGLONG targetModuleBase
    )
{
    ULONG moduleIndex = 0UL;

    if (moduleInfo == NULL || address == 0ULL || targetModuleBase == 0ULL) {
        return FALSE;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswDriverUnloadSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const ULONGLONG kModuleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
        const ULONGLONG kModuleEnd = kModuleBase + (ULONGLONG)moduleEntry->imageSize;

        if (kModuleBase != targetModuleBase) {
            continue;
        }
        if (address >= kModuleBase && address < kModuleEnd) {
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

/* Note: Determine if the enumeration entry belongs to the target module; non-function address entries must already have the moduleBase field. */
static BOOLEAN
kswordArkDriverUnloadCallbackEntryMatchesModuleBase(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry,
    _In_opt_ const KswDriverUnloadSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG targetModuleBase
    )
{
    if (entry == NULL || targetModuleBase == 0ULL) {
        return FALSE;
    }
    if ((entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE) != 0UL &&
        entry->moduleBase == targetModuleBase) {
        return TRUE;
    }
    if ((entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0UL) {
        return FALSE;
    }
    return kswordArkDriverUnloadAddressBelongsToModuleBase(
        moduleInfo,
        entry->callbackAddress,
        targetModuleBase);
}

/* Note: Invoke single external callback removal path and aggregate status into result count. */
static VOID
kswordArkDriverUnloadRemoveOneCallbackEntry(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry,
    _Inout_ KswDriverUnloadCallbackCleanupResult* cleanupResult
    )
{
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST removeRequest;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE removeResponse;
    NTSTATUS removeStatus = STATUS_SUCCESS;

    if (entry == NULL || cleanupResult == NULL) {
        return;
    }

    RtlZeroMemory(&removeRequest, sizeof(removeRequest));
    RtlZeroMemory(&removeResponse, sizeof(removeResponse));
    removeRequest.size = sizeof(removeRequest);
    removeRequest.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    removeRequest.callbackClass = kswordArkDriverUnloadCallbackClassToRemoveType(entry->callbackClass);
    removeRequest.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
    removeRequest.callbackAddress = entry->callbackAddress;
    removeResponse.size = sizeof(removeResponse);
    removeResponse.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    removeResponse.callbackClass = removeRequest.callbackClass;
    removeResponse.callbackAddress = removeRequest.callbackAddress;

    switch (removeRequest.callbackClass) {
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS:
        removeStatus = PsSetCreateProcessNotifyRoutineEx(
            (KswDriverUnloadProcessNotifyEx)(ULONG_PTR)removeRequest.callbackAddress,
            TRUE);
        if (removeStatus == STATUS_PROCEDURE_NOT_FOUND || removeStatus == STATUS_INVALID_PARAMETER) {
            removeStatus = PsSetCreateProcessNotifyRoutine(
                (PCREATE_PROCESS_NOTIFY_ROUTINE)(ULONG_PTR)removeRequest.callbackAddress,
                TRUE);
        }
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD:
        removeStatus = PsRemoveCreateThreadNotifyRoutine(
            (KswDriverUnloadThreadNotify)(ULONG_PTR)removeRequest.callbackAddress);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE:
        removeStatus = PsRemoveLoadImageNotifyRoutine(
            (KswDriverUnloadImageNotify)(ULONG_PTR)removeRequest.callbackAddress);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER:
        removeStatus = kswordArkCallbackExternalRemoveByRequest(
            &removeRequest,
            &removeResponse);
        break;

    default:
        removeStatus = STATUS_INVALID_PARAMETER;
        break;
    }

    if (NT_SUCCESS(removeStatus)) {
        cleanupResult->removed += 1UL;
    }
    else {
        cleanupResult->failures += 1UL;
        cleanupResult->lastStatus = removeStatus;
    }
}

/* Note: Read-only count residual callbacks by module base address as evidence for whether forced removal is allowed. */
static NTSTATUS
kswordArkDriverUnloadInspectCallbacksByModuleBase(
    _In_ ULONGLONG targetModuleBase,
    _Out_ KswDriverUnloadCallbackEvidenceResult* evidenceResult
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KswDriverUnloadSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG responseBytes = 0UL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* enumResponse = NULL;
    ULONG entryIndex = 0UL;
    ULONG parsedEntries = 0UL;

    /*
     * Input: Target driver module base address and evidence output structure.
     * Handling: Reuse existing callback enumeration paths to build a read-only snapshot, determine module ownership by moduleBase
     *      or callback address range, and distinguish entries removable by controlled APIs from those that cannot be safely removed.
     * Return: STATUS_SUCCESS on successful base enumeration; specific status on memory/module snapshot failure.
     */
    if (evidenceResult == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(evidenceResult, sizeof(*evidenceResult));
    evidenceResult->lastStatus = STATUS_SUCCESS;
    if (targetModuleBase == 0ULL) {
        evidenceResult->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverUnloadBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        evidenceResult->lastStatus = status;
        return status;
    }

    responseBytes = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) +
        ((KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT - 1UL) * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
#pragma warning(push)
#pragma warning(disable:4996)
    enumResponse = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        responseBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (enumResponse == NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        evidenceResult->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(enumResponse, responseBytes);
    enumResponse->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
    enumResponse->version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
    enumResponse->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
    enumResponse->lastStatus = STATUS_SUCCESS;

    {
        KswordArkCallbackEnumBuilder builder;

        RtlZeroMemory(&builder, sizeof(builder));
        builder.entries = enumResponse->entries;
        builder.entryCapacity = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
        builder.lastStatus = STATUS_SUCCESS;
        kswordArkCallbackEnumSnapshotBegin(&builder);
        kswordArkCallbackEnumAddMinifilters(&builder);
        kswordArkCallbackEnumAddPrivateCallbacks(&builder);
        kswordArkCallbackExternalAddCallbacks(&builder);
        kswordArkCallbackEnumSnapshotFinalize(&builder);
        enumResponse->totalCount = builder.totalCount;
        enumResponse->returnedCount = builder.returnedCount;
        enumResponse->flags = builder.flags;
        enumResponse->lastStatus = builder.lastStatus;
        enumResponse->enumerationGeneration = builder.snapshotHash;
        enumResponse->snapshotHash = builder.snapshotHash;
    }

    parsedEntries = enumResponse->returnedCount;
    if (parsedEntries > KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT) {
        parsedEntries = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
    }
    evidenceResult->enumerated = parsedEntries;
    evidenceResult->truncated =
        (enumResponse->totalCount > enumResponse->returnedCount) ? TRUE : FALSE;
    evidenceResult->lastStatus = enumResponse->lastStatus;

    for (entryIndex = 0UL; entryIndex < parsedEntries; ++entryIndex) {
        const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = &enumResponse->entries[entryIndex];

        if (!kswordArkDriverUnloadCallbackEntryMatchesModuleBase(
            entry,
            moduleInfo,
            targetModuleBase)) {
            continue;
        }

        evidenceResult->matched += 1UL;
        if (kswordArkDriverUnloadCallbackEntryIsRemovable(entry)) {
            evidenceResult->removable += 1UL;
        }
        else {
            evidenceResult->nonRemovable += 1UL;
        }
    }

    ExFreePoolWithTag(enumResponse, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    return STATUS_SUCCESS;
}

/* Note: enumerate and remove verifiable callbacks by module base to prevent residual target modules from continuing to run via callbacks. */
static NTSTATUS
kswordArkDriverUnloadRemoveCallbacksByModuleBase(
    _In_ ULONGLONG targetModuleBase,
    _Out_ KswDriverUnloadCallbackCleanupResult* cleanupResult
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KswDriverUnloadSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG responseBytes = 0UL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* enumResponse = NULL;
    ULONG entryIndex = 0UL;
    ULONG parsedEntries = 0UL;

    if (cleanupResult == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(cleanupResult, sizeof(*cleanupResult));
    cleanupResult->lastStatus = STATUS_SUCCESS;
    if (targetModuleBase == 0ULL) {
        cleanupResult->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverUnloadBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        cleanupResult->lastStatus = status;
        return status;
    }

    responseBytes = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) +
        ((KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT - 1UL) * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
#pragma warning(push)
#pragma warning(disable:4996)
    enumResponse = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        responseBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (enumResponse == NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        cleanupResult->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(enumResponse, responseBytes);
    enumResponse->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
    enumResponse->version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
    enumResponse->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
    enumResponse->lastStatus = STATUS_SUCCESS;

    {
        KswordArkCallbackEnumBuilder builder;

        RtlZeroMemory(&builder, sizeof(builder));
        builder.entries = enumResponse->entries;
        builder.entryCapacity = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
        builder.lastStatus = STATUS_SUCCESS;
        kswordArkCallbackEnumSnapshotBegin(&builder);
        kswordArkCallbackEnumAddMinifilters(&builder);
        kswordArkCallbackEnumAddPrivateCallbacks(&builder);
        kswordArkCallbackExternalAddCallbacks(&builder);
        kswordArkCallbackEnumSnapshotFinalize(&builder);
        enumResponse->totalCount = builder.totalCount;
        enumResponse->returnedCount = builder.returnedCount;
        enumResponse->flags = builder.flags;
        enumResponse->lastStatus = builder.lastStatus;
        enumResponse->enumerationGeneration = builder.snapshotHash;
        enumResponse->snapshotHash = builder.snapshotHash;
    }

    parsedEntries = enumResponse->returnedCount;
    if (parsedEntries > KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT) {
        parsedEntries = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
    }

    for (entryIndex = 0UL; entryIndex < parsedEntries; ++entryIndex) {
        const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = &enumResponse->entries[entryIndex];

        if (!kswordArkDriverUnloadCallbackEntryIsRemovable(entry)) {
            continue;
        }
        if (!kswordArkDriverUnloadCallbackEntryMatchesModuleBase(
            entry,
            moduleInfo,
            targetModuleBase)) {
            continue;
        }
        cleanupResult->candidates += 1UL;
        kswordArkDriverUnloadRemoveOneCallbackEntry(entry, cleanupResult);
    }

    ExFreePoolWithTag(enumResponse, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    return cleanupResult->failures == 0UL ? STATUS_SUCCESS : cleanupResult->lastStatus;
}

/* Note: Neutralize rejected IRP stubs for the target DriverObject after a forced unload. */
static NTSTATUS
kswordArkDriverUnloadRejectedDispatch(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp
    )
{
    // Input: Device object and IRP dispatched by the system to a DriverObject that has been forcibly neutralized.
    // Note: Do not access the target driver's private extension; complete the IRP with STATUS_DELETE_PENDING only.
    // Return: STATUS_DELETE_PENDING, indicating to the caller that the device is being deleted/unavailable.
    UNREFERENCED_PARAMETER(deviceObject);

    if (irp != NULL) {
        irp->IoStatus.Status = STATUS_DELETE_PENDING;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    return STATUS_DELETE_PENDING;
}

/* Note: Optionally clear the dispatch table, aligning with SKT64's force unload semantics but controlled by a flag. */
static VOID
kswordArkDriverUnloadClearDispatchUnsafe(
    _Inout_ PDRIVER_OBJECT driverObject
    )
{
    if (driverObject == NULL) {
        return;
    }

    __try {
        ULONG majorIndex = 0UL;
        driverObject->FastIoDispatch = NULL;
        for (majorIndex = 0UL; majorIndex <= IRP_MJ_MAXIMUM_FUNCTION; ++majorIndex) {
            driverObject->MajorFunction[majorIndex] = kswordArkDriverUnloadRejectedDispatch;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        (VOID)0;
    }
}

/* Note: Read-only snapshot of DriverObject entry point and device object flags, and reference the device object to keep it alive. */
static NTSTATUS
kswordArkDriverUnloadSnapshotEntryTransaction(
    _In_ PDRIVER_OBJECT driverObject,
    _Out_ KswDriverUnloadEntryTransaction* transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG actualDeviceCount = 0UL;
    ULONG majorIndex = 0UL;
    ULONG deviceIndex = 0UL;

    /*
     * Input: referenced target DriverObject and null transaction structure.
     * Handling: First, obtain a referenced device snapshot via the public IoEnumerateDeviceObjectList, then read FastIo,
     *      all MajorFunction handlers, and the device's original Flags. This function does not modify the target object.
     * Returns: STATUS_SUCCESS on successful full snapshot; returns an error on capacity, object ownership, or access failure.
     */
    if (driverObject == NULL || transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(transaction, sizeof(*transaction));

    status = IoEnumerateDeviceObjectList(
        driverObject,
        transaction->deviceObjects,
        sizeof(transaction->deviceObjects),
        &actualDeviceCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualDeviceCount > KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
        for (deviceIndex = 0UL;
             deviceIndex < KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT;
             ++deviceIndex) {
            if (transaction->deviceObjects[deviceIndex] != NULL) {
                ObDereferenceObject(transaction->deviceObjects[deviceIndex]);
                transaction->deviceObjects[deviceIndex] = NULL;
            }
        }
        return STATUS_BUFFER_OVERFLOW;
    }
    transaction->deviceCount = actualDeviceCount;

    __try {
        transaction->originalFastIoDispatch = driverObject->FastIoDispatch;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            transaction->originalMajorFunction[majorIndex] =
                driverObject->MajorFunction[majorIndex];
        }
        for (deviceIndex = 0UL;
             deviceIndex < transaction->deviceCount;
             ++deviceIndex) {
            if (transaction->deviceObjects[deviceIndex] == NULL ||
                transaction->deviceObjects[deviceIndex]->DriverObject != driverObject) {
                status = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }
            transaction->originalDeviceFlags[deviceIndex] =
                transaction->deviceObjects[deviceIndex]->Flags;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        for (deviceIndex = 0UL;
             deviceIndex < transaction->deviceCount;
             ++deviceIndex) {
            if (transaction->deviceObjects[deviceIndex] != NULL) {
                ObDereferenceObject(transaction->deviceObjects[deviceIndex]);
                transaction->deviceObjects[deviceIndex] = NULL;
            }
        }
        transaction->deviceCount = 0UL;
    }
    return status;
}

/* Note: Atomically merge dispatch and block new device opens when a complete transaction snapshot exists. */
static NTSTATUS
kswordArkDriverUnloadApplyEntryTransaction(
    _Inout_ PDRIVER_OBJECT driverObject,
    _Inout_ KswDriverUnloadEntryTransaction* transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /*
     * Input: Target DriverObject and a successfully established entry-point transaction snapshot.
     * Handling: Mark the transaction as applied, then disable dispatch, clear FastIo, and set
     *      DO_DEVICE_INITIALIZING for the snapshot device; exceptions are rolled back uniformly by the caller.
     * Returns: STATUS_SUCCESS when all writes succeed; returns an exception NTSTATUS on failure.
     */
    if (driverObject == NULL || transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    transaction->applied = TRUE;
    __try {
        ULONG majorIndex = 0UL;
        ULONG deviceIndex = 0UL;

        driverObject->FastIoDispatch = NULL;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            driverObject->MajorFunction[majorIndex] =
                kswordArkDriverUnloadRejectedDispatch;
        }
        for (deviceIndex = 0UL;
             deviceIndex < transaction->deviceCount;
             ++deviceIndex) {
            (VOID)InterlockedOr(
                (volatile LONG*)&transaction->deviceObjects[deviceIndex]->Flags,
                (LONG)DO_DEVICE_INITIALIZING);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

/* Note: Restores FastIo, MajorFunction, and device initialization flags saved by the entry point transaction. */
static NTSTATUS
kswordArkDriverUnloadRollbackEntryTransaction(
    _Inout_ PDRIVER_OBJECT driverObject,
    _Inout_ KswDriverUnloadEntryTransaction* transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /*
     * Input: the target DriverObject still being referenced and the transaction snapshot previously applied.
     * Handling: Only when Applied=TRUE, restore all reversible entry fields and original initialization flags.
     *      Flags of other concurrently updated devices remain unchanged to avoid overwriting the target driver's new state during rollback.
     * Return: STATUS_SUCCESS on successful restoration; specific NTSTATUS on write-back exception.
     */
    if (driverObject == NULL || transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!transaction->applied) {
        return STATUS_SUCCESS;
    }

    __try {
        ULONG majorIndex = 0UL;
        ULONG deviceIndex = 0UL;

        driverObject->FastIoDispatch = transaction->originalFastIoDispatch;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            driverObject->MajorFunction[majorIndex] =
                transaction->originalMajorFunction[majorIndex];
        }
        for (deviceIndex = 0UL;
             deviceIndex < transaction->deviceCount;
             ++deviceIndex) {
            volatile LONG* flagsAddress =
                (volatile LONG*)&transaction->deviceObjects[deviceIndex]->Flags;

            if ((transaction->originalDeviceFlags[deviceIndex] & DO_DEVICE_INITIALIZING) != 0UL) {
                (VOID)InterlockedOr(flagsAddress, (LONG)DO_DEVICE_INITIALIZING);
            }
            else {
                (VOID)InterlockedAnd(flagsAddress, (LONG)(~DO_DEVICE_INITIALIZING));
            }
        }
        transaction->applied = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

/* Note: Release the device object reference held by the entry transaction without modifying already committed target fields. */
static VOID
kswordArkDriverUnloadReleaseEntryTransaction(
    _Inout_ KswDriverUnloadEntryTransaction* transaction
    )
{
    ULONG deviceIndex = 0UL;

    /*
     * Input: Transaction with a successfully snapped device object.
     * Processing: Release object references added by IoEnumerateDeviceObjectList one by one and clear the count.
     * Return: None. Can be used for symmetric cleanup after a successful commit or rollback completion.
     */
    if (transaction == NULL) {
        return;
    }
    for (deviceIndex = 0UL;
         deviceIndex < transaction->deviceCount;
         ++deviceIndex) {
        if (transaction->deviceObjects[deviceIndex] != NULL) {
            ObDereferenceObject(transaction->deviceObjects[deviceIndex]);
            transaction->deviceObjects[deviceIndex] = NULL;
        }
    }
    transaction->deviceCount = 0UL;
}

/* Note: Optionally clear the DriverUnload pointer to prevent right-click from re-triggering the same unload entry. */
static VOID
kswordArkDriverUnloadClearUnloadPointerUnsafe(
    _Inout_ PDRIVER_OBJECT driverObject
    )
{
    if (driverObject == NULL) {
        return;
    }

    __try {
        driverObject->DriverUnload = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        (VOID)0;
    }
}

/* Note: Before removing devices or neutralizing the DriverObject, attempt to block new external opens. */
static NTSTATUS
kswordArkDriverUnloadBlockNewDeviceCreatesUnsafe(
    _Inout_ PDRIVER_OBJECT driverObject,
    _Out_opt_ ULONG* blockedDeviceCountOut
    )
{
    PDEVICE_OBJECT deviceCursor = NULL;
    PDEVICE_OBJECT deviceList[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG deviceCount = 0UL;
    ULONG deviceIndex = 0UL;
    NTSTATUS validationStatus = STATUS_SUCCESS;

    /*
     * Input: Target DriverObject still referenced by this thread, and optional blocked count output.
     * Handling: First, snapshot and validate the DeviceObject->NextDevice chain to confirm no cycles exist and
     *      every node still belongs to the same DriverObject. Then, set the public DO_DEVICE_INITIALIZING flag as a
     *      best-effort access block when IoLockRemoveDevice is unavailable, without touching the private DeviceLock.
     * Returns: STATUS_SUCCESS if both the linked list checksum and tag are valid; otherwise returns the specific failure code.
     */
    if (blockedDeviceCountOut != NULL) {
        *blockedDeviceCountOut = 0UL;
    }
    if (driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(deviceList, sizeof(deviceList));

    __try {
        deviceCursor = driverObject->DeviceObject;
        while (deviceCursor != NULL) {
            ULONG previousIndex = 0UL;

            if (deviceCount >= KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                validationStatus = STATUS_BUFFER_OVERFLOW;
                break;
            }
            for (previousIndex = 0UL; previousIndex < deviceCount; ++previousIndex) {
                if (deviceList[previousIndex] == deviceCursor) {
                    validationStatus = STATUS_INVALID_DEVICE_REQUEST;
                    break;
                }
            }
            if (!NT_SUCCESS(validationStatus)) {
                break;
            }
            if (deviceCursor->DriverObject != driverObject) {
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }

            deviceList[deviceCount] = deviceCursor;
            deviceCount += 1UL;
            deviceCursor = deviceCursor->NextDevice;
        }

        if (!NT_SUCCESS(validationStatus)) {
            return validationStatus;
        }

        for (deviceIndex = 0UL; deviceIndex < deviceCount; ++deviceIndex) {
            (VOID)InterlockedOr(
                (volatile LONG*)&deviceList[deviceIndex]->Flags,
                (LONG)DO_DEVICE_INITIALIZING);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (blockedDeviceCountOut != NULL) {
        *blockedDeviceCountOut = deviceCount;
    }
    return STATUS_SUCCESS;
}

/* Note: When the target lacks a DriverUnload routine, delete device objects following the original DeviceObject->NextDevice chain. */
static NTSTATUS
kswordArkDriverUnloadDeleteDeviceObjectsUnsafe(
    _Inout_ PDRIVER_OBJECT driverObject,
    _In_ BOOLEAN detachDeviceStacks,
    _Out_ ULONG* deletedDeviceCountOut,
    _Out_ ULONG* detachedDeviceCountOut
    )
{
    PDEVICE_OBJECT deviceCursor = NULL;
    PDEVICE_OBJECT deviceList[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG deviceCount = 0UL;
    ULONG deletedDeviceCount = 0UL;
    ULONG detachedDeviceCount = 0UL;
    NTSTATUS validationStatus = STATUS_SUCCESS;

    if (deletedDeviceCountOut == NULL || detachedDeviceCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *deletedDeviceCountOut = 0UL;
    *detachedDeviceCountOut = 0UL;

    if (driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(deviceList, sizeof(deviceList));

    /*
     * Note: Deleting a DeviceObject is not roll-backable; therefore, take a full snapshot and validate the linked list first.
     * If the list is too long, contains a cycle, or includes a different DriverObject, fail immediately without partially deleting it.
     */
    __try {
        deviceCursor = driverObject->DeviceObject;
        while (deviceCursor != NULL) {
            ULONG previousIndex = 0UL;
            PDEVICE_OBJECT nextDevice = NULL;

            if (deviceCount >= KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                validationStatus = STATUS_BUFFER_OVERFLOW;
                break;
            }
            for (previousIndex = 0UL; previousIndex < deviceCount; ++previousIndex) {
                if (deviceList[previousIndex] == deviceCursor) {
                    validationStatus = STATUS_INVALID_DEVICE_REQUEST;
                    break;
                }
            }
            if (!NT_SUCCESS(validationStatus)) {
                break;
            }
            if (deviceCursor->DriverObject != driverObject) {
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }
            if (!detachDeviceStacks &&
                (deviceCursor->AttachedDevice != NULL ||
                    deviceCursor->ReferenceCount != 0)) {
                validationStatus = STATUS_DEVICE_BUSY;
                break;
            }

            nextDevice = deviceCursor->NextDevice;
            deviceList[deviceCount] = deviceCursor;
            deviceCount += 1UL;
            deviceCursor = nextDevice;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (!NT_SUCCESS(validationStatus)) {
        return validationStatus;
    }

    __try {
        ULONG deleteIndex = 0UL;
        for (deleteIndex = 0UL; deleteIndex < deviceCount; ++deleteIndex) {
            if (detachDeviceStacks) {
                PDEVICE_OBJECT lowerDevice = NULL;
                ULONG detachGuard = 0UL;

                /*
                 * First detach layers upward from the current target device, then detach the target device from its lower layers.
                 * IoDetachDevice accepts only the lower DeviceObject; release the
                 * reference returned by IoGetLowerDeviceObject after detaching.
                 */
                while (deviceList[deleteIndex]->AttachedDevice != NULL &&
                    detachGuard < KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                    IoDetachDevice(deviceList[deleteIndex]);
                    detachedDeviceCount += 1UL;
                    detachGuard += 1UL;
                }
                if (deviceList[deleteIndex]->AttachedDevice != NULL) {
                    *deletedDeviceCountOut = deletedDeviceCount;
                    *detachedDeviceCountOut = detachedDeviceCount;
                    return STATUS_BUFFER_OVERFLOW;
                }

                lowerDevice = IoGetLowerDeviceObject(deviceList[deleteIndex]);
                if (lowerDevice != NULL) {
                    IoDetachDevice(lowerDevice);
                    detachedDeviceCount += 1UL;
                    ObDereferenceObject(lowerDevice);
                }
            }
            IoDeleteDevice(deviceList[deleteIndex]);
            deletedDeviceCount += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *deletedDeviceCountOut = deletedDeviceCount;
        *detachedDeviceCountOut = detachedDeviceCount;
        return GetExceptionCode();
    }

    *deletedDeviceCountOut = deletedDeviceCount;
    *detachedDeviceCountOut = detachedDeviceCount;
    return driverObject->DeviceObject == NULL ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

/* Verify one DeviceObject chain entry is not busy before destructive fallback. */
static NTSTATUS
kswordArkDriverUnloadCheckDeviceObjectIdleUnsafe(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PDEVICE_OBJECT deviceObject,
    _Out_ PDEVICE_OBJECT* nextDeviceOut
    )
{
    // Inputs: target DriverObject, one DeviceObject from its NextDevice chain, and an output slot.
    // Processing: read owner, next, attached, and ReferenceCount while guarded by SEH.
    // Return: STATUS_SUCCESS when the device can participate in direct unload; otherwise a blocking NTSTATUS.
    if (driverObject == NULL || deviceObject == NULL || nextDeviceOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *nextDeviceOut = NULL;
    __try {
        if (deviceObject->DriverObject != driverObject) {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        if (deviceObject->AttachedDevice != NULL) {
            return STATUS_DEVICE_BUSY;
        }
        if (deviceObject->ReferenceCount != 0) {
            return STATUS_DEVICE_BUSY;
        }
        *nextDeviceOut = deviceObject->NextDevice;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/* Note: Verify that the DeviceObject chain has been cleared after DriverUnload returns. */
static NTSTATUS
kswordArkDriverUnloadRequireNoDeviceObjectsUnsafe(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    // Input: Target DriverObject still referenced by this thread.
    // Handling: Read-only check of the DeviceObject chain head; no traversal, deletion, or correction.
    // Return: STATUS_SUCCESS if no devices remain; STATUS_DEVICE_BUSY if devices still exist; otherwise propagate the exception code.
    if (driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        return driverObject->DeviceObject == NULL
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

/* Note: Safely read a pointer field by adding DynData offset to the DriverObject base address. */
static BOOLEAN
kswordArkDriverUnloadReadPointerFieldByOffset(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG fieldOffset,
    _Out_ PVOID* valueOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // Input: referenced DriverObject, PDB/DynData field offsets, and output pointer.
    // Processing: Reject missing offsets; use MmCopyMemory wrapper to read the target field.
    // Returns TRUE on successful and complete read; FALSE if any parameter, offset, or memory read fails.
    if (driverObject == NULL ||
        valueOut == NULL ||
        !kswordArkDriverIntegrityOffsetPresent(fieldOffset)) {
        return FALSE;
    }

    *valueOut = NULL;
    fieldAddress = (const UCHAR*)driverObject + (SIZE_T)fieldOffset;
    return kswordArkHookReadMemorySafe(fieldAddress, valueOut, sizeof(*valueOut));
}

/* Note: Safely read a ULONG field by adding the DynData offset to the DriverObject base address. */
static BOOLEAN
kswordArkDriverUnloadReadUlongFieldByOffset(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG fieldOffset,
    _Out_ ULONG* valueOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // Input: Referenced DriverObject, PDB/DynData field offsets, and output ULONG.
    // Processing: Reject missing offsets; use MmCopyMemory wrapper to read the target field.
    // Returns TRUE on successful and complete read; FALSE if any parameter, offset, or memory read fails.
    if (driverObject == NULL ||
        valueOut == NULL ||
        !kswordArkDriverIntegrityOffsetPresent(fieldOffset)) {
        return FALSE;
    }

    *valueOut = 0UL;
    fieldAddress = (const UCHAR*)driverObject + (SIZE_T)fieldOffset;
    return kswordArkHookReadMemorySafe(fieldAddress, valueOut, sizeof(*valueOut));
}

/* Note: Validate PDB/DynData _DRIVER_OBJECT offsets against the current WDK view. */
static BOOLEAN
kswordArkDriverUnloadValidateDriverObjectOffsets(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ const KswDynState* dynState
    )
{
    PVOID driverStart = NULL;
    ULONG driverSize = 0UL;
    PVOID driverSection = NULL;
    PVOID driverUnload = NULL;
    PVOID majorFunction = NULL;
    PVOID expectedMajorFunction = NULL;

    // Input: Target DriverObject and DynData snapshot that has passed identity matching.
    // Handling: Read-only access to critical _DRIVER_OBJECT fields provided by the PDB profile, and cross-compare with results from current WDK structure access.
    // Return: TRUE if all keyword fields match; FALSE if any field is missing, fails to read, or is inconsistent.
    if (driverObject == NULL || dynState == NULL) {
        return FALSE;
    }

    if (!kswordArkDriverUnloadReadPointerFieldByOffset(
            driverObject,
            dynState->kernel.doDriverStart,
            &driverStart) ||
        !kswordArkDriverUnloadReadUlongFieldByOffset(
            driverObject,
            dynState->kernel.doDriverSize,
            &driverSize) ||
        !kswordArkDriverUnloadReadPointerFieldByOffset(
            driverObject,
            dynState->kernel.doDriverSection,
            &driverSection) ||
        !kswordArkDriverUnloadReadPointerFieldByOffset(
            driverObject,
            dynState->kernel.doDriverUnload,
            &driverUnload) ||
        !kswordArkDriverUnloadReadPointerFieldByOffset(
            driverObject,
            dynState->kernel.doMajorFunction,
            &majorFunction)) {
        return FALSE;
    }

    expectedMajorFunction = (PVOID)(ULONG_PTR)driverObject->MajorFunction[0];
    if (driverStart != driverObject->DriverStart ||
        driverSize != driverObject->DriverSize ||
        driverSection != driverObject->DriverSection ||
        driverUnload != (PVOID)(ULONG_PTR)driverObject->DriverUnload ||
        majorFunction != expectedMajorFunction) {
        return FALSE;
    }

    return TRUE;
}

/* Note: Ensure the DynData field for strong path dependencies during unloading originates from PDB or is backed by real-time structure validation. */
static BOOLEAN
kswordArkDriverUnloadDynDataSourceTrusted(
    _In_ ULONG source
    )
{
    // Input: A DynData field source.
    // Note: only accepts exact PDB profiles or runtime patterns verified by unique hits and structural review.
    // Return: TRUE if the source is usable for strong unload pre-check; otherwise FALSE.
    return (source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
            source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)
        ? TRUE
        : FALSE;
}

/* Note: Retain the old function name for diagnostic ABI compatibility; its semantics are now 'strongly validate DynData availability'. */
static BOOLEAN
kswordArkDriverUnloadHasPdbBackedDynData(
    _In_ const KswDynState* dynState
    )
{
    // Input: Current DynData snapshot.
    // Handles: checks sources of _DRIVER_OBJECT, _KLDR_DATA_TABLE_ENTRY, and PsLoadedModuleList fields for strong unload dependencies.
    // Return: TRUE if all keyword fields are from PDB or verified via structural runtime patterns; otherwise FALSE.
    if (dynState == NULL) {
        return FALSE;
    }

    return kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.doDriverStart) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.doDriverSize) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.doDriverSection) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.doMajorFunction) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.doDriverUnload) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.kldrInLoadOrderLinks) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.kldrDllBase) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelSources.kldrSizeOfImage) &&
        kswordArkDriverUnloadDynDataSourceTrusted(dynState->kernelGlobalSources.psLoadedModuleList);
}

/* Note: Confirm that the ETHREAD offset relied upon by the thread entry evidence scan originates from a trusted resolution source. */
static BOOLEAN
kswordArkDriverUnloadHasPdbBackedThreadDynData(
    _In_ const KswDynState* dynState
    )
{
    /*
     * Input: Current DynData snapshot.
     * Processing: Enforce that ETHREAD.StartAddress originates from PDB or falls back to structural validation.
     *      Win32StartAddress is optional; if present, it must originate from a trust level equivalent to the current context.
     * Return: TRUE if the thread can be safely scanned; FALSE if the source is missing or weak.
     */
    if (dynState == NULL) {
        return FALSE;
    }
    if (!kswordArkDriverIntegrityOffsetPresent(dynState->kernel.etStartAddress) ||
        !kswordArkDriverUnloadDynDataSourceTrusted(
            dynState->kernelSources.etStartAddress)) {
        return FALSE;
    }
    if (kswordArkDriverIntegrityOffsetPresent(dynState->kernel.etWin32StartAddress) &&
        !kswordArkDriverUnloadDynDataSourceTrusted(
            dynState->kernelSources.etWin32StartAddress)) {
        return FALSE;
    }
    return TRUE;
}

/* Note: Dynamically resolve PsGetNextProcess; return NULL on failure instead of hard-dependency import. */
static KswDriverUnloadPsGetNextProcessFn
kswordArkDriverUnloadResolvePsGetNextProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    // Inputs: None.
    // Processing: Query public exports via MmGetSystemRoutineAddress to ensure compatibility across different WDK/system export sets.
    // Returns: Callable function pointer; returns NULL if the system does not support it.
    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswDriverUnloadPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

/* Note: Dynamically resolve psGetNextProcessThread; return NULL on failure instead of hard-linking the import. */
static KswDriverUnloadPsGetNextProcessThreadFn
kswordArkDriverUnloadResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    // Inputs: None.
    // Processing: Query public exports via MmGetSystemRoutineAddress; used only for read-only thread enumeration.
    // Returns: Callable function pointer; returns NULL if the system does not support it.
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswDriverUnloadPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

/* Note: Read a 64-bit address field from ETHREAD at the DynData offset. */
static BOOLEAN
kswordArkDriverUnloadReadThreadAddressField(
    _In_ PETHREAD threadObject,
    _In_ ULONG fieldOffset,
    _Out_ ULONGLONG* addressOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // Input: Referenced ETHREAD, PDB-backed field offset, and output address slot.
    // Processing: Access ETHREAD fields via safe memory read wrappers; do not trust pointer readability directly.
    // Return: TRUE on successful full address read; FALSE if parameters are invalid, the offset is missing, or the read fails.
    if (threadObject == NULL ||
        addressOut == NULL ||
        !kswordArkDriverIntegrityOffsetPresent(fieldOffset)) {
        return FALSE;
    }

    *addressOut = 0ULL;
    fieldAddress = (const UCHAR*)threadObject + (SIZE_T)fieldOffset;
    return kswordArkHookReadMemorySafe(fieldAddress, addressOut, sizeof(*addressOut));
}

/* Note: Check if the thread entry address falls within the target driver image range. */
static BOOLEAN
kswordArkDriverUnloadAddressInImageRange(
    _In_ ULONGLONG address,
    _In_ ULONGLONG imageStart,
    _In_ ULONGLONG imageEnd
    )
{
    // Input: Address to check and the [ImageStart, ImageEnd) half-open interval.
    // Processing: Perform only integer range checks; the caller guarantees the range comes from loader/DriverObject cross-evidence.
    // Returns: TRUE if the address falls within the target module image, otherwise FALSE.
    if (address == 0ULL || imageStart == 0ULL || imageEnd <= imageStart) {
        return FALSE;
    }
    return (address >= imageStart && address < imageEnd) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDriverUnloadThreadIsTerminated(
    _In_ PETHREAD threadObject
    )
{
    LARGE_INTEGER zeroTimeout;
    NTSTATUS waitStatus = STATUS_SUCCESS;

    if (threadObject == NULL) {
        return TRUE;
    }
    zeroTimeout.QuadPart = 0LL;
    waitStatus = KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        &zeroTimeout);
    return waitStatus == STATUS_SUCCESS ? TRUE : FALSE;
}

/* Note: Read-only scan still targets threads running from the target module entry point as strong evidence for blocking driver unloading. */
static NTSTATUS
kswordArkDriverUnloadScanModuleResidentThreads(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG imageStart,
    _In_ ULONGLONG imageEnd,
    _Out_ ULONG* scannedProcessCountOut,
    _Out_ ULONG* scannedThreadCountOut,
    _Out_ ULONG* residentThreadCountOut
    )
{
    KswDriverUnloadPsGetNextProcessFn psGetNextProcess = NULL;
    KswDriverUnloadPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;
    ULONG residentThreads = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN stopScan = FALSE;

    /*
     * Input: target image range and PDB-backed ETHREAD entry offset.
     * Handling: Traverse referenced threads via public PsGetNextProcess/psGetNextProcessThread,
     *      read StartAddress/Win32StartAddress, and count threads falling within the target module.
     * Returns: STATUS_SUCCESS upon completion of scanning; returns the corresponding status if export/offset is unavailable or the limit is reached.
     *      This function only generates evidence; it does not terminate threads, modify ETHREAD, or touch the CID table.
     */
    if (scannedProcessCountOut == NULL ||
        scannedThreadCountOut == NULL ||
        residentThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *scannedProcessCountOut = 0UL;
    *scannedThreadCountOut = 0UL;
    *residentThreadCountOut = 0UL;

    if (dynState == NULL || imageStart == 0ULL || imageEnd <= imageStart) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkDriverUnloadHasPdbBackedThreadDynData(dynState)) {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    psGetNextProcess = kswordArkDriverUnloadResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkDriverUnloadResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = NULL;
        PETHREAD threadCursor = NULL;

        scannedProcesses += 1UL;
        threadCursor = psGetNextProcessThread(processCursor, NULL);
        while (threadCursor != NULL) {
            PETHREAD nextThread = NULL;
            ULONGLONG startAddress = 0ULL;
            ULONGLONG win32StartAddress = 0ULL;
            BOOLEAN matchesTarget = FALSE;

            scannedThreads += 1UL;
            if (kswordArkDriverUnloadReadThreadAddressField(
                    threadCursor,
                    dynState->kernel.etStartAddress,
                    &startAddress) &&
                kswordArkDriverUnloadAddressInImageRange(startAddress, imageStart, imageEnd)) {
                matchesTarget = TRUE;
            }
            if (!matchesTarget &&
                kswordArkDriverIntegrityOffsetPresent(dynState->kernel.etWin32StartAddress) &&
                kswordArkDriverUnloadReadThreadAddressField(
                    threadCursor,
                    dynState->kernel.etWin32StartAddress,
                    &win32StartAddress) &&
                kswordArkDriverUnloadAddressInImageRange(win32StartAddress, imageStart, imageEnd)) {
                matchesTarget = TRUE;
            }
            if (matchesTarget &&
                (PsGetThreadProcess(threadCursor) != PsInitialSystemProcess ||
                    kswordArkDriverUnloadThreadIsTerminated(threadCursor))) {
                /*
                 * Note: Forceful removal only identifies threads within the System process that have not exited and whose entry point
                 * belongs to the target image as 'threads created by the driver'. User threads and terminated ETHREADs are excluded.
                 */
                matchesTarget = FALSE;
            }
            if (matchesTarget) {
                residentThreads += 1UL;
            }

            if (scannedThreads >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS) {
                status = STATUS_BUFFER_OVERFLOW;
                ObDereferenceObject(threadCursor);
                stopScan = TRUE;
                break;
            }

            nextThread = psGetNextProcessThread(processCursor, threadCursor);
            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;
        }

        if (scannedProcesses >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES) {
            status = STATUS_BUFFER_OVERFLOW;
            stopScan = TRUE;
        }

        if (!stopScan) {
            nextProcess = psGetNextProcess(processCursor);
        }
        ObDereferenceObject(processCursor);
        if (stopScan) {
            break;
        }
        processCursor = nextProcess;
    }

    *scannedProcessCountOut = scannedProcesses;
    *scannedThreadCountOut = scannedThreads;
    *residentThreadCountOut = residentThreads;
    return status;
}

static NTSTATUS
kswordArkDriverUnloadTerminateModuleThreadsUnsafe(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG imageStart,
    _In_ ULONGLONG imageEnd,
    _Out_ PkswDriverUnloadThreadCleanupResult result
    )
{
    KswDriverUnloadPsGetNextProcessFn psGetNextProcess = NULL;
    KswDriverUnloadPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;
    NTSTATUS aggregateStatus = STATUS_SUCCESS;

    /*
     * Input: Target image range confirmed by loader/PDB evidence.
     * Handling: Only process threads in the System process where the entry point is still within the target image and has not exited.
     *      Forcefully terminate each thread and wait for the ETHREAD to reach a signaled state. If any
     *      thread fails to confirm exit, return failure; the caller must not proceed into DriverUnload.
     * Returns: STATUS_SUCCESS when all candidates confirm exit, and fills back candidate/success/failure counts.
     */
    if (result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(result, sizeof(*result));
    result->lastStatus = STATUS_SUCCESS;

    if (dynState == NULL || imageStart == 0ULL || imageEnd <= imageStart) {
        result->lastStatus = STATUS_INVALID_PARAMETER;
        return result->lastStatus;
    }
    if (!kswordArkDriverUnloadHasPdbBackedThreadDynData(dynState)) {
        result->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        return result->lastStatus;
    }

    psGetNextProcess = kswordArkDriverUnloadResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkDriverUnloadResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        result->lastStatus = STATUS_NOT_SUPPORTED;
        return result->lastStatus;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = NULL;
        PETHREAD threadCursor = NULL;
        BOOLEAN stopScan = FALSE;

        scannedProcesses += 1UL;
        threadCursor = psGetNextProcessThread(processCursor, NULL);
        while (threadCursor != NULL) {
            PETHREAD nextThread = NULL;
            ULONGLONG startAddress = 0ULL;
            ULONGLONG win32StartAddress = 0ULL;
            BOOLEAN matchesTarget = FALSE;

            /*
             * Fetch the next reference first, then terminate the current thread; the target process may be detached from the
             * process/thread chain upon exit, so enumeration cannot continue using the current ETHREAD after termination.
             */
            nextThread = psGetNextProcessThread(processCursor, threadCursor);
            scannedThreads += 1UL;

            if (PsGetThreadProcess(threadCursor) == PsInitialSystemProcess &&
                !kswordArkDriverUnloadThreadIsTerminated(threadCursor)) {
                if (kswordArkDriverUnloadReadThreadAddressField(
                        threadCursor,
                        dynState->kernel.etStartAddress,
                        &startAddress) &&
                    kswordArkDriverUnloadAddressInImageRange(startAddress, imageStart, imageEnd)) {
                    matchesTarget = TRUE;
                }
                if (!matchesTarget &&
                    kswordArkDriverIntegrityOffsetPresent(dynState->kernel.etWin32StartAddress) &&
                    kswordArkDriverUnloadReadThreadAddressField(
                        threadCursor,
                        dynState->kernel.etWin32StartAddress,
                        &win32StartAddress) &&
                    kswordArkDriverUnloadAddressInImageRange(
                        win32StartAddress,
                        imageStart,
                        imageEnd)) {
                    matchesTarget = TRUE;
                }
            }

            if (matchesTarget) {
                LARGE_INTEGER waitInterval;
                NTSTATUS terminateStatus = STATUS_SUCCESS;
                NTSTATUS waitStatus = STATUS_SUCCESS;

                result->candidates += 1UL;
                terminateStatus = kswordArkDriverTerminateReferencedThread(
                    threadCursor,
                    STATUS_CANCELLED);
                if (NT_SUCCESS(terminateStatus)) {
                    waitInterval.QuadPart =
                        -((LONGLONG)KSW_DRIVER_UNLOAD_THREAD_TERMINATE_WAIT_MS * 10LL * 1000LL);
                    waitStatus = KeWaitForSingleObject(
                        threadCursor,
                        Executive,
                        KernelMode,
                        FALSE,
                        &waitInterval);
                }
                /* STATUS_TIMEOUT is NT_SUCCESS-compatible but the thread is still live. */
                if (NT_SUCCESS(terminateStatus) && waitStatus == STATUS_SUCCESS) {
                    result->terminated += 1UL;
                }
                else {
                    result->failures += 1UL;
                    result->lastStatus = !NT_SUCCESS(terminateStatus)
                        ? terminateStatus
                        : waitStatus;
                    aggregateStatus = result->lastStatus;
                }
            }

            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;

            if (scannedThreads >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS) {
                aggregateStatus = STATUS_BUFFER_OVERFLOW;
                result->lastStatus = aggregateStatus;
                if (threadCursor != NULL) {
                    ObDereferenceObject(threadCursor);
                    threadCursor = NULL;
                }
                stopScan = TRUE;
                break;
            }
        }

        if (scannedProcesses >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES) {
            aggregateStatus = STATUS_BUFFER_OVERFLOW;
            result->lastStatus = aggregateStatus;
            stopScan = TRUE;
        }
        if (!stopScan) {
            nextProcess = psGetNextProcess(processCursor);
        }
        ObDereferenceObject(processCursor);
        if (stopScan) {
            break;
        }
        processCursor = nextProcess;
    }

    if (result->failures != 0UL && NT_SUCCESS(aggregateStatus)) {
        aggregateStatus = result->lastStatus != STATUS_SUCCESS
            ? result->lastStatus
            : STATUS_UNSUCCESSFUL;
    }
    return aggregateStatus;
}

/* Note: Read-only validation that the loader list node's forward and backward links still point back to the target node. */
static NTSTATUS
kswordArkDriverUnloadInspectLoaderLinkCoherence(
    _In_ ULONGLONG linkAddress,
    _Out_ BOOLEAN* mismatchOut
    )
{
    LIST_ENTRY selfLinks;
    LIST_ENTRY flinkLinks;
    LIST_ENTRY blinkLinks;
    ULONGLONG flinkAddress = 0ULL;
    ULONGLONG blinkAddress = 0ULL;

    /*
     * Input: Kernel address of the target KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.
     * Handling: Safely read target node, Flink node, and Blink node; require Flink->Blink to match.
     *      Both Blink->Flink refer back to the target node. This is for evidence validation only; do not unlink or modify the chain.
     * Returns: STATUS_SUCCESS if the link is consistent; otherwise returns the specific status for read failures or link inconsistencies.
     */
    if (mismatchOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *mismatchOut = FALSE;
    if (linkAddress == 0ULL) {
        *mismatchOut = TRUE;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&selfLinks, sizeof(selfLinks));
    RtlZeroMemory(&flinkLinks, sizeof(flinkLinks));
    RtlZeroMemory(&blinkLinks, sizeof(blinkLinks));
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)linkAddress,
            &selfLinks,
            sizeof(selfLinks))) {
        *mismatchOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }

    flinkAddress = (ULONGLONG)(ULONG_PTR)selfLinks.Flink;
    blinkAddress = (ULONGLONG)(ULONG_PTR)selfLinks.Blink;
    if (flinkAddress == 0ULL || blinkAddress == 0ULL) {
        *mismatchOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)flinkAddress,
            &flinkLinks,
            sizeof(flinkLinks)) ||
        !kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)blinkAddress,
            &blinkLinks,
            sizeof(blinkLinks))) {
        *mismatchOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if ((ULONGLONG)(ULONG_PTR)flinkLinks.Blink != linkAddress ||
        (ULONGLONG)(ULONG_PTR)blinkLinks.Flink != linkAddress) {
        *mismatchOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    return STATUS_SUCCESS;
}

/* Note: Read-only validation to check if the target kernel image PE header is still parsable, detecting erased/corrupted states. */
static NTSTATUS
kswordArkDriverUnloadInspectImageHeader(
    _In_ ULONGLONG imageBase,
    _In_ ULONG expectedSizeOfImage,
    _Out_ ULONG* headerSizeOfImageOut,
    _Out_ ULONG* ntHeaderOffsetOut,
    _Out_ BOOLEAN* invalidHeaderOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG ntHeaderOffset = 0UL;

    /*
     * Input: Target module base address and loader record SizeOfImage.
     * Note: Safely read DOS/NT headers and verify MZ/PE/PE32+ signatures and SizeOfImage consistency.
     * Return STATUS_SUCCESS if the PE header is valid; return a failure status if the header is erased, the offset is
     *      invalid, or the size is inconsistent. This function reads memory only and does not erase or repair the PE header.
     */
    if (headerSizeOfImageOut == NULL ||
        ntHeaderOffsetOut == NULL ||
        invalidHeaderOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *headerSizeOfImageOut = 0UL;
    *ntHeaderOffsetOut = 0UL;
    *invalidHeaderOut = FALSE;
    if (imageBase == 0ULL) {
        *invalidHeaderOut = TRUE;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)imageBase,
            &dosHeader,
            sizeof(dosHeader))) {
        *invalidHeaderOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        dosHeader.e_lfanew > 0x1000) {
        *invalidHeaderOut = TRUE;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaderOffset = (ULONG)dosHeader.e_lfanew;
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)(imageBase + (ULONGLONG)ntHeaderOffset),
            &ntHeaders,
            sizeof(ntHeaders))) {
        *invalidHeaderOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL) {
        *invalidHeaderOut = TRUE;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *headerSizeOfImageOut = ntHeaders.OptionalHeader.SizeOfImage;
    *ntHeaderOffsetOut = ntHeaderOffset;
    if (expectedSizeOfImage != 0UL &&
        ntHeaders.OptionalHeader.SizeOfImage != expectedSizeOfImage) {
        *invalidHeaderOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    return STATUS_SUCCESS;
}

/* Note: Aggregates loader chain and PE header consistency evidence for strong unload preflight checks. */
static VOID
kswordArkDriverUnloadInspectLoaderAndImageEvidence(
    _In_opt_ const KswDriverIntegrityLdrTarget* loaderTarget,
    _In_ ULONGLONG imageBase,
    _In_ ULONG expectedSizeOfImage,
    _Out_ KswDriverUnloadLoaderImageEvidence* evidenceOut
    )
{
    /*
     * Input: target loader record and image base found via PsLoadedModuleList.
     * Processing: Perform bidirectional loader link consistency check and PE header validation separately.
     * Returns: outputs status and count via EvidenceOut; the function itself has no return value.
     */
    if (evidenceOut == NULL) {
        return;
    }
    RtlZeroMemory(evidenceOut, sizeof(*evidenceOut));
    evidenceOut->loaderLinkStatus = STATUS_REQUEST_NOT_ACCEPTED;
    evidenceOut->imageHeaderStatus = STATUS_REQUEST_NOT_ACCEPTED;

    if (loaderTarget != NULL && loaderTarget->found && loaderTarget->linkAddress != 0ULL) {
        evidenceOut->loaderLinkChecked = TRUE;
        evidenceOut->loaderLinkStatus = kswordArkDriverUnloadInspectLoaderLinkCoherence(
            loaderTarget->linkAddress,
            &evidenceOut->loaderLinkMismatch);
        if (!NT_SUCCESS(evidenceOut->loaderLinkStatus)) {
            evidenceOut->loaderLinkMismatch = TRUE;
        }
    }

    if (imageBase != 0ULL) {
        evidenceOut->imageHeaderChecked = TRUE;
        evidenceOut->imageHeaderStatus = kswordArkDriverUnloadInspectImageHeader(
            imageBase,
            expectedSizeOfImage,
            &evidenceOut->imageHeaderSizeOfImage,
            &evidenceOut->imageNtHeaderOffset,
            &evidenceOut->invalidImageHeader);
        if (!NT_SUCCESS(evidenceOut->imageHeaderStatus)) {
            evidenceOut->invalidImageHeader = TRUE;
        }
    }
}

/* Note: Read-only pre-unload evidence for the unload target is retrieved to determine whether to allow system unloading or force cleanup. */
static NTSTATUS
kswordArkDriverUnloadBuildPreflightResult(
    _In_ PDRIVER_OBJECT driverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* normalizedDriverName,
    _In_ ULONGLONG targetModuleBase,
    _In_ ULONG flags,
    _Out_ KswDriverUnloadPreflightResult* result
    )
{
    KswDriverUnloadPreflightWorkspace* workspace = NULL;
    KswDynState* dynState = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    const KswHookSystemModuleEntry* targetModule = NULL;
    KswDriverIntegrityLdrTarget ldrTarget;
    KswDriverUnloadLoaderImageEvidence loaderImageEvidence;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS evidenceStatus = STATUS_SUCCESS;
    ULONGLONG driverStart = 0ULL;
    ULONGLONG driverEnd = 0ULL;
    const BOOLEAN kTeardownRequested =
        ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL &&
            (flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL)
        ? TRUE
        : FALSE;

    if (driverObject == NULL || result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    UNREFERENCED_PARAMETER(moduleInfoBytes);

    workspace = (KswDriverUnloadPreflightWorkspace*)kswordArkAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
    if (workspace == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workspace, sizeof(*workspace));
    dynState = &workspace->dynState;

    RtlZeroMemory(result, sizeof(*result));
    RtlZeroMemory(&ldrTarget, sizeof(ldrTarget));
    RtlZeroMemory(&loaderImageEvidence, sizeof(loaderImageEvidence));

    result->allowDirectUnload = FALSE;
    result->allowZwUnload = FALSE;
    result->allowDestructiveCleanup =
        (flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL ? TRUE : FALSE;

    __try {
        driverStart = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
        driverEnd = driverStart + (ULONGLONG)driverObject->DriverSize;
        result->hasDriverUnload = (driverObject->DriverUnload != NULL) ? TRUE : FALSE;
        status = kswordArkDriverUnloadBuildServiceRegistryPath(
            driverObject,
            normalizedDriverName,
            result->serviceRegistryPath,
            RTL_NUMBER_OF(result->serviceRegistryPath));
        result->hasServiceRegistryPath = NT_SUCCESS(status) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return status;
    }

    if (driverStart == 0ULL ||
        driverEnd <= driverStart ||
        driverEnd < driverStart) {
        result->allowDirectUnload = FALSE;
        result->allowZwUnload = FALSE;
        result->allowDestructiveCleanup = FALSE;
        result->status = STATUS_INVALID_PARAMETER;
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return result->status;
    }
    result->driverStart = driverStart;
    result->driverEnd = driverEnd;

    if (targetModuleBase != 0ULL &&
        targetModuleBase != driverStart) {
        result->allowDirectUnload = FALSE;
        result->allowZwUnload = FALSE;
        result->allowDestructiveCleanup = FALSE;
        result->status = STATUS_OBJECT_TYPE_MISMATCH;
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return result->status;
    }

    kswordArkDynDataSnapshot(dynState);
    result->allowDirectUnload = result->hasDriverUnload;
    result->allowZwUnload = result->hasServiceRegistryPath;
    result->hasValidDynData =
        dynState->initialized &&
        dynState->ntosActive &&
        (dynState->capabilityMask & KSW_CAP_DRIVER_OBJECT_FIELDS) != 0ULL &&
        (dynState->capabilityMask & KSW_CAP_KERNEL_MODULE_LIST_FIELDS) != 0ULL &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.doDriverStart) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.doDriverSize) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.doDriverSection) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.doMajorFunction) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.doDriverUnload) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrDllBase) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrSizeOfImage) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrInLoadOrderLinks) &&
        kswordArkDriverIntegrityOffsetPresent(dynState->kernelGlobals.psLoadedModuleList);
    result->hasPdbBackedDynData = kswordArkDriverUnloadHasPdbBackedDynData(dynState);

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (NT_SUCCESS(status) && moduleInfo != NULL) {
        targetModule = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, driverStart);
        result->isCoreKernelModule = kswordArkDriverIntegrityIsCoreKernelModule(targetModule);
        if (targetModule != NULL) {
            const UCHAR* fileName = NULL;
            ULONG fileNameBytes = 0UL;

            kswordArkHookGetModuleFileName(targetModule, &fileName, &fileNameBytes);
            if (kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "KswordARK.sys")) {
                result->isSelfModule = TRUE;
            }
            if (kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntoskrnl.exe") ||
                kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrnlmp.exe") ||
                kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrnlpa.exe") ||
                kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrpamp.exe") ||
                kswordArkDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "hal.dll")) {
                result->isCoreKernelModule = TRUE;
            }
        }
    }
    else {
        evidenceStatus = status;
        status = STATUS_SUCCESS;
    }

    if (!result->isSelfModule &&
        result->serviceRegistryPath[0] != L'\0') {
        const WCHAR* leafName = result->serviceRegistryPath;
        if (kswordArkDriverUnloadStartsWithInsensitive(
            result->serviceRegistryPath,
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")) {
            const ULONG kPrefixChars = kswordArkDriverUnloadCountFixedStringChars(
                L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
            leafName = result->serviceRegistryPath + kPrefixChars;
        }
        if (kswordArkDriverUnloadStartsWithInsensitive(leafName, L"KswordARK")) {
            result->isSelfModule = TRUE;
        }
    }

    if (result->hasValidDynData) {
        status = kswordArkDriverIntegrityFindLoadedModule(dynState, driverStart, &ldrTarget);
        if (NT_SUCCESS(status) && ldrTarget.found) {
            const ULONGLONG kDriverSize = (ULONGLONG)driverObject->DriverSize;
            result->loaderEntryAddress = ldrTarget.entryAddress;
            result->loaderDllBase = ldrTarget.dllBase;
            result->loaderSizeOfImage = ldrTarget.sizeOfImage;
            if (ldrTarget.dllBase == driverStart &&
                ldrTarget.sizeOfImage != 0UL &&
                (ULONGLONG)ldrTarget.sizeOfImage == kDriverSize &&
                ((ULONGLONG)(ULONG_PTR)driverObject->DriverSection == 0ULL ||
                    (ULONGLONG)(ULONG_PTR)driverObject->DriverSection == ldrTarget.entryAddress)) {
                result->hasValidLoaderEvidence = TRUE;
            }
            else {
                evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
                result->hasValidLoaderEvidence = FALSE;
            }
        }
        else {
            evidenceStatus = status;
            result->hasValidLoaderEvidence = FALSE;
        }
        status = STATUS_SUCCESS;
    }

    kswordArkDriverUnloadInspectLoaderAndImageEvidence(
        result->hasValidLoaderEvidence ? &ldrTarget : NULL,
        driverStart,
        result->loaderSizeOfImage != 0UL ? result->loaderSizeOfImage : (ULONG)driverObject->DriverSize,
        &loaderImageEvidence);
    result->hasLoaderLinkCheck = loaderImageEvidence.loaderLinkChecked;
    result->hasLoaderLinkMismatch = loaderImageEvidence.loaderLinkMismatch;
    result->hasImageHeaderCheck = loaderImageEvidence.imageHeaderChecked;
    result->hasInvalidImageHeader = loaderImageEvidence.invalidImageHeader;
    result->loaderLinkStatus = loaderImageEvidence.loaderLinkStatus;
    result->imageHeaderStatus = loaderImageEvidence.imageHeaderStatus;
    result->imageHeaderSizeOfImage = loaderImageEvidence.imageHeaderSizeOfImage;
    result->imageNtHeaderOffset = loaderImageEvidence.imageNtHeaderOffset;
    if ((loaderImageEvidence.loaderLinkMismatch ||
            loaderImageEvidence.invalidImageHeader) &&
        evidenceStatus == STATUS_SUCCESS) {
        evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
    }

    if (result->hasValidDynData && result->hasValidLoaderEvidence) {
        result->hasValidDriverObjectOffsets =
            kswordArkDriverUnloadValidateDriverObjectOffsets(driverObject, dynState);
        if (!result->hasValidDriverObjectOffsets && evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }

    result->threadScanStatus = kswordArkDriverUnloadScanModuleResidentThreads(
        dynState,
        driverStart,
        driverEnd,
        &result->scannedProcessCount,
        &result->scannedThreadCount,
        &result->moduleResidentThreadCount);
    if (NT_SUCCESS(result->threadScanStatus)) {
        result->hasThreadScan = TRUE;
        if (result->moduleResidentThreadCount != 0UL) {
            result->hasModuleResidentThreads = TRUE;
            if (evidenceStatus == STATUS_SUCCESS) {
                evidenceStatus = STATUS_DEVICE_BUSY;
            }
        }
    }
    else {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = result->threadScanStatus;
        }
        result->allowDestructiveCleanup = FALSE;
        result->allowDirectUnload = FALSE;
    }

    {
        KswDriverUnloadCallbackEvidenceResult callbackEvidence;

        RtlZeroMemory(&callbackEvidence, sizeof(callbackEvidence));
        result->callbackScanStatus = kswordArkDriverUnloadInspectCallbacksByModuleBase(
            driverStart,
            &callbackEvidence);
        if (NT_SUCCESS(result->callbackScanStatus)) {
            result->hasCallbackScan = TRUE;
            result->callbackEnumeratedCount = callbackEvidence.enumerated;
            result->moduleCallbackCount = callbackEvidence.matched;
            result->removableModuleCallbackCount = callbackEvidence.removable;
            result->nonRemovableModuleCallbackCount = callbackEvidence.nonRemovable;
            if (callbackEvidence.matched != 0UL) {
                result->hasModuleCallbacks = TRUE;
            }
            if (callbackEvidence.nonRemovable != 0UL) {
                result->hasNonRemovableModuleCallbacks = TRUE;
            }
        }
        else {
            if (evidenceStatus == STATUS_SUCCESS) {
                evidenceStatus = result->callbackScanStatus;
            }
            result->allowDestructiveCleanup = FALSE;
            result->allowDirectUnload = FALSE;
        }
    }

    __try {
        PDEVICE_OBJECT rootDevice = driverObject->DeviceObject;
        ULONG visitedCount = 0UL;
        PDEVICE_OBJECT* visited = workspace->visitedDevices;

        while (rootDevice != NULL) {
            PDEVICE_OBJECT nextDevice = NULL;
            ULONG previousIndex = 0UL;
            NTSTATUS deviceIdleStatus = STATUS_SUCCESS;

            result->hasDeviceChain = TRUE;
            if (visitedCount >= KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT) {
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = STATUS_BUFFER_OVERFLOW;
                }
                break;
            }
            for (previousIndex = 0UL; previousIndex < visitedCount; ++previousIndex) {
                if (visited[previousIndex] == rootDevice) {
                    result->hasDeviceLoop = TRUE;
                    break;
                }
            }
            if (result->hasDeviceLoop) {
                break;
            }
            visited[visitedCount++] = rootDevice;

            deviceIdleStatus = kswordArkDriverUnloadCheckDeviceObjectIdleUnsafe(
                driverObject,
                rootDevice,
                &nextDevice);
            if (deviceIdleStatus == STATUS_OBJECT_TYPE_MISMATCH) {
                result->hasCrossDriverAttach = TRUE;
                break;
            }
            if (deviceIdleStatus == STATUS_DEVICE_BUSY) {
                if (rootDevice->AttachedDevice != NULL) {
                    result->hasAttachedDevice = TRUE;
                }
                if (rootDevice->ReferenceCount != 0) {
                    result->hasBusyDeviceReference = TRUE;
                }
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = STATUS_DEVICE_BUSY;
                }
                break;
            }
            if (!NT_SUCCESS(deviceIdleStatus)) {
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = deviceIdleStatus;
                }
                break;
            }

            rootDevice = nextDevice;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        evidenceStatus = status;
        status = STATUS_SUCCESS;
    }

    if (result->isSelfModule || result->isCoreKernelModule) {
        result->allowDirectUnload = FALSE;
        result->allowZwUnload = FALSE;
        result->allowDestructiveCleanup = FALSE;
        result->status = STATUS_DRIVER_BLOCKED_CRITICAL;
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        }
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return result->status;
    }

    if (result->hasDeviceLoop || result->hasCrossDriverAttach) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_INVALID_DEVICE_REQUEST;
        }
        result->allowDestructiveCleanup = FALSE;
    }
    if ((result->hasAttachedDevice || result->hasBusyDeviceReference) &&
        (!kTeardownRequested ||
            (flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        result->allowDestructiveCleanup = FALSE;
        result->allowDirectUnload = FALSE;
    }
    if (result->hasModuleResidentThreads &&
        (!kTeardownRequested ||
            (flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        result->allowDestructiveCleanup = FALSE;
    }
    if (result->hasNonRemovableModuleCallbacks ||
        (result->hasModuleCallbacks &&
            (flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        result->allowDestructiveCleanup = FALSE;
    }
    if (result->hasLoaderLinkMismatch || result->hasInvalidImageHeader) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
        result->allowDestructiveCleanup = FALSE;
        result->allowDirectUnload = FALSE;
    }

    if (!result->hasServiceRegistryPath) {
        result->allowZwUnload = FALSE;
    }
    if (!result->hasValidDynData ||
        !result->hasPdbBackedDynData ||
        !result->hasValidLoaderEvidence) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_REQUEST_NOT_ACCEPTED;
        }
        result->allowDestructiveCleanup = FALSE;
        result->allowDirectUnload = FALSE;
    }
    if (!result->hasValidDriverObjectOffsets) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
        result->allowDestructiveCleanup = FALSE;
        result->allowDirectUnload = FALSE;
    }

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
    result->status = evidenceStatus;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverUnloadApplyPreUnloadTeardownUnsafe(
    _Inout_ PkswDriverUnloadContext unloadContext
    )
{
    KswDynState dynState;
    KswDriverUnloadEntryTransaction entryTransaction;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;
    ULONG terminatePass = 0UL;
    ULONG remainingThreads = 0UL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;

    /*
     * First half of the transaction forcibly tearing down DriverObject:
     * 1. Re-verify PDB-backed ETHREAD fields and perform a single read-only thread scan;
     * 2. Block new external entry points only after saving MajorFunction, FastIo, and Device Flags;
     * 3. Restore all reversible entry fields when thread or callback cleanup fails;
     * 4. Only after all operations succeed is the transaction committed, allowing entry into DriverUnload.
     */
    if (unloadContext == NULL || unloadContext->driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) == 0UL) {
        return STATUS_SUCCESS;
    }
    if ((unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL ||
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD) == 0UL ||
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS) == 0UL) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&entryTransaction, sizeof(entryTransaction));
    kswordArkDynDataSnapshot(&dynState);
    if (!kswordArkDriverUnloadHasPdbBackedThreadDynData(&dynState)) {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    status = kswordArkDriverUnloadScanModuleResidentThreads(
        &dynState,
        unloadContext->driverStart,
        unloadContext->driverEnd,
        &scannedProcesses,
        &scannedThreads,
        &remainingThreads);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverUnloadSnapshotEntryTransaction(
        unloadContext->driverObject,
        &entryTransaction);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkDriverUnloadApplyEntryTransaction(
        unloadContext->driverObject,
        &entryTransaction);
    if (!NT_SUCCESS(status)) {
        goto RollbackEntryTransaction;
    }
    unloadContext->cleanupFlagsApplied |=
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD;

    for (terminatePass = 0UL;
        terminatePass < KSW_DRIVER_UNLOAD_THREAD_TERMINATE_PASSES;
        ++terminatePass) {
        KswDriverUnloadThreadCleanupResult threadResult;

        RtlZeroMemory(&threadResult, sizeof(threadResult));
        threadResult.lastStatus = STATUS_SUCCESS;
        status = kswordArkDriverUnloadTerminateModuleThreadsUnsafe(
            &dynState,
            unloadContext->driverStart,
            unloadContext->driverEnd,
            &threadResult);
        unloadContext->threadCandidates += threadResult.candidates;
        unloadContext->threadsTerminated += threadResult.terminated;
        unloadContext->threadFailures += threadResult.failures;
        if (threadResult.lastStatus != STATUS_SUCCESS) {
            unloadContext->threadLastStatus = threadResult.lastStatus;
        }
        if (!NT_SUCCESS(status)) {
            goto RollbackEntryTransaction;
        }

        remainingThreads = 0UL;
        scannedProcesses = 0UL;
        scannedThreads = 0UL;
        status = kswordArkDriverUnloadScanModuleResidentThreads(
            &dynState,
            unloadContext->driverStart,
            unloadContext->driverEnd,
            &scannedProcesses,
            &scannedThreads,
            &remainingThreads);
        if (!NT_SUCCESS(status)) {
            unloadContext->threadLastStatus = status;
            goto RollbackEntryTransaction;
        }
        if (remainingThreads == 0UL) {
            break;
        }
    }
    if (remainingThreads != 0UL) {
        unloadContext->threadCandidates += remainingThreads;
        unloadContext->threadFailures += remainingThreads;
        unloadContext->threadLastStatus = STATUS_DEVICE_BUSY;
        status = STATUS_DEVICE_BUSY;
        goto RollbackEntryTransaction;
    }

    unloadContext->cleanupFlagsApplied |=
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS;

    if ((unloadContext->flags &
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) != 0UL) {
        KswDriverUnloadCallbackCleanupResult callbackResult;

        RtlZeroMemory(&callbackResult, sizeof(callbackResult));
        callbackResult.lastStatus = STATUS_SUCCESS;
        status = kswordArkDriverUnloadRemoveCallbacksByModuleBase(
            unloadContext->driverStart,
            &callbackResult);
        unloadContext->callbackCandidates = callbackResult.candidates;
        unloadContext->callbacksRemoved = callbackResult.removed;
        unloadContext->callbackFailures = callbackResult.failures;
        unloadContext->callbackLastStatus = callbackResult.lastStatus;
        if (!NT_SUCCESS(status)) {
            goto RollbackEntryTransaction;
        }
        unloadContext->cleanupFlagsApplied |=
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE;
    }
    kswordArkDriverUnloadReleaseEntryTransaction(&entryTransaction);
    return STATUS_SUCCESS;

RollbackEntryTransaction:
    rollbackStatus = kswordArkDriverUnloadRollbackEntryTransaction(
        unloadContext->driverObject,
        &entryTransaction);
    unloadContext->cleanupFlagsApplied &=
        ~KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD;
    kswordArkDriverUnloadReleaseEntryTransaction(&entryTransaction);
    return NT_SUCCESS(rollbackStatus) ? status : rollbackStatus;
}

/* Note: Perform additional cleanup after forced unloading; every action must be explicitly enabled by a valid flag. */
static NTSTATUS
kswordArkDriverUnloadApplyCleanupUnsafe(
    _Inout_ PkswDriverUnloadContext unloadContext,
    _In_ BOOLEAN driverUnloadWasCalled
    )
{
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    BOOLEAN allowPersistentCleanup = FALSE;
    BOOLEAN deleteDeviceObjects = FALSE;
    BOOLEAN clearDispatchForPath = FALSE;
    BOOLEAN dispatchCleared = FALSE;
    BOOLEAN blockNewDeviceAccess = FALSE;
    ULONG clearDispatchFlag = 0UL;

    if (unloadContext == NULL || unloadContext->driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    allowPersistentCleanup =
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL
        ? TRUE
        : FALSE;
    if (!allowPersistentCleanup) {
        return STATUS_SUCCESS;
    }

    deleteDeviceObjects =
        (!driverUnloadWasCalled &&
            (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD) != 0UL) ||
        ((unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL)
        ? TRUE
        : FALSE;

    if (driverUnloadWasCalled &&
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD) != 0UL) {
        clearDispatchForPath = TRUE;
        clearDispatchFlag = KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD;
    }
    else if (!driverUnloadWasCalled &&
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        clearDispatchForPath = TRUE;
        clearDispatchFlag = KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD;
    }

    /*
     * Note: Refer to the 'block external access first' phase of the strong unload scheme. Since the
     * public WDK lacks IoLockRemoveDevice, the explicit destructive fallback first neutralizes the
     * dispatch table with reject IRP stubs and re-marks the device as initializing before deleting
     * device objects, reducing the window for new create/IRP entries into the target driver code.
     */
    blockNewDeviceAccess = (clearDispatchForPath || deleteDeviceObjects) ? TRUE : FALSE;
    if (clearDispatchForPath) {
        kswordArkDriverUnloadClearDispatchUnsafe(unloadContext->driverObject);
        unloadContext->cleanupFlagsApplied |= clearDispatchFlag;
        dispatchCleared = TRUE;
    }
    if (blockNewDeviceAccess) {
        NTSTATUS blockStatus = kswordArkDriverUnloadBlockNewDeviceCreatesUnsafe(
            unloadContext->driverObject,
            NULL);
        if (!NT_SUCCESS(blockStatus)) {
            return blockStatus;
        }
    }

    if (deleteDeviceObjects) {
        ULONG deletedDeviceCount = 0UL;
        ULONG detachedDeviceCount = 0UL;
        const BOOLEAN kDetachDeviceStacks =
            (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS) != 0UL
            ? TRUE
            : FALSE;
        NTSTATUS deleteStatus = kswordArkDriverUnloadDeleteDeviceObjectsUnsafe(
            unloadContext->driverObject,
            kDetachDeviceStacks,
            &deletedDeviceCount,
            &detachedDeviceCount);
        unloadContext->deletedDeviceCount = deletedDeviceCount;
        unloadContext->detachedDeviceCount = detachedDeviceCount;
        unloadContext->cleanupFlagsApplied |=
            (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL
            ? KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS
            : KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD;
        if (kDetachDeviceStacks) {
            unloadContext->cleanupFlagsApplied |=
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS;
        }
        if (!NT_SUCCESS(deleteStatus)) {
            return deleteStatus;
        }
    }
    if (driverUnloadWasCalled && !deleteDeviceObjects) {
        NTSTATUS noDeviceStatus = kswordArkDriverUnloadRequireNoDeviceObjectsUnsafe(
            unloadContext->driverObject);
        if (!NT_SUCCESS(noDeviceStatus)) {
            return noDeviceStatus;
        }
    }

    if ((unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        __try {
            ObMakeTemporaryObject(unloadContext->driverObject);
            unloadContext->cleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    if ((unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER) != 0UL) {
        kswordArkDriverUnloadClearUnloadPointerUnsafe(unloadContext->driverObject);
        unloadContext->cleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER;
    }
    if (driverUnloadWasCalled &&
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD) != 0UL) {
        if (!dispatchCleared) {
            kswordArkDriverUnloadClearDispatchUnsafe(unloadContext->driverObject);
            unloadContext->cleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD;
            dispatchCleared = TRUE;
        }
    }
    if (!driverUnloadWasCalled &&
        (unloadContext->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        if (!dispatchCleared) {
            kswordArkDriverUnloadClearDispatchUnsafe(unloadContext->driverObject);
            unloadContext->cleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD;
            dispatchCleared = TRUE;
        }
    }

    return cleanupStatus;
}

/* Note: Demote R3 request flags to R0 flags actually allowed for execution. */
static ULONG
kswordArkDriverUnloadSanitizeFlags(
    _In_ ULONG requestedFlags
    )
{
    // Input: R3 raw strong unload flags.
    // Processing: retain locator-type flags; if ALLOW_DESTRUCTIVE_CLEANUP is not set, clear all persistent modification/removal-type flags.
    // Returns: R0 flags actually executed in this instance, used to fill back the response and drive subsequent logic.
    const ULONG kMutatingMask =
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;

    if ((requestedFlags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL) {
        return requestedFlags & ~kMutatingMask;
    }
    return requestedFlags;
}

/* Note: When the target lacks a DriverUnload routine, determine whether to still enter the post-processing branch. */
static BOOLEAN
kswordArkDriverUnloadShouldCleanupWithoutUnload(
    _In_ ULONG flags
    )
{
    // Input: Strong unload flags passed from R3.
    // Note: return TRUE only if explicit permission for persistent cleanup is granted and the specific cleanup flags are set.
    // Returns: TRUE indicates post-processing must be executed even without DriverUnload; FALSE indicates reporting the absence of DriverUnload directly.
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL) {
        return FALSE;
    }
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        return TRUE;
    }
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER) != 0UL) {
        return TRUE;
    }
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD) != 0UL) {
        return TRUE;
    }
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL) {
        return TRUE;
    }
    if ((flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        return TRUE;
    }
    return FALSE;
}

/* Note: Check if this request explicitly requires post-processing/neutralization of the DriverObject. */
static BOOLEAN
kswordArkDriverUnloadHasCleanupRequest(
    _In_ ULONG flags
    )
{
    // Input: Force-unload flags passed from R3.
    // Processing: Only check cleanup flags that modify DriverObject/callback state; do not rely on the FORCE_CLEANUP combination macro.
    // Returns: TRUE indicates that additional cleanup actions were requested before and after calling DriverUnload; FALSE indicates only DriverUnload was called.
    const ULONG kCleanupMask =
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;

    return ((flags & kCleanupMask) != 0UL) ? TRUE : FALSE;
}

/* Note: Consolidate the preflight 'success but not executable' state into a single explicit denial code. */
static NTSTATUS
kswordArkDriverUnloadPreflightDenyStatus(
    _In_opt_ const KswDriverUnloadPreflightResult* preflight
    )
{
    // Input: Pre-unload check result; may be null.
    // Processing: Prioritize retaining the specific failure reason already computed in preflight; if the status remains
    //      success, supplement a stable NTSTATUS based on critical boolean evidence to avoid R3 seeing lastStatus=0.
    // Returns: a failure NTSTATUS that can be directly written to response->lastStatus / waitStatus.
    if (preflight == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(preflight->status)) {
        return preflight->status;
    }
    if (preflight->isSelfModule || preflight->isCoreKernelModule) {
        return STATUS_DRIVER_BLOCKED_CRITICAL;
    }
    if (preflight->hasDeviceLoop || preflight->hasCrossDriverAttach) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!preflight->hasThreadScan) {
        return NT_SUCCESS(preflight->threadScanStatus)
            ? STATUS_REQUEST_NOT_ACCEPTED
            : preflight->threadScanStatus;
    }
    if (!preflight->hasCallbackScan) {
        return NT_SUCCESS(preflight->callbackScanStatus)
            ? STATUS_REQUEST_NOT_ACCEPTED
            : preflight->callbackScanStatus;
    }
    if (preflight->hasModuleResidentThreads) {
        return STATUS_DEVICE_BUSY;
    }
    if (preflight->hasModuleCallbacks) {
        return STATUS_DEVICE_BUSY;
    }
    if (preflight->hasLoaderLinkMismatch || preflight->hasInvalidImageHeader) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (preflight->hasAttachedDevice || preflight->hasBusyDeviceReference) {
        return STATUS_DEVICE_BUSY;
    }
    if (!preflight->hasValidDriverObjectOffsets ||
        (preflight->driverStart != 0ULL &&
            preflight->loaderDllBase != 0ULL &&
            preflight->loaderDllBase != preflight->driverStart)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!preflight->hasValidDynData ||
        !preflight->hasPdbBackedDynData ||
        !preflight->hasValidLoaderEvidence) {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    if (!preflight->hasServiceRegistryPath && !preflight->hasDriverUnload) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_REQUEST_NOT_ACCEPTED;
}

/* Note: Centralized logic to determine if a fallback to direct DriverUnload/neutralization is permitted after system unloading failure. */
static BOOLEAN
kswordArkDriverUnloadCanUseDestructiveFallback(
    _In_opt_ const KswDriverUnloadPreflightResult* preflight,
    _In_ ULONG flags
    )
{
    // Input: preflight evidence and request flags that have already been sanitized.
    // Processing: Requires ALLOW_DESTRUCTIVE_CLEANUP, PDB-backed DynData, loader alignment, and live
    //      _DRIVER_OBJECT offset self-checks to all pass, and ensures there is actually an executable action.
    // Return: TRUE indicates entry into forced fallback is allowed; FALSE indicates failure status must be returned exclusively.
    if (preflight == NULL) {
        return FALSE;
    }
    if (!preflight->allowDestructiveCleanup ||
        !preflight->hasValidDynData ||
        !preflight->hasPdbBackedDynData ||
        !preflight->hasValidDriverObjectOffsets ||
        !preflight->hasValidLoaderEvidence ||
        !preflight->hasThreadScan ||
        !preflight->hasCallbackScan) {
        return FALSE;
    }
    if (!kswordArkDriverUnloadHasCleanupRequest(flags)) {
        return FALSE;
    }
    if (!preflight->allowDirectUnload &&
        !kswordArkDriverUnloadShouldCleanupWithoutUnload(flags)) {
        return FALSE;
    }
    return TRUE;
}

/* Note: Only when Zw unloading succeeds but the loopback remains busy, determine whether post-neutralization is allowed. */
/* Note: Determine if the forced fallback allows removing target module callbacks before DriverUnload. */
static BOOLEAN
kswordArkDriverUnloadCanPreCleanupCallbacks(
    _In_opt_ const KswDriverUnloadPreflightResult* preflight,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request
    )
{
    // Input: preflight evidence and local request snapshot.
    // Handling: Callback cleanup is enabled only when the module base address is explicit, matches DriverStart, and the forced
    //      fallback satisfies PDB-backed safety gates; callback cleanup is rejected when the service name path lacks a base address.
    // Returns: TRUE indicates that module base address callbacks can be invoked for cleanup; FALSE indicates this high-risk step cannot be executed.
    if (preflight == NULL || request == NULL) {
        return FALSE;
    }
    if ((request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) == 0UL ||
        (request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        request->targetModuleBase == 0ULL) {
        return FALSE;
    }
    if (request->targetModuleBase != preflight->driverStart) {
        return FALSE;
    }
    return kswordArkDriverUnloadCanUseDestructiveFallback(preflight, request->flags);
}

/* Note: Pure system unload thread; carries only the service registry path, without holding an additional DriverObject reference. */
static VOID
kswordArkDriverUnloadZwThreadRoutine(
    _In_opt_ PVOID startContext
    )
{
    PkswDriverUnloadZwContext unloadContext = (PkswDriverUnloadZwContext)startContext;
    UNICODE_STRING serviceRegistryPath;
    NTSTATUS threadStatus = STATUS_INVALID_PARAMETER;

    if (unloadContext == NULL || unloadContext->serviceRegistryPath[0] == L'\0') {
        if (unloadContext != NULL) {
            kswordArkDriverUnloadReleaseZwContext(unloadContext);
        }
        PsTerminateSystemThread(threadStatus);
        return;
    }

    RtlInitUnicodeString(&serviceRegistryPath, unloadContext->serviceRegistryPath);
    threadStatus = ZwUnloadDriver(&serviceRegistryPath);
    unloadContext->unloadStatus = threadStatus;
    kswordArkDriverUnloadReleaseZwContext(unloadContext);
    PsTerminateSystemThread(threadStatus);
}

/* Note: Executes the pure ZwUnloadDriver path without holding a reference to the DriverObject. */
static NTSTATUS
kswordArkDriverUnloadRunZwOnly(
    _In_reads_(KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS) const WCHAR* serviceRegistryPath,
    _In_ ULONG timeoutMilliseconds,
    _Out_ NTSTATUS* waitStatusOut,
    _Out_ NTSTATUS* unloadStatusOut
    )
{
    HANDLE threadHandle = NULL;
    PETHREAD threadObject = NULL;
    LARGE_INTEGER timeoutInterval;
    PkswDriverUnloadZwContext zwContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Input: Full Services registry path and wait timeout.
    // Note: Call ZwUnloadDriver in a system thread; context saves only the path, not the DriverObject.
    // Return: directly returns the corresponding status on wait failure/timeout; returns the NTSTATUS from ZwUnloadDriver on success.
    if (serviceRegistryPath == NULL ||
        serviceRegistryPath[0] == L'\0' ||
        waitStatusOut == NULL ||
        unloadStatusOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *waitStatusOut = STATUS_SUCCESS;
    *unloadStatusOut = STATUS_PENDING;

#pragma warning(push)
#pragma warning(disable:4996)
    zwContext = (PkswDriverUnloadZwContext)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*zwContext),
        KSW_DRIVER_UNLOAD_TAG);
#pragma warning(pop)
    if (zwContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(zwContext, sizeof(*zwContext));
    zwContext->referenceCount = 2L;
    status = RtlStringCchCopyW(
        zwContext->serviceRegistryPath,
        RTL_NUMBER_OF(zwContext->serviceRegistryPath),
        serviceRegistryPath);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(zwContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }
    zwContext->unloadStatus = STATUS_PENDING;

    if (timeoutMilliseconds == 0UL) {
        timeoutMilliseconds = KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS;
    }
    if (timeoutMilliseconds > KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS) {
        timeoutMilliseconds = KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS;
    }

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        kswordArkDriverUnloadZwThreadRoutine,
        zwContext);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(zwContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        SYNCHRONIZE,
        *PsThreadType,
        KernelMode,
        (PVOID*)&threadObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        kswordArkDriverUnloadReleaseZwContext(zwContext);
        return status;
    }
    timeoutInterval.QuadPart = -((LONGLONG)timeoutMilliseconds * 10LL * 1000LL);
    *waitStatusOut = KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    ObDereferenceObject(threadObject);
    ZwClose(threadHandle);

    if (*waitStatusOut != STATUS_SUCCESS) {
        kswordArkDriverUnloadReleaseZwContext(zwContext);
        return *waitStatusOut;
    }

    *unloadStatusOut = zwContext->unloadStatus;
    status = *unloadStatusOut;
    kswordArkDriverUnloadReleaseZwContext(zwContext);
    return status;
}

/* Verify that no named DriverObject can be referenced after the final local dereference. */
static NTSTATUS
kswordArkDriverUnloadVerifyDriverObjectGone(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* normalizedDriverName
    )
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST verifyRequest;
    PDRIVER_OBJECT referencedObject = NULL;
    WCHAR verifiedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    // Inputs: original request snapshot and the normalized object path found before unload.
    // Processing: try the same lookup path used by the operation, but fall back to the exact
    // normalized name so module-base requests cannot hide a still-named DriverObject.
    // Return: STATUS_SUCCESS only when the object is no longer referenceable; otherwise a
    // blocking NTSTATUS that is safe to expose as the unload result.
    if (request == NULL || normalizedDriverName == NULL || normalizedDriverName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&verifyRequest, sizeof(verifyRequest));
    RtlCopyMemory(&verifyRequest, request, sizeof(verifyRequest));
    status = kswordArkDriverUnloadReferenceByName(
        &verifyRequest,
        &referencedObject,
        verifiedName,
        RTL_NUMBER_OF(verifiedName));
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(referencedObject);
        return STATUS_DEVICE_BUSY;
    }
    if (!kswordArkDriverUnloadShouldTryAlternateName(status) &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        return status;
    }

    RtlZeroMemory(&verifyRequest, sizeof(verifyRequest));
    verifyRequest.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
    (VOID)RtlStringCchCopyW(
        verifyRequest.driverName,
        RTL_NUMBER_OF(verifyRequest.driverName),
        normalizedDriverName);
    status = kswordArkDriverUnloadReferenceByName(
        &verifyRequest,
        &referencedObject,
        verifiedName,
        RTL_NUMBER_OF(verifiedName));
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(referencedObject);
        return STATUS_DEVICE_BUSY;
    }
    if (!kswordArkDriverUnloadShouldTryAlternateName(status) &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        return status;
    }

    return STATUS_SUCCESS;
}

/* Verify that the target image left both loader-list and module-list views. */
static NTSTATUS
kswordArkDriverUnloadVerifyLoaderGone(
    _In_ const KswDriverUnloadPreflightResult* preflight
    )
{
    KswDynState dynState;
    KswDriverIntegrityLdrTarget ldrTarget;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    NTSTATUS loaderStatus = STATUS_SUCCESS;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    BOOLEAN checkedAnyView = FALSE;

    // Inputs: preflight evidence containing the exact DriverStart/module base.
    // Processing: re-walk PsLoadedModuleList with PDB-backed offsets, then compare the
    // public SystemModuleInformation snapshot. Both are read-only checks.
    // Return: STATUS_SUCCESS when no view still owns the target base; failure when the
    // image is still listed or when every verification view is unavailable.
    if (preflight == NULL || preflight->driverStart == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&ldrTarget, sizeof(ldrTarget));
    kswordArkDynDataSnapshot(&dynState);
    if (dynState.initialized &&
        dynState.ntosActive &&
        kswordArkDriverUnloadHasPdbBackedDynData(&dynState)) {
        checkedAnyView = TRUE;
        loaderStatus = kswordArkDriverIntegrityFindLoadedModule(
            &dynState,
            preflight->driverStart,
            &ldrTarget);
        if (NT_SUCCESS(loaderStatus) && ldrTarget.found) {
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        if (!NT_SUCCESS(loaderStatus) &&
            loaderStatus != STATUS_NOT_FOUND) {
            return loaderStatus;
        }
    }

    moduleStatus = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (NT_SUCCESS(moduleStatus) && moduleInfo != NULL) {
        checkedAnyView = TRUE;
        if (kswordArkDriverIntegrityFindModuleForAddress(
                moduleInfo,
                preflight->driverStart) != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    else if (!checkedAnyView) {
        return moduleStatus;
    }

    return checkedAnyView ? STATUS_SUCCESS : STATUS_REQUEST_NOT_ACCEPTED;
}

/* Close the ReactOS-style strong-unload loop after local references are released. */
static NTSTATUS
kswordArkDriverUnloadVerifyClosedLoop(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* normalizedDriverName,
    _In_ const KswDriverUnloadPreflightResult* preflight
    )
{
    ULONG attemptIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    LARGE_INTEGER delayInterval;

    // Inputs: request snapshot, normalized DriverObject name, and preflight loader evidence.
    // Processing: retry a short bounded object/loader verification window after the final
    // ObDereferenceObject, because object-manager and image-unload side effects may complete
    // just after the unload worker exits.
    // Return: STATUS_SUCCESS when both object and image are gone; otherwise the most specific
    // failure from the last verification pass.
    if (request == NULL || normalizedDriverName == NULL || preflight == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    delayInterval.QuadPart = -((LONGLONG)KSW_DRIVER_UNLOAD_POST_VERIFY_DELAY_MS * 10LL * 1000LL);
    for (attemptIndex = 0UL;
        attemptIndex < KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES;
        ++attemptIndex) {
        NTSTATUS objectStatus = kswordArkDriverUnloadVerifyDriverObjectGone(
            request,
            normalizedDriverName);
        NTSTATUS loaderStatus = STATUS_SUCCESS;

        if (NT_SUCCESS(objectStatus)) {
            loaderStatus = kswordArkDriverUnloadVerifyLoaderGone(preflight);
            if (NT_SUCCESS(loaderStatus)) {
                return STATUS_SUCCESS;
            }
            lastStatus = loaderStatus;
        }
        else {
            lastStatus = objectStatus;
        }

        if (attemptIndex + 1UL < KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES) {
            (VOID)KeDelayExecutionThread(
                KernelMode,
                FALSE,
                &delayInterval);
        }
    }

    return NT_SUCCESS(lastStatus) ? STATUS_REQUEST_NOT_ACCEPTED : lastStatus;
}

/* Note: The system thread actually invokes DriverUnload, isolating the call stack and wait timeout. */
static VOID
kswordArkDriverUnloadThreadRoutine(
    _In_opt_ PVOID startContext
    )
{
    PkswDriverUnloadContext unloadContext = (PkswDriverUnloadContext)startContext;
    NTSTATUS threadStatus = STATUS_INVALID_PARAMETER;

    if (unloadContext == NULL || unloadContext->driverObject == NULL) {
        if (unloadContext != NULL) {
            kswordArkDriverUnloadReleaseContext(unloadContext);
        }
        PsTerminateSystemThread(threadStatus);
        return;
    }

    unloadContext->unloadStatus = STATUS_SUCCESS;
    unloadContext->cleanupStatus = STATUS_SUCCESS;
    unloadContext->driverUnload = unloadContext->driverObject->DriverUnload;

    unloadContext->cleanupStatus =
        kswordArkDriverUnloadApplyPreUnloadTeardownUnsafe(unloadContext);
    if (!NT_SUCCESS(unloadContext->cleanupStatus)) {
        unloadContext->unloadStatus = unloadContext->cleanupStatus;
    }
    else if (unloadContext->attemptDirectUnload && unloadContext->driverUnload != NULL) {
        __try {
            unloadContext->driverUnload(unloadContext->driverObject);
            unloadContext->unloadStatus = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            unloadContext->unloadStatus = GetExceptionCode();
        }
        if (NT_SUCCESS(unloadContext->unloadStatus)) {
            unloadContext->cleanupStatus = kswordArkDriverUnloadApplyCleanupUnsafe(
                unloadContext,
                TRUE);
        }
    }
    else if (kswordArkDriverUnloadShouldCleanupWithoutUnload(unloadContext->flags)) {
        unloadContext->cleanupStatus = kswordArkDriverUnloadApplyCleanupUnsafe(
            unloadContext,
            FALSE);
        unloadContext->unloadStatus = STATUS_PROCEDURE_NOT_FOUND;
    }
    else {
        unloadContext->unloadStatus = STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Note: The DriverObject reference held by the thread is released here; the parent thread only releases its own reference. */
    threadStatus = unloadContext->unloadStatus;
    ObDereferenceObject(unloadContext->driverObject);
    kswordArkDriverUnloadReleaseContext(unloadContext);
    PsTerminateSystemThread(threadStatus);
}

/* Note: Start a system thread and wait for the unload result. */
static NTSTATUS
kswordArkDriverUnloadRunThread(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG flags,
    _In_ ULONG timeoutMilliseconds,
    _Out_ NTSTATUS* waitStatusOut,
    _Out_ NTSTATUS* unloadStatusOut,
    _Out_ NTSTATUS* cleanupStatusOut,
    _Out_ PDRIVER_UNLOAD* driverUnloadOut,
    _Out_ ULONG* cleanupFlagsAppliedOut,
    _Out_ ULONG* deletedDeviceCountOut,
    _Out_ ULONG* detachedDeviceCountOut,
    _Out_ ULONG* threadCandidatesOut,
    _Out_ ULONG* threadsTerminatedOut,
    _Out_ ULONG* threadFailuresOut,
    _Out_ NTSTATUS* threadLastStatusOut,
    _Out_ ULONG* callbackCandidatesOut,
    _Out_ ULONG* callbacksRemovedOut,
    _Out_ ULONG* callbackFailuresOut,
    _Out_ NTSTATUS* callbackLastStatusOut,
    _In_opt_ const KswDriverUnloadPreflightResult* preflight
    )
{
    HANDLE threadHandle = NULL;
    PETHREAD threadObject = NULL;
    LARGE_INTEGER timeoutInterval;
    PkswDriverUnloadContext unloadContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (driverObject == NULL ||
        waitStatusOut == NULL ||
        unloadStatusOut == NULL ||
        cleanupStatusOut == NULL ||
        driverUnloadOut == NULL ||
        cleanupFlagsAppliedOut == NULL ||
        deletedDeviceCountOut == NULL ||
        detachedDeviceCountOut == NULL ||
        threadCandidatesOut == NULL ||
        threadsTerminatedOut == NULL ||
        threadFailuresOut == NULL ||
        threadLastStatusOut == NULL ||
        callbackCandidatesOut == NULL ||
        callbacksRemovedOut == NULL ||
        callbackFailuresOut == NULL ||
        callbackLastStatusOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *waitStatusOut = STATUS_SUCCESS;
    *unloadStatusOut = STATUS_SUCCESS;
    *cleanupStatusOut = STATUS_SUCCESS;
    *driverUnloadOut = driverObject->DriverUnload;
    *cleanupFlagsAppliedOut = 0UL;
    *deletedDeviceCountOut = 0UL;
    *detachedDeviceCountOut = 0UL;
    *threadCandidatesOut = 0UL;
    *threadsTerminatedOut = 0UL;
    *threadFailuresOut = 0UL;
    *threadLastStatusOut = STATUS_SUCCESS;
    *callbackCandidatesOut = 0UL;
    *callbacksRemovedOut = 0UL;
    *callbackFailuresOut = 0UL;
    *callbackLastStatusOut = STATUS_SUCCESS;

#pragma warning(push)
#pragma warning(disable:4996)
    unloadContext = (PkswDriverUnloadContext)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*unloadContext),
        KSW_DRIVER_UNLOAD_TAG);
#pragma warning(pop)
    if (unloadContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Note: The unloading thread may continue running after a timeout, so the context cannot be placed on the parent thread's stack. */
    RtlZeroMemory(unloadContext, sizeof(*unloadContext));
    unloadContext->referenceCount = 2L;
    unloadContext->driverObject = driverObject;
    unloadContext->flags = flags;
    unloadContext->unloadStatus = STATUS_PENDING;
    unloadContext->cleanupStatus = STATUS_SUCCESS;
    unloadContext->driverUnload = driverObject->DriverUnload;
    unloadContext->threadLastStatus = STATUS_SUCCESS;
    unloadContext->callbackLastStatus = STATUS_SUCCESS;
    unloadContext->attemptDirectUnload =
        (preflight != NULL &&
            preflight->allowDirectUnload &&
            preflight->hasValidDynData &&
            preflight->hasPdbBackedDynData &&
            preflight->hasValidDriverObjectOffsets &&
            preflight->hasValidLoaderEvidence) ? TRUE : FALSE;
    if (preflight != NULL) {
        unloadContext->driverStart = preflight->driverStart;
        unloadContext->driverEnd = preflight->driverEnd;
        (VOID)RtlStringCchCopyW(
            unloadContext->serviceRegistryPath,
            RTL_NUMBER_OF(unloadContext->serviceRegistryPath),
            preflight->serviceRegistryPath);
    }
    ObReferenceObject(driverObject);

    if (timeoutMilliseconds == 0UL) {
        timeoutMilliseconds = KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS;
    }
    if (timeoutMilliseconds > KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS) {
        timeoutMilliseconds = KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS;
    }

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        kswordArkDriverUnloadThreadRoutine,
        unloadContext);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(driverObject);
        ExFreePoolWithTag(unloadContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        SYNCHRONIZE,
        *PsThreadType,
        KernelMode,
        (PVOID*)&threadObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        kswordArkDriverUnloadReleaseContext(unloadContext);
        return status;
    }
    timeoutInterval.QuadPart = -((LONGLONG)timeoutMilliseconds * 10LL * 1000LL);
    *waitStatusOut = KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    ObDereferenceObject(threadObject);
    ZwClose(threadHandle);

    if (*waitStatusOut != STATUS_SUCCESS) {
        kswordArkDriverUnloadReleaseContext(unloadContext);
        return *waitStatusOut;
    }

    *unloadStatusOut = unloadContext->unloadStatus;
    *cleanupStatusOut = unloadContext->cleanupStatus;
    *driverUnloadOut = unloadContext->driverUnload;
    *cleanupFlagsAppliedOut = unloadContext->cleanupFlagsApplied;
    *deletedDeviceCountOut = unloadContext->deletedDeviceCount;
    *detachedDeviceCountOut = unloadContext->detachedDeviceCount;
    *threadCandidatesOut = unloadContext->threadCandidates;
    *threadsTerminatedOut = unloadContext->threadsTerminated;
    *threadFailuresOut = unloadContext->threadFailures;
    *threadLastStatusOut = unloadContext->threadLastStatus;
    *callbackCandidatesOut = unloadContext->callbackCandidates;
    *callbacksRemovedOut = unloadContext->callbacksRemoved;
    *callbackFailuresOut = unloadContext->callbackFailures;
    *callbackLastStatusOut = unloadContext->callbackLastStatus;

    if (*driverUnloadOut == NULL &&
        unloadContext->cleanupFlagsApplied != 0UL &&
        NT_SUCCESS(*cleanupStatusOut)) {
        *unloadStatusOut = STATUS_SUCCESS;
        status = STATUS_SUCCESS;
    }
    else {
        status = !NT_SUCCESS(*cleanupStatusOut) ? *cleanupStatusOut : *unloadStatusOut;
    }

    kswordArkDriverUnloadReleaseContext(unloadContext);
    return status;
}

NTSTATUS
kswordArkDriverForceUnloadDriver(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request,
    _Out_ size_t* bytesWrittenOut,
    _Out_opt_ KswDriverUnloadDiagnostics* diagnostics
    )
/*++

Routine Description:

    Force-unload a DriverObject by name. Note: The first-priority path only calls the target.
    DriverObject->DriverUnload; if the target has no DriverUnload, clear the dispatch table only
    when explicitly requested by a flag, and do not delete DeviceObject instances proactively.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Output buffer length.
    Request - R3 request, containing the DriverObject name and flags.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; the underlying unload result is written to response->lastStatus.

--*/
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE* response = NULL;
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST requestSnapshot;
    PDRIVER_OBJECT driverObject = NULL;
    WCHAR normalizedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    KswDriverUnloadPreflightResult preflightResult;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    NTSTATUS unloadStatus = STATUS_SUCCESS;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS callbackCleanupStatus = STATUS_SUCCESS;
    PDRIVER_UNLOAD driverUnload = NULL;
    ULONG cleanupFlagsApplied = 0UL;
    ULONG deletedDeviceCount = 0UL;
    ULONG detachedDeviceCount = 0UL;
    ULONG threadCandidates = 0UL;
    ULONG threadsTerminated = 0UL;
    ULONG threadFailures = 0UL;
    NTSTATUS threadLastStatus = STATUS_SUCCESS;
    ULONG requestedFlags = 0UL;
    BOOLEAN directCallRequested = FALSE;
    BOOLEAN teardownRequested = FALSE;
    KswDriverUnloadCallbackCleanupResult callbackCleanupResult;
    KswDriverUnloadCallbackCleanupResult teardownCallbackCleanupResult;

    if (diagnostics != NULL) {
        RtlZeroMemory(diagnostics, sizeof(*diagnostics));
    }

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&callbackCleanupResult, sizeof(callbackCleanupResult));
    callbackCleanupResult.lastStatus = STATUS_SUCCESS;
    RtlZeroMemory(&teardownCallbackCleanupResult, sizeof(teardownCallbackCleanupResult));
    teardownCallbackCleanupResult.lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /*
     * Note: IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER uses METHOD_BUFFERED.
     * KMDF may cause the input request and output response to point to the same SystemBuffer.
     * The output buffer will be zeroed later, so the R3 request must be fully copied to a local stack variable first.
     */
    RtlCopyMemory(&requestSnapshot, request, sizeof(requestSnapshot));
    requestedFlags = requestSnapshot.flags;
    if (diagnostics != NULL) {
        diagnostics->requestedFlags = requestedFlags;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNKNOWN;
    response->reserved = requestedFlags;
    requestSnapshot.flags = kswordArkDriverUnloadSanitizeFlags(requestSnapshot.flags);
    if ((requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL) {
        /*
         * A strong-unload mode bit corresponds to a fixed, non-reorderable R0 flow. The caller cannot select only certain stages,
         * to avoid scenarios like 'device removed but entry points not closed' or 'unload called but threads still resident'.
         */
        requestSnapshot.flags |=
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN_STAGES;
    }
    directCallRequested =
        (requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL) != 0UL
        ? TRUE
        : FALSE;
    teardownRequested =
        (requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL
        ? TRUE
        : FALSE;
    if (diagnostics != NULL) {
        diagnostics->sanitizedFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;
    response->lastStatus = STATUS_SUCCESS;
    response->waitStatus = STATUS_SUCCESS;
    response->callbackLastStatus = STATUS_SUCCESS;

    /*
     * Note: Forceful unloading is reserved for malicious driver scenarios, but by default only DriverUnload is called.
     * Any action that persistently rewrites DriverObject, deletes DeviceObject, or removes callbacks must simultaneously
     * include ALLOW_DESTRUCTIVE_CLEANUP. The old R3 FORCE_CLEANUP flag will be downgraded to prevent leaving a partially
     * cleaned state upon failure, which would cause a bugcheck during the target driver's subsequent real unload.
     */

    status = kswordArkDriverUnloadReferenceByName(
        &requestSnapshot,
        &driverObject,
        normalizedName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
    if (diagnostics != NULL) {
        diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_REFERENCE;
        diagnostics->referenceStatus = status;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED;
        response->lastStatus = status;
        if (normalizedName[0] != L'\0') {
            /* Note: Even on failure, populate the normalized object name to facilitate R3 log verification of the actual resolved target. */
            (VOID)RtlStringCchCopyW(
                response->driverName,
                KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
                normalizedName);
        }
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload;
    RtlStringCchCopyW(
        response->driverName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        normalizedName);

    /*
     * Note: Both communication blind and the generic IRP editor retain a reference to the target object and its
     * original dispatch. Before forced unloading, RESTORE or explicitly ABANDON to avoid losing the identity needed
     * for recovery. The gate matches both the referenced object and the module base from the original request.
     */
    if (kswordArkDriverCommunicationHasBlockingRecord(
        driverObject,
        requestSnapshot.targetModuleBase) ||
        kswordArkDriverDispatchHasBlockingRecord(
            driverObject,
            requestSnapshot.targetModuleBase) ||
        kswordArkDriverImageHasBlockingRecord(
            driverObject,
            requestSnapshot.targetModuleBase)) {
        /* Note: Use the fixed operation-failed response status to carry a retryable busy reason. */
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        /* Note: lastStatus explicitly requires the caller to restore the communication entry first. */
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* Note: Sync waitStatus to busy to prevent the UI from misinterpreting the result as a timeout. */
        response->waitStatus = STATUS_DEVICE_BUSY;
        /* Note: Return a complete fixed response for R3 to display recovery suggestions. */
        *bytesWrittenOut = sizeof(*response);
        /* Note: Release the temporary object reference obtained during this force-unload resolution. */
        ObDereferenceObject(driverObject);
        /* Note: Protocol layer call succeeded; the specific rejection reason is in the response status. */
        return STATUS_SUCCESS;
    }

    status = kswordArkDriverUnloadBuildPreflightResult(
        driverObject,
        normalizedName,
        requestSnapshot.targetModuleBase,
        requestSnapshot.flags,
        &preflightResult);
    if (diagnostics != NULL) {
        diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_PREFLIGHT;
        diagnostics->preflightBuildStatus = status;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = status;
        response->waitStatus = status;
        *bytesWrittenOut = sizeof(*response);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }
    if (diagnostics != NULL) {
        kswordArkDriverUnloadCapturePreflightDiagnostics(diagnostics, &preflightResult);
    }

    if (!preflightResult.allowDirectUnload &&
        !preflightResult.allowZwUnload &&
        !preflightResult.allowDestructiveCleanup) {
        const NTSTATUS kDenyStatus = kswordArkDriverUnloadPreflightDenyStatus(&preflightResult);
        if (diagnostics != NULL) {
            diagnostics->preflightDenyStatus = kDenyStatus;
        }
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = kDenyStatus;
        response->waitStatus = kDenyStatus;
        *bytesWrittenOut = sizeof(*response);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }

    if (!preflightResult.allowDestructiveCleanup) {
        const ULONG kDestructiveMask =
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP;
        requestSnapshot.flags &= ~kDestructiveMask;
        teardownRequested = FALSE;
    }
    if (diagnostics != NULL) {
        diagnostics->finalFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;

    /*
     * Note: ZwUnloadDriver must be executed without holding a reference to the target DriverObject.
     * The reference obtained via ObReferenceObjectByName is used only for preflight; it must be released before the actual system unload.
     * If system unloading fails and preflight allows the forced path, re-reference the object to enter manual unloading.
     */
    ObDereferenceObject(driverObject);
    driverObject = NULL;

    if (preflightResult.allowZwUnload && !directCallRequested) {
        status = kswordArkDriverUnloadRunZwOnly(
            preflightResult.serviceRegistryPath,
            requestSnapshot.timeoutMilliseconds,
            &waitStatus,
            &unloadStatus);
        if (diagnostics != NULL) {
            diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW;
            diagnostics->zwRunStatus = status;
            diagnostics->zwWaitStatus = waitStatus;
            diagnostics->zwUnloadStatus = unloadStatus;
        }
        cleanupStatus = STATUS_SUCCESS;
        if (NT_SUCCESS(status)) {
            /*
             * Note: The return value of ZwUnloadDriver only indicates that the system unload path has returned normally; it cannot
             * independently prove that the DriverObject is no longer referenceable or that the image has left the loader view.
             * Therefore, the normal path must also pass the same closed-loop verification; if verification fails and the
             * caller explicitly allows destructive fallback, proceed to direct fallback; otherwise, return the failure
             * reason to R3 to prevent the UI from displaying 'unloaded' as success when it was not truly unloaded.
             */
            NTSTATUS verifyStatus = kswordArkDriverUnloadVerifyClosedLoop(
                &requestSnapshot,
                normalizedName,
                &preflightResult);
            if (diagnostics != NULL) {
                diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW_VERIFY;
                diagnostics->zwVerifyStatus = verifyStatus;
            }
            if (NT_SUCCESS(verifyStatus)) {
                response->lastStatus = status;
                response->waitStatus = waitStatus;
                response->cleanupFlagsApplied = 0UL;
                response->deletedDeviceCount = 0UL;
                response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED;
                *bytesWrittenOut = sizeof(*response);
                return STATUS_SUCCESS;
            }
            status = verifyStatus;
        }
        if (NT_SUCCESS(status) ||
            !kswordArkDriverUnloadCanUseDestructiveFallback(&preflightResult, requestSnapshot.flags)) {
            const NTSTATUS kReportStatus = NT_SUCCESS(status)
                ? kswordArkDriverUnloadPreflightDenyStatus(&preflightResult)
                : status;
            if (diagnostics != NULL && diagnostics->preflightDenyStatus == STATUS_SUCCESS) {
                diagnostics->preflightDenyStatus = NT_SUCCESS(status)
                    ? kReportStatus
                    : kswordArkDriverUnloadPreflightDenyStatus(&preflightResult);
            }
            response->lastStatus = kReportStatus;
            response->waitStatus = waitStatus;
            response->cleanupFlagsApplied = 0UL;
            response->deletedDeviceCount = 0UL;
            response->status = (kReportStatus == STATUS_TIMEOUT || waitStatus == STATUS_TIMEOUT)
                ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT
                : KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
            *bytesWrittenOut = sizeof(*response);
            return STATUS_SUCCESS;
        }
    }

    if ((kswordArkDriverUnloadHasCleanupRequest(requestSnapshot.flags) &&
            !kswordArkDriverUnloadCanUseDestructiveFallback(
                &preflightResult,
                requestSnapshot.flags)) ||
        (!kswordArkDriverUnloadHasCleanupRequest(requestSnapshot.flags) &&
            (!directCallRequested || !preflightResult.allowDirectUnload))) {
        const NTSTATUS kDenyStatus = kswordArkDriverUnloadPreflightDenyStatus(&preflightResult);
        if (diagnostics != NULL) {
            diagnostics->preflightDenyStatus = kDenyStatus;
        }
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = kDenyStatus;
        response->waitStatus = kDenyStatus;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    /*
     * Note: ReactOS/I/O Manager unload model is not 'only call DriverUnload'.
     * Direct fallback only enters the object deletion and image unloading loop after DriverUnload clears
     * the device chain, marks the DriverObject as temporary, and releases the last reference held by
     * this driver. Thus, upon entering forced fallback, R0 automatically sets MAKE_TEMPORARY_OBJECT.
     */
    if (kswordArkDriverUnloadHasCleanupRequest(requestSnapshot.flags)) {
        requestSnapshot.flags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT;
    }
    if ((requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) != 0UL &&
        requestSnapshot.targetModuleBase == 0ULL &&
        preflightResult.driverStart != 0ULL) {
        /*
         * Note: When initiating unloading by DriverObject name from R3, the module base address may not be provided.
         * Preflight has already confirmed DriverStart using DriverObject/loader evidence; thus, this step uses the trusted
         * DriverStart as the internal callback cleanup target to avoid requiring the user-mode caller to retransmit the address.
         */
        requestSnapshot.targetModuleBase = preflightResult.driverStart;
        requestSnapshot.flags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT;
    }
    if (diagnostics != NULL) {
        diagnostics->finalFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;

    status = kswordArkDriverUnloadReferenceByName(
        &requestSnapshot,
        &driverObject,
        normalizedName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
    if (diagnostics != NULL) {
        diagnostics->referenceStatus = status;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED;
        response->lastStatus = status;
        response->waitStatus = waitStatus;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload;

    if (!teardownRequested &&
        kswordArkDriverUnloadCanPreCleanupCallbacks(&preflightResult, &requestSnapshot)) {
        callbackCleanupStatus = kswordArkDriverUnloadRemoveCallbacksByModuleBase(
            requestSnapshot.targetModuleBase,
            &callbackCleanupResult);
        response->callbackCandidates = callbackCleanupResult.candidates;
        response->callbacksRemoved = callbackCleanupResult.removed;
        response->callbackFailures = callbackCleanupResult.failures;
        response->callbackLastStatus = callbackCleanupResult.lastStatus;
        if (!NT_SUCCESS(callbackCleanupStatus) &&
            response->callbackLastStatus == STATUS_SUCCESS) {
            response->callbackLastStatus = callbackCleanupStatus;
        }
    }

    status = kswordArkDriverUnloadRunThread(
        driverObject,
        requestSnapshot.flags,
        requestSnapshot.timeoutMilliseconds,
        &waitStatus,
        &unloadStatus,
        &cleanupStatus,
        &driverUnload,
        &cleanupFlagsApplied,
        &deletedDeviceCount,
        &detachedDeviceCount,
        &threadCandidates,
        &threadsTerminated,
        &threadFailures,
        &threadLastStatus,
        &teardownCallbackCleanupResult.candidates,
        &teardownCallbackCleanupResult.removed,
        &teardownCallbackCleanupResult.failures,
        &teardownCallbackCleanupResult.lastStatus,
        &preflightResult);
    if (diagnostics != NULL) {
        diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT;
        diagnostics->directRunStatus = status;
        diagnostics->directWaitStatus = waitStatus;
        diagnostics->directUnloadStatus = unloadStatus;
        diagnostics->directCleanupStatus = cleanupStatus;
    }

    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverUnload;
    response->lastStatus = status;
    response->waitStatus = waitStatus;
    response->cleanupFlagsApplied = cleanupFlagsApplied;
    response->deletedDeviceCount = deletedDeviceCount;
    response->detachedDeviceCount = detachedDeviceCount;
    response->threadCandidates = threadCandidates;
    response->threadsTerminated = threadsTerminated;
    response->threadFailures = threadFailures;
    response->threadLastStatus = threadLastStatus;
    if (teardownRequested) {
        callbackCleanupResult = teardownCallbackCleanupResult;
    }
    response->callbackCandidates = callbackCleanupResult.candidates;
    response->callbacksRemoved = callbackCleanupResult.removed;
    response->callbackFailures = callbackCleanupResult.failures;
    response->callbackLastStatus = callbackCleanupResult.lastStatus;

    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
        driverObject = NULL;
    }
    if (NT_SUCCESS(status) &&
        NT_SUCCESS(cleanupStatus) &&
        cleanupFlagsApplied != 0UL &&
        (cleanupFlagsApplied & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        NTSTATUS verifyStatus = kswordArkDriverUnloadVerifyClosedLoop(
            &requestSnapshot,
            normalizedName,
            &preflightResult);
        if (diagnostics != NULL) {
            diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT_VERIFY;
            diagnostics->directVerifyStatus = verifyStatus;
        }
        if (!NT_SUCCESS(verifyStatus)) {
            status = verifyStatus;
            cleanupStatus = verifyStatus;
            response->lastStatus = verifyStatus;
        }
    }

    if (status == STATUS_TIMEOUT || waitStatus == STATUS_TIMEOUT) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT;
    }
    else if (!NT_SUCCESS(cleanupStatus)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_CLEANUP_FAILED;
    }
    else if (driverUnload == NULL && unloadStatus == STATUS_PROCEDURE_NOT_FOUND) {
        response->status = NT_SUCCESS(cleanupStatus) &&
            kswordArkDriverUnloadHasCleanupRequest(requestSnapshot.flags)
            ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP
            : KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_MISSING;
    }
    else if (NT_SUCCESS(status)) {
        response->status = teardownRequested
            ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP
            : (directCallRequested
                ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_CALLED
                : KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED);
    }
    else {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
    }

    if (diagnostics != NULL && diagnostics->finalFlags == 0UL) {
        diagnostics->finalFlags = requestSnapshot.flags;
    }
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
