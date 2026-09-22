/*++

Module Name:

    driver_object_query.c

Abstract:

    Phase-9 DriverObject / DeviceObject diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

#define KSW_DRIVER_OBJECT_QUERY_TAG 'oDsK'

// ObReferenceObjectByName is a commonly used but undocumented kernel entry point for referencing named objects:
// - System Informer's KphOpenDriver ultimately performs reference counting and opening operations around the DriverObject type.
// - Here, only the name reference is used; arbitrary kernel addresses are not allowed to be passed by users.
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

typedef struct KswSystemModuleEntry
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
} KswSystemModuleEntry, *PkswSystemModuleEntry;

typedef struct KswSystemModuleInformation
{
    ULONG numberOfModules;
    KswSystemModuleEntry modules[1];
} KswSystemModuleInformation, *PkswSystemModuleInformation;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

static PVOID
kswordArkDriverObjectAllocate(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate transient nonpaged memory for module snapshots.

Arguments:

    BufferBytes - Number of bytes to allocate.

Return Value:

    Allocation pointer or NULL.

--*/
{
    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_DRIVER_OBJECT_QUERY_TAG);
#pragma warning(pop)
}

static VOID
kswordArkCopyUnicodeStringToFixed(
    _In_opt_ PCUNICODE_STRING sourceString,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Copy a UNICODE_STRING into a fixed WCHAR buffer with guaranteed NUL.

Arguments:

    SourceString - Source text, may be NULL.
    DestinationText - Fixed output buffer.
    DestinationChars - Output character capacity.

Return Value:

    None.

--*/
{
    ULONG copyChars = 0UL;

    if (destinationText == NULL || destinationChars == 0UL) {
        return;
    }

    destinationText[0] = L'\0';
    if (sourceString == NULL || sourceString->Buffer == NULL || sourceString->Length == 0) {
        return;
    }

    copyChars = (ULONG)(sourceString->Length / sizeof(WCHAR));
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
    }

    RtlCopyMemory(destinationText, sourceString->Buffer, copyChars * sizeof(WCHAR));
    destinationText[copyChars] = L'\0';
}

static VOID
kswordArkCopyBoundedAnsiToWide(
    _In_reads_bytes_(sourceBytes) const UCHAR* sourceText,
    _In_ ULONG sourceBytes,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Copy an ANSI module filename to a fixed WCHAR buffer.

Arguments:

    sourceText - Bounded ANSI text.
    SourceBytes - Maximum readable bytes.
    DestinationText - Wide output buffer.
    DestinationChars - Output character capacity.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (destinationText == NULL || destinationChars == 0UL) {
        return;
    }

    destinationText[0] = L'\0';
    if (sourceText == NULL || sourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < destinationChars && index < sourceBytes; ++index) {
        if (sourceText[index] == '\0') {
            break;
        }
        destinationText[index] = (WCHAR)sourceText[index];
    }
    destinationText[index] = L'\0';
}

static NTSTATUS
kswordArkBuildSystemModuleSnapshot(
    _Outptr_result_bytebuffer_(*bufferBytesOut) KswSystemModuleInformation** moduleInfoOut,
    _Out_ ULONG* bufferBytesOut
    )
/*++

Routine Description:

    Query SystemModuleInformation for dispatch address ownership checks.

Arguments:

    ModuleInfoOut - Receives allocated module information.
    BufferBytesOut - Receives allocated byte count.

Return Value:

    STATUS_SUCCESS or query/allocation failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    KswSystemModuleInformation* moduleInfo = NULL;

    if (moduleInfoOut == NULL || bufferBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *moduleInfoOut = NULL;
    *bufferBytesOut = 0UL;

    status = ZwQuerySystemInformation(11UL, NULL, 0UL, &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    moduleInfo = (KswSystemModuleInformation*)kswordArkDriverObjectAllocate(requiredBytes);
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(11UL, moduleInfo, requiredBytes, &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_OBJECT_QUERY_TAG);
        return status;
    }

    *moduleInfoOut = moduleInfo;
    *bufferBytesOut = requiredBytes;
    return STATUS_SUCCESS;
}

static VOID
kswordArkResolveModuleForAddress(
    _In_opt_ const KswSystemModuleInformation* moduleInfo,
    _In_ PVOID address,
    _Out_ ULONGLONG* moduleBaseOut,
    _Out_writes_(moduleNameChars) PWCHAR moduleNameOut,
    _In_ ULONG moduleNameChars
    )
/*++

Routine Description:

    Resolve a kernel address to the loaded module that owns it.

Arguments:

    ModuleInfo - Optional system module snapshot.
    Address - Address being classified.
    ModuleBaseOut - Receives owning module base when found.
    ModuleNameOut - Receives module filename when found.
    ModuleNameChars - ModuleNameOut capacity.

Return Value:

    None.

--*/
{
    ULONG moduleIndex = 0UL;
    ULONG_PTR addressValue = (ULONG_PTR)address;

    if (moduleBaseOut != NULL) {
        *moduleBaseOut = 0ULL;
    }
    if (moduleNameOut != NULL && moduleNameChars != 0UL) {
        moduleNameOut[0] = L'\0';
    }
    if (moduleInfo == NULL || address == NULL) {
        return;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const ULONG_PTR kImageBase = (ULONG_PTR)moduleEntry->imageBase;
        const ULONG_PTR kImageEnd = kImageBase + (ULONG_PTR)moduleEntry->imageSize;
        const UCHAR* fileName = moduleEntry->fullPathName;
        ULONG fileNameBytes = (ULONG)sizeof(moduleEntry->fullPathName);

        if (addressValue < kImageBase || addressValue >= kImageEnd) {
            continue;
        }

        if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
            fileName = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
            fileNameBytes = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
        }

        if (moduleBaseOut != NULL) {
            *moduleBaseOut = (ULONGLONG)kImageBase;
        }
        kswordArkCopyBoundedAnsiToWide(fileName, fileNameBytes, moduleNameOut, moduleNameChars);
        return;
    }
}

static VOID
kswordArkFillMajorFunctionRows(
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ const KswSystemModuleInformation* moduleInfo,
    _Inout_ KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE* response
    )
/*++

Routine Description:

    Copy the driver dispatch table and classify each dispatch address.

Arguments:

    DriverObject - Referenced driver object.
    ModuleInfo - Optional module snapshot.
    Response - Response header being filled.

Return Value:

    None.

--*/
{
    ULONG majorIndex = 0UL;

    if (driverObject == NULL || response == NULL) {
        return;
    }

    response->majorFunctionCount = KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT;
    for (majorIndex = 0UL; majorIndex < KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT; ++majorIndex) {
        KSWORD_ARK_DRIVER_MAJOR_FUNCTION_ENTRY* row = &response->majorFunctions[majorIndex];
        PVOID dispatchAddress = NULL;

        RtlZeroMemory(row, sizeof(*row));
        row->majorFunction = majorIndex;
        dispatchAddress = (PVOID)driverObject->MajorFunction[majorIndex];
        row->dispatchAddress = (ULONGLONG)(ULONG_PTR)dispatchAddress;
        kswordArkResolveModuleForAddress(
            moduleInfo,
            dispatchAddress,
            &row->moduleBase,
            row->moduleName,
            KSWORD_ARK_DRIVER_MODULE_NAME_CHARS);
        if (row->moduleBase != 0ULL) {
            row->flags |= 0x00000001UL;
        }
        if ((ULONG_PTR)dispatchAddress >= (ULONG_PTR)driverObject->DriverStart &&
            (ULONG_PTR)dispatchAddress < ((ULONG_PTR)driverObject->DriverStart + (ULONG_PTR)driverObject->DriverSize)) {
            row->flags |= 0x00000002UL;
        }
    }

    response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_MAJOR_PRESENT;
}

static NTSTATUS
kswordArkQueryObjectNameToFixed(
    _In_ PVOID object,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Query a kernel object's name into a fixed WCHAR buffer.

Arguments:

    Object - Referenced object pointer.
    DestinationText - Fixed output text.
    DestinationChars - Output character capacity.

Return Value:

    STATUS_SUCCESS when a name was copied; otherwise query/allocation failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    if (destinationText == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destinationText[0] = L'\0';
    if (object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObQueryNameString(object, NULL, 0UL, &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_NOT_FOUND : status;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkDriverObjectAllocate(requiredBytes);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ObQueryNameString(object, nameInfo, requiredBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        kswordArkCopyUnicodeStringToFixed(&nameInfo->Name, destinationText, destinationChars);
    }

    ExFreePoolWithTag(nameInfo, KSW_DRIVER_OBJECT_QUERY_TAG);
    return status;
}

static VOID
kswordArkFillOneDeviceRow(
    _In_ PDEVICE_OBJECT rootDevice,
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ ULONG relationDepth,
    _Inout_ KSWORD_ARK_DRIVER_DEVICE_ENTRY* row
    )
/*++

Routine Description:

    Copy one DeviceObject snapshot into the shared response row.

Arguments:

    RootDevice - DeviceObject from DriverObject->DeviceObject chain.
    DeviceObject - Current device or attached device.
    RelationDepth - 0 for root/NextDevice chain; >0 for AttachedDevice chain.
    Row - Output row.

Return Value:

    None.

--*/
{
    if (row == NULL) {
        return;
    }

    RtlZeroMemory(row, sizeof(*row));
    if (deviceObject == NULL) {
        return;
    }

    row->relationDepth = relationDepth;
    row->deviceType = deviceObject->DeviceType;
    row->flags = deviceObject->Flags;
    row->characteristics = deviceObject->Characteristics;
    row->stackSize = (ULONG)(UCHAR)deviceObject->StackSize;
    row->alignmentRequirement = deviceObject->AlignmentRequirement;
    row->rootDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootDevice;
    row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject;
    row->nextDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject->NextDevice;
    row->attachedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject->AttachedDevice;
    row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject->DriverObject;
    // WDK exposes DEVICE_OBJECT.Timer; only copy the pointer snapshot, do not dereference the private IO_TIMER layout.
    // Subsequent control must re-reference the object and verify the triple identity; this snapshot cannot be treated as a stable operation handle.
    row->ioTimerAddress = (ULONGLONG)(ULONG_PTR)deviceObject->Timer;
    row->nameStatus = kswordArkQueryObjectNameToFixed(
        deviceObject,
        row->deviceName,
        KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS);
}

static VOID
kswordArkFillDeviceRows(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG maxDevices,
    _In_ ULONG maxAttachedDevices,
    _In_ BOOLEAN includeAttached,
    _Inout_ KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE* response,
    _In_ ULONG deviceCapacity
    )
/*++

Routine Description:

    enumerate DriverObject->DeviceObject and optional AttachedDevice chains.

Arguments:

    DriverObject - Referenced driver object.
    MaxDevices - User-requested root device limit.
    MaxAttachedDevices - User-requested attached-chain limit per root.
    IncludeAttached - Whether to include attached devices.
    Response - Response header and variable row array.
    DeviceCapacity - Number of rows fitting output buffer.

Return Value:

    None.

--*/
{
    PDEVICE_OBJECT rootDevice = NULL;
    ULONG rootVisited = 0UL;
    ULONG returnedRows = 0UL;

    if (driverObject == NULL || response == NULL || deviceCapacity == 0UL) {
        return;
    }

    if (maxDevices == 0UL || maxDevices > KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT) {
        maxDevices = KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT;
    }
    if (maxAttachedDevices == 0UL || maxAttachedDevices > KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT) {
        maxAttachedDevices = KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT;
    }

    rootDevice = driverObject->DeviceObject;
    while (rootDevice != NULL && rootVisited < maxDevices) {
        PDEVICE_OBJECT attachedDevice = NULL;
        ULONG attachedDepth = 0UL;

        ++response->totalDeviceCount;
        if (returnedRows < deviceCapacity) {
            kswordArkFillOneDeviceRow(
                rootDevice,
                rootDevice,
                0UL,
                &response->devices[returnedRows]);
            ++returnedRows;
        }
        else {
            response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_DEVICE_TRUNCATED;
        }

        if (includeAttached) {
            attachedDevice = rootDevice->AttachedDevice;
            while (attachedDevice != NULL && attachedDepth < maxAttachedDevices) {
                ++attachedDepth;
                ++response->totalDeviceCount;
                if (returnedRows < deviceCapacity) {
                    kswordArkFillOneDeviceRow(
                        rootDevice,
                        attachedDevice,
                        attachedDepth,
                        &response->devices[returnedRows]);
                    ++returnedRows;
                }
                else {
                    response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_DEVICE_TRUNCATED;
                    break;
                }
                attachedDevice = attachedDevice->AttachedDevice;
            }
            if (attachedDevice != NULL) {
                response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_ATTACHED_TRUNCATED;
            }
        }

        ++rootVisited;
        rootDevice = rootDevice->NextDevice;
    }

    if (rootDevice != NULL) {
        response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_DEVICE_TRUNCATED;
    }
    if (response->totalDeviceCount != 0UL) {
        response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_DEVICE_PRESENT;
    }
    response->returnedDeviceCount = returnedRows;
}

// Check if the object path has the specified prefix. Note: Only handles ASCII case sensitivity, which is sufficient to cover NT object directory names.
static BOOLEAN
kswordArkDriverObjectNameHasPrefix(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* objectName,
    _In_z_ const WCHAR* prefix
    )
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

// Extract the last level of the object path. Note: \FileSystem\Filters\X extracts X.
static NTSTATUS
kswordArkDriverObjectExtractLeafName(
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

// Construct the first candidate object path. Note: Full paths are kept as-is; bare names default to \Driver\.
static NTSTATUS
kswordArkDriverObjectBuildObjectName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* sourceName,
    _Out_writes_(destinationChars) PWCHAR destinationName,
    _In_ ULONG destinationChars
    )
{
    ULONG inputChars = 0UL;

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
        return RtlStringCchCopyNW(
            destinationName,
            destinationChars,
            sourceName,
            inputChars);
    }

    return RtlStringCchPrintfW(
        destinationName,
        destinationChars,
        L"\\Driver\\%ws",
        sourceName);
}

// Reference a single complete DriverObject path. Note: On success, the caller is responsible for calling ObDereferenceObject.
static NTSTATUS
kswordArkDriverObjectReferenceCandidateName(
    _In_z_ const WCHAR* candidateName,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )
{
    UNICODE_STRING objectName;
    NTSTATUS status = STATUS_SUCCESS;

    if (candidateName == NULL || driverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;
    RtlInitUnicodeString(&objectName, candidateName);
    // ObReferenceObjectByName returns an object reference, not a handle. Note: OBJ_KERNEL_HANDLE cannot be used
    // here, as it would pass handle attributes to the object name resolution path and trigger a parameter error.
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

// Determine whether to continue attempting other directories. Note: Parameter or permission errors should not be masked by fallback.
static BOOLEAN
kswordArkDriverObjectShouldTryAlternateName(
    _In_ NTSTATUS status
    )
{
    return (status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_NOT_FOUND) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkReferenceDriverObjectByRequestName(
    _In_ const KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )
/*++

Routine Description:

    Validate and reference a DriverObject by its object namespace name.

Arguments:

    Request - User request containing \Driver\xxx or xxx.
    DriverObjectOut - Receives referenced driver object.

Return Value:

    STATUS_SUCCESS or validation/reference failure.

--*/
{
    WCHAR firstCandidate[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR leafName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR alternateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || driverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *driverObjectOut = NULL;

    status = kswordArkDriverObjectBuildObjectName(
        request->driverName,
        firstCandidate,
        RTL_NUMBER_OF(firstCandidate));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverObjectReferenceCandidateName(firstCandidate, driverObjectOut);
    if (NT_SUCCESS(status) || !kswordArkDriverObjectShouldTryAlternateName(status)) {
        return status;
    }

    /*
     * Note: Keep this consistent with the forced-unload path. Many filesystem/filter driver objects reside under
     * \FileSystem or \FileSystem\Filters; simply constructing \Driver\Name from the service name is insufficient.
     */
    if (!NT_SUCCESS(kswordArkDriverObjectExtractLeafName(
        firstCandidate,
        leafName,
        RTL_NUMBER_OF(leafName)))) {
        return status;
    }

    if (!kswordArkDriverObjectNameHasPrefix(firstCandidate, L"\\FileSystem\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverObjectReferenceCandidateName(
                alternateName,
                driverObjectOut);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverObjectShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!kswordArkDriverObjectNameHasPrefix(firstCandidate, L"\\FileSystem\\Filters\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\Filters\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverObjectReferenceCandidateName(
                alternateName,
                driverObjectOut);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverObjectShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!kswordArkDriverObjectNameHasPrefix(firstCandidate, L"\\Driver\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\Driver\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = kswordArkDriverObjectReferenceCandidateName(
                alternateName,
                driverObjectOut);
            if (NT_SUCCESS(alternateStatus) ||
                !kswordArkDriverObjectShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    return status;
}

NTSTATUS
kswordArkDriverQueryDriverObject(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query a DriverObject by name and return DriverObject, dispatch table and
    DeviceObject chain diagnostics.

Arguments:

    outputBuffer - Shared response buffer.
    outputBufferLength - Output byte capacity.
    request - Validated R3 request.
    bytesWrittenOut - Receives bytes populated.

Return Value:

    STATUS_SUCCESS for valid response packets, or NTSTATUS for IO/buffer errors.

--*/
{
    const size_t kResponseHeaderSize =
        sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
    KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE* response = NULL;
    KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST requestSnapshot;
    PDRIVER_OBJECT driverObject = NULL;
    KswSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG deviceCapacity = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN includeMajor = FALSE;
    BOOLEAN includeDevices = FALSE;
    BOOLEAN includeNames = FALSE;
    BOOLEAN includeAttached = FALSE;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0;
    if (outputBufferLength < kResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /*
     * Note: This IOCTL uses METHOD_BUFFERED, where input and output may share the same SystemBuffer;
     * copy the request before zeroing the response to prevent driverName from being erased.
     * STATUS_INVALID_PARAMETER。
     */
    RtlCopyMemory(&requestSnapshot, request, sizeof(requestSnapshot));

    response = (KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*)outputBuffer;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response->version = KSWORD_ARK_DRIVER_OBJECT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_UNAVAILABLE;
    response->deviceEntrySize = sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
    response->lastStatus = STATUS_SUCCESS;

    deviceCapacity = (ULONG)((outputBufferLength - kResponseHeaderSize) / sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY));
    includeMajor = ((requestSnapshot.flags & KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_MAJOR_FUNCTIONS) != 0UL) ? TRUE : FALSE;
    includeDevices = ((requestSnapshot.flags & KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_DEVICES) != 0UL) ? TRUE : FALSE;
    includeNames = ((requestSnapshot.flags & KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_NAMES) != 0UL) ? TRUE : FALSE;
    includeAttached = ((requestSnapshot.flags & KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ATTACHED) != 0UL) ? TRUE : FALSE;

    status = kswordArkReferenceDriverObjectByRequestName(&requestSnapshot, &driverObject);
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus =
            (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_TYPE_MISMATCH)
            ? KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND
            : KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED;
        *bytesWrittenOut = kResponseHeaderSize;
        return STATUS_SUCCESS;
    }

    response->queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK;
    response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_BASIC_PRESENT;
    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->driverFlags = driverObject->Flags;
    response->driverStart = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
    response->driverSize = driverObject->DriverSize;
    response->driverSection = (ULONGLONG)(ULONG_PTR)driverObject->DriverSection;
    response->driverUnload = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload;
    kswordArkCopyUnicodeStringToFixed(
        &driverObject->DriverName,
        response->driverName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
    response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_DRIVER_NAME_PRESENT;

    if (driverObject->DriverExtension != NULL) {
        kswordArkCopyUnicodeStringToFixed(
            &driverObject->DriverExtension->ServiceKeyName,
            response->serviceKeyName,
            KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS);
        if (response->serviceKeyName[0] != L'\0') {
            response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_SERVICE_KEY_PRESENT;
        }
    }

    if (includeNames) {
        UNICODE_STRING imagePath;
        RtlZeroMemory(&imagePath, sizeof(imagePath));
        status = IoQueryFullDriverPath(driverObject, &imagePath);
        if (NT_SUCCESS(status)) {
            kswordArkCopyUnicodeStringToFixed(
                &imagePath,
                response->imagePath,
                KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS);
            if (response->imagePath[0] != L'\0') {
                response->fieldFlags |= KSWORD_ARK_DRIVER_OBJECT_FIELD_IMAGE_PATH_PRESENT;
            }
            ExFreePool(imagePath.Buffer);
        }
        else if (response->queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK) {
            response->queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL;
            response->lastStatus = status;
        }
    }

    status = kswordArkBuildSystemModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        moduleInfo = NULL;
    }

    if (includeMajor) {
        kswordArkFillMajorFunctionRows(driverObject, moduleInfo, response);
    }
    if (includeDevices) {
        kswordArkFillDeviceRows(
            driverObject,
            requestSnapshot.maxDevices,
            requestSnapshot.maxAttachedDevices,
            includeAttached,
            response,
            deviceCapacity);
        if ((response->fieldFlags & (KSWORD_ARK_DRIVER_OBJECT_FIELD_DEVICE_TRUNCATED | KSWORD_ARK_DRIVER_OBJECT_FIELD_ATTACHED_TRUNCATED)) != 0UL) {
            response->queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL;
        }
    }

    *bytesWrittenOut = kResponseHeaderSize +
        ((size_t)response->returnedDeviceCount * sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY));

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_OBJECT_QUERY_TAG);
    }
    ObDereferenceObject(driverObject);
    return STATUS_SUCCESS;
}
