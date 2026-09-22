/*++

Module Name:

    i8042_audit.c

Abstract:

    i8042prt specialized read-only audit. All versions use the I/O manager's public interface to enumerate device objects;
    Only read the endpoint pointer in the device extension when
    all known PE/RSDS/opcode/DriverObject descriptors match.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkI8042AuditIoctl.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntimage.h>
#include <ntstrsafe.h>

// These exported I/O-manager routines are declared by ntifs.h but not by
// ntddk.h in WDK 10.0.26100.  Keep this driver translation unit on ntddk.h and
// provide the matching public prototypes locally.
NTKERNELAPI
NTSTATUS
IoEnumerateDeviceObjectList(
    _In_ PDRIVER_OBJECT driverObject,
    _Out_writes_bytes_to_opt_(
        DeviceObjectListSize,
        (*ActualNumberDeviceObjects) * sizeof(PDEVICE_OBJECT))
        PDEVICE_OBJECT* deviceObjectList,
    _In_ ULONG deviceObjectListSize,
    _Out_ PULONG actualNumberDeviceObjects
    );

NTKERNELAPI
PDEVICE_OBJECT
IoGetLowerDeviceObject(
    _In_ PDEVICE_OBJECT deviceObject
    );

NTKERNELAPI
PDEVICE_OBJECT
IoGetDeviceAttachmentBaseRef(
    _In_ PDEVICE_OBJECT deviceObject
    );

#define KSW_I8042_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE, entries))
#define KSW_I8042_POOL_TAG '24iK'
#define KSW_I8042_DEVICE_LIMIT 64UL
#define KSW_I8042_DEVICE_ENUM_RETRIES 2UL
#define KSW_I8042_STACK_DEPTH_LIMIT 32UL
#define KSW_I8042_RSDS_SIGNATURE 0x53445352UL

#define KSW_I8042_EXPECTED_TIME_DATE_STAMP 0xFD7548DDUL
#define KSW_I8042_EXPECTED_IMAGE_SIZE      0x00026000UL
#define KSW_I8042_EXPECTED_CHECKSUM        0x0002637EUL
#define KSW_I8042_EXPECTED_PDB_AGE         1UL
#define KSW_I8042_EXPECTED_INTERNAL_DISPATCH_RVA 0x00007190UL
#define KSW_I8042_EXPECTED_ADD_DEVICE_RVA       0x0001B6F0UL
#define KSW_I8042_EXPECTED_EXTENSION_SIZE        0x00000458UL

#define KSW_I8042_OFFSET_CLASS_DEVICE_OBJECT 0x1B0UL
#define KSW_I8042_OFFSET_CLASS_SERVICE       0x1B8UL
#define KSW_I8042_OFFSET_KEYBOARD_INIT       0x398UL
#define KSW_I8042_OFFSET_KEYBOARD_ISR        0x3A0UL
#define KSW_I8042_OFFSET_KEYBOARD_CONTEXT    0x3A8UL
#define KSW_I8042_OFFSET_MOUSE_ISR           0x428UL
#define KSW_I8042_OFFSET_MOUSE_CONTEXT       0x430UL

typedef struct KswI8042RsdsHeader
{
    ULONG signature;
    GUID guid;
    ULONG age;
} KswI8042RsdsHeader;

typedef struct KswI8042OpcodeDescriptor
{
    ULONG rva;
    ULONG length;
    UCHAR bytes[48];
} KswI8042OpcodeDescriptor;

typedef struct KswI8042EndpointValues
{
    PVOID classDeviceObject;
    PVOID classService;
    PVOID initializationRoutine;
    PVOID isrRoutine;
    PVOID context;
} KswI8042EndpointValues;

static const GUID kGKswI8042ExpectedPdbGuid = {
    0xEC704C63UL,
    0x3F2FU,
    0xA4E7U,
    { 0xBEU, 0xF7U, 0x86U, 0xF7U, 0x55U, 0xDCU, 0xB5U, 0x2CU }
};

// Corresponding disk file SHA256:
// 6BF208FF2A08DFAEA0FDEE5890FB6D96920052D00235DBE7C95212AD37D76166。
// R0 does not hash the relocated memory image as a file; instead, it
// validates the PE/RSDS of the same file against five precise opcode windows.
static const KswI8042OpcodeDescriptor kGKswI8042OpcodeDescriptors[] = {
    {
        0x0000758BUL,
        10UL,
        { 0x0FU, 0x10U, 0x00U, 0x0FU, 0x11U, 0x87U, 0xB0U, 0x01U, 0x00U, 0x00U }
    },
    {
        0x00007840UL,
        10UL,
        { 0x0FU, 0x10U, 0x00U, 0x0FU, 0x11U, 0x87U, 0xB0U, 0x01U, 0x00U, 0x00U }
    },
    {
        0x0000768CUL,
        46UL,
        {
            0x48U, 0x8BU, 0x4EU, 0x20U, 0x48U, 0x8BU, 0x01U,
            0x48U, 0x89U, 0x87U, 0xA8U, 0x03U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x08U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0x98U, 0x03U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x10U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0xA0U, 0x03U, 0x00U, 0x00U
        }
    },
    {
        0x000079E3UL,
        30UL,
        {
            0x48U, 0x8BU, 0x4EU, 0x20U, 0x48U, 0x8BU, 0x01U,
            0x48U, 0x89U, 0x87U, 0x30U, 0x04U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x08U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0x28U, 0x04U, 0x00U, 0x00U
        }
    },
    {
        0x0001B761UL,
        31UL,
        {
            0xBFU, 0x58U, 0x04U, 0x00U, 0x00U,
            0x48U, 0x89U, 0x44U, 0x24U, 0x30U,
            0x41U, 0xB9U, 0x27U, 0x00U, 0x00U, 0x00U,
            0x44U, 0x88U, 0x7CU, 0x24U, 0x28U,
            0x45U, 0x33U, 0xC0U, 0x8BU, 0xD7U,
            0x44U, 0x89U, 0x7CU, 0x24U, 0x20U
        }
    }
};

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

static VOID
kswI8042CopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source != NULL) {
        (VOID)RtlStringCchCopyNW(
            destination,
            destinationChars,
            source,
            destinationChars - 1UL);
    }
}

static BOOLEAN
kswI8042ModuleNameEquals(
    _In_opt_ const KswHookSystemModuleEntry* module,
    _In_z_ PCSTR expectedName
    )
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (module == NULL || expectedName == NULL) {
        return FALSE;
    }
    kswordArkHookGetModuleFileName(module, &fileName, &fileNameBytes);
    return kswordArkHookBoundedAnsiEqualsInsensitive(
        fileName,
        fileNameBytes,
        expectedName);
}

static const KswHookSystemModuleEntry*
kswI8042FindUniqueModule(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCSTR expectedName
    )
{
    const KswHookSystemModuleEntry* result = NULL;
    ULONG index = 0UL;
    ULONG matches = 0UL;

    if (moduleInfo == NULL || expectedName == NULL) {
        return NULL;
    }
    for (index = 0UL; index < moduleInfo->numberOfModules; ++index) {
        const KswHookSystemModuleEntry* module = &moduleInfo->modules[index];
        if (!kswI8042ModuleNameEquals(module, expectedName)) {
            continue;
        }
        result = module;
        matches += 1UL;
    }
    return matches == 1UL ? result : NULL;
}

static BOOLEAN
kswI8042AddressExecutable(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ ULONG_PTR address
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG index = 0UL;

    if (module == NULL ||
        address < (ULONG_PTR)module->imageBase ||
        address >= ((ULONG_PTR)module->imageBase + module->imageSize) ||
        !kswordArkHookReadImageBytes(module, 0UL, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !kswordArkHookReadImageNtHeaders(module, &ntHeaders)) {
        return FALSE;
    }
    sectionTableRva =
        (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (index = 0UL; index < ntHeaders.FileHeader.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section;
        ULONG sectionRva = sectionTableRva +
            (index * (ULONG)sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR start = 0U;
        ULONG_PTR end = 0U;

        RtlZeroMemory(&section, sizeof(section));
        if (!kswordArkHookReadImageBytes(
                module,
                sectionRva,
                &section,
                sizeof(section))) {
            return FALSE;
        }
        span = section.Misc.VirtualSize;
        if (span < section.SizeOfRawData) {
            span = section.SizeOfRawData;
        }
        if (span == 0UL ||
            !kswordArkHookValidateRvaRange(
                section.VirtualAddress,
                span,
                module->imageSize)) {
            continue;
        }
        start = (ULONG_PTR)module->imageBase + section.VirtualAddress;
        end = start + span;
        if (address >= start && address < end) {
            return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        }
    }
    return FALSE;
}

static BOOLEAN
kswI8042ValidateRsds(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ const IMAGE_NT_HEADERS* ntHeaders,
    _Out_ GUID* guidOut,
    _Out_ ULONG* ageOut
    )
{
    IMAGE_DATA_DIRECTORY directory;
    ULONG entryCount = 0UL;
    ULONG index = 0UL;
    ULONG rsdsCount = 0UL;
    ULONG matchingCount = 0UL;
    GUID observedGuid;
    ULONG observedAge = 0UL;
    GUID matchingGuid;
    ULONG matchingAge = 0UL;

    if (module == NULL || ntHeaders == NULL || guidOut == NULL || ageOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&directory, sizeof(directory));
    RtlZeroMemory(&observedGuid, sizeof(observedGuid));
    RtlZeroMemory(&matchingGuid, sizeof(matchingGuid));
    RtlZeroMemory(guidOut, sizeof(*guidOut));
    *ageOut = 0UL;
    if (!kswordArkHookGetDataDirectory(
            ntHeaders,
            IMAGE_DIRECTORY_ENTRY_DEBUG,
            &directory) ||
        directory.VirtualAddress == 0UL ||
        directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        (directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0UL ||
        !kswordArkHookValidateRvaRange(
            directory.VirtualAddress,
            directory.Size,
            module->imageSize)) {
        return FALSE;
    }
    entryCount = directory.Size / (ULONG)sizeof(IMAGE_DEBUG_DIRECTORY);
    if (entryCount == 0UL || entryCount > 32UL) {
        return FALSE;
    }

    for (index = 0UL; index < entryCount; ++index) {
        IMAGE_DEBUG_DIRECTORY debugEntry;
        KswI8042RsdsHeader rsds;
        ULONG entryRva = directory.VirtualAddress +
            (index * (ULONG)sizeof(IMAGE_DEBUG_DIRECTORY));

        RtlZeroMemory(&debugEntry, sizeof(debugEntry));
        RtlZeroMemory(&rsds, sizeof(rsds));
        if (!kswordArkHookReadImageBytes(
                module,
                entryRva,
                &debugEntry,
                sizeof(debugEntry)) ||
            debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            debugEntry.AddressOfRawData == 0UL ||
            debugEntry.SizeOfData < sizeof(rsds) ||
            !kswordArkHookReadImageBytes(
                module,
                debugEntry.AddressOfRawData,
                &rsds,
                sizeof(rsds)) ||
            rsds.signature != KSW_I8042_RSDS_SIGNATURE) {
            continue;
        }
        rsdsCount += 1UL;
        observedGuid = rsds.guid;
        observedAge = rsds.age;
        if (RtlCompareMemory(
                &rsds.guid,
                &kGKswI8042ExpectedPdbGuid,
                sizeof(GUID)) == sizeof(GUID) &&
            rsds.age == KSW_I8042_EXPECTED_PDB_AGE) {
            matchingGuid = rsds.guid;
            matchingAge = rsds.age;
            matchingCount += 1UL;
        }
    }
    if (rsdsCount == 1UL) {
        *guidOut = observedGuid;
        *ageOut = observedAge;
    }
    if (rsdsCount != 1UL || matchingCount != 1UL) {
        return FALSE;
    }
    *guidOut = matchingGuid;
    *ageOut = matchingAge;
    return TRUE;
}

static NTSTATUS
kswI8042ValidateImage(
    _In_ const KswHookSystemModuleEntry* module,
    _Out_ IMAGE_NT_HEADERS* ntHeadersOut,
    _Out_ GUID* pdbGuidOut,
    _Out_ ULONG* pdbAgeOut,
    _Out_ ULONG* failedOpcodeRvaOut
    )
{
    IMAGE_NT_HEADERS ntHeaders;
    GUID pdbGuid;
    ULONG pdbAge = 0UL;
    ULONG index = 0UL;

    if (module == NULL || ntHeadersOut == NULL || pdbGuidOut == NULL ||
        pdbAgeOut == NULL || failedOpcodeRvaOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    RtlZeroMemory(ntHeadersOut, sizeof(*ntHeadersOut));
    RtlZeroMemory(pdbGuidOut, sizeof(*pdbGuidOut));
    *pdbAgeOut = 0UL;
    *failedOpcodeRvaOut = 0UL;
    if (!kswI8042ModuleNameEquals(module, "i8042prt.sys") ||
        !kswordArkHookReadImageNtHeaders(module, &ntHeaders)) {
        return STATUS_IMAGE_CHECKSUM_MISMATCH;
    }
    *ntHeadersOut = ntHeaders;
    if (
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.FileHeader.TimeDateStamp != KSW_I8042_EXPECTED_TIME_DATE_STAMP ||
        ntHeaders.OptionalHeader.SizeOfImage != KSW_I8042_EXPECTED_IMAGE_SIZE ||
        ntHeaders.OptionalHeader.CheckSum != KSW_I8042_EXPECTED_CHECKSUM ||
        module->imageSize != KSW_I8042_EXPECTED_IMAGE_SIZE) {
        return STATUS_IMAGE_CHECKSUM_MISMATCH;
    }
    if (!kswI8042ValidateRsds(module, &ntHeaders, &pdbGuid, &pdbAge)) {
        *pdbGuidOut = pdbGuid;
        *pdbAgeOut = pdbAge;
        return STATUS_REVISION_MISMATCH;
    }
    *pdbGuidOut = pdbGuid;
    *pdbAgeOut = pdbAge;
    for (index = 0UL;
         index < RTL_NUMBER_OF(kGKswI8042OpcodeDescriptors);
         ++index) {
        const KswI8042OpcodeDescriptor* descriptor =
            &kGKswI8042OpcodeDescriptors[index];
        UCHAR bytes[48];

        RtlZeroMemory(bytes, sizeof(bytes));
        if (descriptor->length == 0UL ||
            descriptor->length > sizeof(bytes) ||
            !kswordArkHookReadImageBytes(
                module,
                descriptor->rva,
                bytes,
                descriptor->length) ||
            RtlCompareMemory(
                bytes,
                descriptor->bytes,
                descriptor->length) != descriptor->length) {
            *failedOpcodeRvaOut = descriptor->rva;
            return STATUS_DATA_ERROR;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswI8042ReferenceDriver(
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )
{
    UNICODE_STRING name;

    if (driverObjectOut == NULL || IoDriverObjectType == NULL ||
        *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    RtlInitUnicodeString(&name, L"\\Driver\\i8042prt");
    return ObReferenceObjectByName(
        &name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0UL,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)driverObjectOut);
}

static NTSTATUS
kswI8042ValidateDriverLayout(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ const KswHookSystemModuleEntry* module,
    _Out_ ULONG64* observedDispatchOut,
    _Out_ ULONG64* observedAddDeviceOut
    )
{
    DRIVER_OBJECT driverView;
    PDRIVER_ADD_DEVICE addDevice = NULL;
    ULONG_PTR expectedDispatch = 0U;
    ULONG_PTR expectedAddDevice = 0U;

    if (driverObject == NULL || module == NULL ||
        observedDispatchOut == NULL || observedAddDeviceOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *observedDispatchOut = 0ULL;
    *observedAddDeviceOut = 0ULL;
    RtlZeroMemory(&driverView, sizeof(driverView));
    if (!kswordArkHookReadMemorySafe(
            driverObject,
            &driverView,
            sizeof(driverView))) {
        return STATUS_PARTIAL_COPY;
    }
    if (driverView.Type != IO_TYPE_DRIVER ||
        driverView.Size != (CSHORT)sizeof(DRIVER_OBJECT) ||
        driverView.DriverStart != module->imageBase ||
        driverView.DriverSize != module->imageSize ||
        driverView.DriverExtension == NULL) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!kswordArkHookReadMemorySafe(
            (const UCHAR*)driverView.DriverExtension +
                FIELD_OFFSET(DRIVER_EXTENSION, AddDevice),
            &addDevice,
            sizeof(addDevice))) {
        return STATUS_PARTIAL_COPY;
    }
    expectedDispatch =
        (ULONG_PTR)module->imageBase + KSW_I8042_EXPECTED_INTERNAL_DISPATCH_RVA;
    expectedAddDevice =
        (ULONG_PTR)module->imageBase + KSW_I8042_EXPECTED_ADD_DEVICE_RVA;
    *observedDispatchOut =
        (ULONG64)(ULONG_PTR)driverView.MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
    *observedAddDeviceOut = (ULONG64)(ULONG_PTR)addDevice;
    if ((ULONG_PTR)driverView.MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] !=
            expectedDispatch ||
        (ULONG_PTR)addDevice != expectedAddDevice) {
        return STATUS_DATA_ERROR;
    }
    return STATUS_SUCCESS;
}

static ULONG
kswI8042OutputCapacity(
    _In_ size_t outputBytes
    )
{
    size_t payloadBytes = 0U;
    size_t capacity = 0U;

    if (outputBytes <= KSW_I8042_RESPONSE_HEADER_SIZE) {
        return 0UL;
    }
    payloadBytes = outputBytes - KSW_I8042_RESPONSE_HEADER_SIZE;
    capacity = payloadBytes / sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY);
    return capacity > MAXULONG ? MAXULONG : (ULONG)capacity;
}

static VOID
kswI8042SetDetail(
    _Inout_ KSWORD_ARK_I8042_AUDIT_ENTRY* entry,
    _In_ ULONG detailCode,
    _In_ ULONGLONG arg0,
    _In_ ULONGLONG arg1,
    _In_ ULONGLONG arg2,
    _In_ ULONGLONG arg3
    )
{
    if (entry == NULL) {
        return;
    }
    entry->detailCode = detailCode;
    entry->detailArgs[0] = arg0;
    entry->detailArgs[1] = arg1;
    entry->detailArgs[2] = arg2;
    entry->detailArgs[3] = arg3;
    if (detailCode != KSWORD_ARK_I8042_DETAIL_NONE) {
        entry->fieldFlags |= KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
    }
}

static VOID
kswI8042Append(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KSWORD_ARK_I8042_AUDIT_ENTRY* entry
    )
{
    if (response == NULL || entry == NULL) {
        return;
    }
    response->totalCount += 1UL;
    if (response->returnedCount >= capacity ||
        response->returnedCount >= maxRows) {
        response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_TRUNCATED |
            KSWORD_ARK_I8042_RESPONSE_PARTIAL;
        response->queryStatus =
            KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }
    response->entries[response->returnedCount] = *entry;
    response->returnedCount += 1UL;
    if (entry->status != KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE) {
        response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_PARTIAL;
        if (response->queryStatus ==
            KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE) {
            response->queryStatus = KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL;
        }
    }
}

static VOID
kswI8042AddDiagnostic(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ ULONG status,
    _In_ NTSTATUS lastStatus,
    _In_ ULONG detailCode,
    _In_ ULONGLONG arg0,
    _In_ ULONGLONG arg1,
    _In_ BOOLEAN failClosed
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY entry;
    ULONG returnedBefore = 0UL;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC;
    entry.status = status;
    entry.verdict = failClosed ?
        KSWORD_ARK_I8042_VERDICT_UNSUPPORTED :
        KSWORD_ARK_I8042_VERDICT_UNKNOWN;
    entry.lastStatus = lastStatus;
    kswI8042SetDetail(&entry, detailCode, arg0, arg1, 0ULL, 0ULL);
    returnedBefore = response->returnedCount;
    kswI8042Append(response, capacity, maxRows, &entry);
    response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_PARTIAL;
    if (failClosed) {
        response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED;
    }
    if (response->returnedCount == returnedBefore) {
        // kswI8042Append has already reserved BUFFER_TRUNCATED/STATUS_BUFFER_OVERFLOW.
        return;
    }
    response->queryStatus = status;
    response->lastStatus = lastStatus;
}

static BOOLEAN
kswI8042WideContainsInsensitive(
    _In_reads_(textChars) PCWSTR text,
    _In_ ULONG textChars,
    _In_z_ PCWSTR needle
    )
{
    ULONG needleChars = 0UL;
    ULONG offset = 0UL;
    ULONG index = 0UL;

    if (text == NULL || needle == NULL) {
        return FALSE;
    }
    while (needle[needleChars] != L'\0') {
        needleChars += 1UL;
    }
    if (needleChars == 0UL || needleChars > textChars) {
        return FALSE;
    }
    for (offset = 0UL; offset + needleChars <= textChars; ++offset) {
        BOOLEAN matched = TRUE;
        for (index = 0UL; index < needleChars; ++index) {
            WCHAR left = text[offset + index];
            WCHAR right = needle[index];
            if (left == L'\0') {
                matched = FALSE;
                break;
            }
            if (RtlUpcaseUnicodeChar(left) != RtlUpcaseUnicodeChar(right)) {
                matched = FALSE;
                break;
            }
        }
        if (matched) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG
kswI8042ClassifyDevice(
    _In_ PDEVICE_OBJECT deviceObject,
    _Out_writes_(pnpIdChars) PWCHAR pnpId,
    _In_ ULONG pnpIdChars
    )
{
    PDEVICE_OBJECT physicalDevice = NULL;
    WCHAR classGuid[64];
    WCHAR hardwareIds[KSWORD_ARK_I8042_PNP_ID_CHARS];
    ULONG requiredBytes = 0UL;
    NTSTATUS classStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS hardwareStatus = STATUS_UNSUCCESSFUL;

    if (pnpId == NULL || pnpIdChars == 0UL) {
        return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
    }
    pnpId[0] = L'\0';
    RtlZeroMemory(classGuid, sizeof(classGuid));
    RtlZeroMemory(hardwareIds, sizeof(hardwareIds));
    physicalDevice = IoGetDeviceAttachmentBaseRef(deviceObject);
    if (physicalDevice == NULL) {
        return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
    }
    classStatus = IoGetDeviceProperty(
        physicalDevice,
        DevicePropertyClassGuid,
        sizeof(classGuid) - sizeof(WCHAR),
        classGuid,
        &requiredBytes);
    requiredBytes = 0UL;
    hardwareStatus = IoGetDeviceProperty(
        physicalDevice,
        DevicePropertyHardwareID,
        sizeof(hardwareIds) - sizeof(WCHAR),
        hardwareIds,
        &requiredBytes);
    if (NT_SUCCESS(hardwareStatus) && hardwareIds[0] != L'\0') {
        kswI8042CopyWide(pnpId, pnpIdChars, hardwareIds);
    }
    else if (NT_SUCCESS(classStatus) && classGuid[0] != L'\0') {
        kswI8042CopyWide(pnpId, pnpIdChars, classGuid);
    }

    ObDereferenceObject(physicalDevice);

    if ((NT_SUCCESS(classStatus) &&
         kswI8042WideContainsInsensitive(
             classGuid,
             RTL_NUMBER_OF(classGuid),
             L"4D36E96B-E325-11CE-BFC1-08002BE10318")) ||
        (NT_SUCCESS(hardwareStatus) &&
         kswI8042WideContainsInsensitive(
             hardwareIds,
             RTL_NUMBER_OF(hardwareIds),
             L"PNP030"))) {
        return KSWORD_ARK_I8042_DEVICE_KEYBOARD;
    }
    if ((NT_SUCCESS(classStatus) &&
         kswI8042WideContainsInsensitive(
             classGuid,
             RTL_NUMBER_OF(classGuid),
             L"4D36E96F-E325-11CE-BFC1-08002BE10318")) ||
        (NT_SUCCESS(hardwareStatus) &&
         kswI8042WideContainsInsensitive(
             hardwareIds,
             RTL_NUMBER_OF(hardwareIds),
             L"PNP0F"))) {
        return KSWORD_ARK_I8042_DEVICE_MOUSE;
    }
    return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
}

static BOOLEAN
kswI8042ReadExtensionPointer(
    _In_ PVOID deviceExtension,
    _In_ ULONG offset,
    _Out_ PVOID* valueOut
    )
{
    if (deviceExtension == NULL || valueOut == NULL ||
        offset + sizeof(PVOID) > KSW_I8042_EXPECTED_EXTENSION_SIZE) {
        return FALSE;
    }
    *valueOut = NULL;
    return kswordArkHookReadMemorySafe(
        (const UCHAR*)deviceExtension + offset,
        valueOut,
        sizeof(*valueOut));
}

static BOOLEAN
kswI8042ReadEndpoints(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PDRIVER_OBJECT expectedDriverObject,
    _In_ ULONG deviceKind,
    _Out_ KswI8042EndpointValues* valuesOut
    )
{
    DEVICE_OBJECT deviceView;
    BOOLEAN success = TRUE;

    if (deviceObject == NULL || expectedDriverObject == NULL ||
        valuesOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&deviceView, sizeof(deviceView));
    RtlZeroMemory(valuesOut, sizeof(*valuesOut));
    if (!kswordArkHookReadMemorySafe(
            deviceObject,
            &deviceView,
            sizeof(deviceView)) ||
        deviceView.DriverObject != expectedDriverObject ||
        deviceView.DeviceExtension == NULL ||
        deviceView.DeviceType != FILE_DEVICE_8042_PORT) {
        return FALSE;
    }
    success = kswI8042ReadExtensionPointer(
        deviceView.DeviceExtension,
        KSW_I8042_OFFSET_CLASS_DEVICE_OBJECT,
        &valuesOut->classDeviceObject) && success;
    success = kswI8042ReadExtensionPointer(
        deviceView.DeviceExtension,
        KSW_I8042_OFFSET_CLASS_SERVICE,
        &valuesOut->classService) && success;
    if (deviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD) {
        success = kswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_INIT,
            &valuesOut->initializationRoutine) && success;
        success = kswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_ISR,
            &valuesOut->isrRoutine) && success;
        success = kswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_CONTEXT,
            &valuesOut->context) && success;
    }
    else if (deviceKind == KSWORD_ARK_I8042_DEVICE_MOUSE) {
        success = kswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_MOUSE_ISR,
            &valuesOut->isrRoutine) && success;
        success = kswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_MOUSE_CONTEXT,
            &valuesOut->context) && success;
    }
    else {
        success = FALSE;
    }
    return success;
}

static VOID
kswI8042InspectStack(
    _In_ PDEVICE_OBJECT baseDevice,
    _In_opt_ PVOID classDeviceObject,
    _In_ ULONG64 ownerModuleBase,
    _In_ ULONG ownerModuleSize,
    _Out_ BOOLEAN* classDevicePresentOut,
    _Out_ BOOLEAN* ownerModulePresentOut
    )
{
    PDEVICE_OBJECT current = NULL;
    ULONG depth = 0UL;

    if (classDevicePresentOut == NULL || ownerModulePresentOut == NULL) {
        return;
    }
    *classDevicePresentOut = FALSE;
    *ownerModulePresentOut = FALSE;
    if (baseDevice == NULL) {
        return;
    }
    current = IoGetAttachedDeviceReference(baseDevice);
    while (current != NULL && depth < KSW_I8042_STACK_DEPTH_LIMIT) {
        PDEVICE_OBJECT next = NULL;
        DEVICE_OBJECT deviceView;
        DRIVER_OBJECT driverView;

        RtlZeroMemory(&deviceView, sizeof(deviceView));
        RtlZeroMemory(&driverView, sizeof(driverView));
        if ((PVOID)current == classDeviceObject) {
            *classDevicePresentOut = TRUE;
        }
        if (kswordArkHookReadMemorySafe(
                current,
                &deviceView,
                sizeof(deviceView)) &&
            deviceView.DriverObject != NULL &&
            kswordArkHookReadMemorySafe(
                deviceView.DriverObject,
                &driverView,
                sizeof(driverView)) &&
            ownerModuleBase != 0ULL &&
            ownerModuleSize != 0UL &&
            (ULONG64)(ULONG_PTR)driverView.DriverStart == ownerModuleBase &&
            driverView.DriverSize == ownerModuleSize) {
            *ownerModulePresentOut = TRUE;
        }
        next = IoGetLowerDeviceObject(current);
        ObDereferenceObject(current);
        current = next;
        depth += 1UL;
    }
    if (current != NULL) {
        ObDereferenceObject(current);
    }
}

static VOID
kswI8042FillOwnerModule(
    _Inout_ KSWORD_ARK_I8042_AUDIT_ENTRY* entry,
    _In_opt_ const KswHookSystemModuleEntry* module
    )
{
    if (entry == NULL || module == NULL) {
        return;
    }
    entry->moduleBase = (ULONGLONG)(ULONG_PTR)module->imageBase;
    entry->moduleSize = module->imageSize;
    entry->fieldFlags |= KSWORD_ARK_I8042_FIELD_OWNER_MODULE;
    kswordArkHookCopyBoundedAnsiToWide(
        module->fullPathName,
        RTL_NUMBER_OF(module->fullPathName),
        entry->ownerModulePath,
        RTL_NUMBER_OF(entry->ownerModulePath));
}

static VOID
kswI8042AddEndpoint(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ ULONG deviceKind,
    _In_ ULONG endpointKind,
    _In_opt_ PVOID callbackAddress,
    _In_opt_ PVOID contextAddress,
    _In_opt_ PVOID classDeviceObject,
    _In_opt_z_ PCWSTR pnpId
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY entry;
    const KswHookSystemModuleEntry* owner = NULL;
    BOOLEAN executable = FALSE;
    BOOLEAN classDevicePresent = FALSE;
    BOOLEAN ownerModulePresent = FALSE;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT;
    entry.deviceKind = deviceKind;
    entry.endpointKind = endpointKind;
    entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE;
    entry.verdict = KSWORD_ARK_I8042_VERDICT_UNKNOWN;
    entry.lastStatus = STATUS_SUCCESS;
    entry.deviceObject = (ULONGLONG)(ULONG_PTR)deviceObject;
    entry.classDeviceObject = (ULONGLONG)(ULONG_PTR)classDeviceObject;
    entry.callbackAddress = (ULONGLONG)(ULONG_PTR)callbackAddress;
    entry.contextAddress = (ULONGLONG)(ULONG_PTR)contextAddress;
    entry.fieldFlags = KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
        KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
        KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED;
    if (pnpId != NULL && pnpId[0] != L'\0') {
        kswI8042CopyWide(entry.pnpId, RTL_NUMBER_OF(entry.pnpId), pnpId);
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_PNP_ID;
    }
    if (classDeviceObject != NULL) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT;
    }
    if (contextAddress != NULL) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS;
    }
    if (callbackAddress == NULL) {
        kswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL,
            endpointKind,
            (ULONGLONG)(ULONG_PTR)deviceObject,
            0ULL,
            0ULL);
        kswI8042Append(response, capacity, maxRows, &entry);
        return;
    }

    entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS;
    owner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)callbackAddress);
    kswI8042FillOwnerModule(&entry, owner);
    executable = owner != NULL &&
        kswI8042AddressExecutable(owner, (ULONG_PTR)callbackAddress);
    if (executable) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_EXECUTABLE;
    }
    kswI8042InspectStack(
        deviceObject,
        classDeviceObject,
        entry.moduleBase,
        entry.moduleSize,
        &classDevicePresent,
        &ownerModulePresent);
    if (classDevicePresent) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK;
    }

    if (owner == NULL || !ownerModulePresent) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        kswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH,
            entry.callbackAddress,
            entry.moduleBase,
            endpointKind,
            0ULL);
    }
    else if (!executable) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_INVALID_ADDRESS;
        kswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE,
            entry.callbackAddress,
            entry.moduleBase,
            endpointKind,
            0ULL);
    }
    else if (classDeviceObject == NULL || !classDevicePresent) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        kswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK,
            entry.classDeviceObject,
            entry.deviceObject,
            endpointKind,
            0ULL);
    }
    else {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_AVAILABLE;
        kswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE,
            entry.callbackAddress,
            entry.moduleBase,
            entry.classDeviceObject,
            entry.contextAddress);
    }
    kswI8042Append(response, capacity, maxRows, &entry);
}

static VOID
kswI8042AuditDevice(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ BOOLEAN imageValidated,
    _In_ BOOLEAN descriptorValidated
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY deviceEntry;
    DEVICE_OBJECT deviceView;
    KswI8042EndpointValues values;
    WCHAR pnpId[KSWORD_ARK_I8042_PNP_ID_CHARS];
    ULONG deviceKind = KSWORD_ARK_I8042_DEVICE_UNKNOWN;

    RtlZeroMemory(&deviceEntry, sizeof(deviceEntry));
    RtlZeroMemory(&deviceView, sizeof(deviceView));
    RtlZeroMemory(&values, sizeof(values));
    RtlZeroMemory(pnpId, sizeof(pnpId));
    deviceEntry.size = sizeof(deviceEntry);
    deviceEntry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_DEVICE;
    deviceEntry.status = KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED;
    deviceEntry.verdict = KSWORD_ARK_I8042_VERDICT_UNKNOWN;
    deviceEntry.deviceObject = (ULONGLONG)(ULONG_PTR)deviceObject;
    deviceEntry.fieldFlags = KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT;
    if (imageValidated) {
        deviceEntry.fieldFlags |= KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED;
    }
    if (descriptorValidated) {
        deviceEntry.fieldFlags |= KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED;
    }

    if (!kswordArkHookReadMemorySafe(
            deviceObject,
            &deviceView,
            sizeof(deviceView)) ||
        deviceView.DriverObject != driverObject) {
        deviceEntry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        kswI8042SetDetail(
            &deviceEntry,
            KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH,
            deviceEntry.deviceObject,
            deviceView.DeviceType,
            (ULONGLONG)(ULONG_PTR)deviceView.DriverObject,
            0ULL);
        kswI8042Append(response, capacity, maxRows, &deviceEntry);
        return;
    }

    deviceKind = kswI8042ClassifyDevice(
        deviceObject,
        pnpId,
        RTL_NUMBER_OF(pnpId));
    deviceEntry.deviceKind = deviceKind;
    if (pnpId[0] != L'\0') {
        kswI8042CopyWide(
            deviceEntry.pnpId,
            RTL_NUMBER_OF(deviceEntry.pnpId),
            pnpId);
        deviceEntry.fieldFlags |= KSWORD_ARK_I8042_FIELD_PNP_ID;
    }
    if (deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN) {
        deviceEntry.status = KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL;
        deviceEntry.verdict = KSWORD_ARK_I8042_VERDICT_UNKNOWN;
        deviceEntry.lastStatus = STATUS_NOT_SUPPORTED;
        kswI8042SetDetail(
            &deviceEntry,
            KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN,
            deviceEntry.deviceObject,
            0ULL,
            0ULL,
            0ULL);
        kswI8042Append(response, capacity, maxRows, &deviceEntry);
        return;
    }

    deviceEntry.status = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
    deviceEntry.verdict = KSWORD_ARK_I8042_VERDICT_AVAILABLE;
    deviceEntry.lastStatus = STATUS_SUCCESS;
    kswI8042SetDetail(
        &deviceEntry,
        descriptorValidated ?
            KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED :
            KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE,
        descriptorValidated ? KSW_I8042_EXPECTED_EXTENSION_SIZE : 0UL,
        deviceKind,
        deviceEntry.deviceObject,
        0ULL);
    kswI8042Append(response, capacity, maxRows, &deviceEntry);

    // Note: Device objects and PnP identifiers come from public I/O Manager interfaces and may vary across versions.
    // The extended offset belongs to i8042prt's private layout; never read when the descriptor is imprecise.
    if (!descriptorValidated || moduleInfo == NULL) {
        return;
    }

    if (!kswI8042ReadEndpoints(
            deviceObject,
            driverObject,
            deviceKind,
            &values)) {
        kswI8042AddDiagnostic(
            response,
            capacity,
            maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED,
            deviceEntry.deviceObject,
            deviceKind,
            FALSE);
        return;
    }

    if (deviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD) {
        kswI8042AddEndpoint(
            response, capacity, maxRows, moduleInfo, deviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE,
            values.classService, NULL, values.classDeviceObject, pnpId);
        kswI8042AddEndpoint(
            response, capacity, maxRows, moduleInfo, deviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_INITIALIZATION,
            values.initializationRoutine, values.context,
            values.classDeviceObject, pnpId);
        kswI8042AddEndpoint(
            response, capacity, maxRows, moduleInfo, deviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR,
            values.isrRoutine, values.context,
            values.classDeviceObject, pnpId);
    }
    else {
        kswI8042AddEndpoint(
            response, capacity, maxRows, moduleInfo, deviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE,
            values.classService, NULL, values.classDeviceObject, pnpId);
        kswI8042AddEndpoint(
            response, capacity, maxRows, moduleInfo, deviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR,
            values.isrRoutine, values.context,
            values.classDeviceObject, pnpId);
    }
}

static VOID
kswI8042ReleaseDeviceList(
    _Inout_updates_(count) PDEVICE_OBJECT* deviceObjects,
    _In_ ULONG count
    )
{
    ULONG index = 0UL;

    if (deviceObjects == NULL) {
        return;
    }
    for (index = 0UL; index < count; ++index) {
        if (deviceObjects[index] != NULL) {
            ObDereferenceObject(deviceObjects[index]);
            deviceObjects[index] = NULL;
        }
    }
}

static NTSTATUS
kswI8042EnumerateDevices(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PDRIVER_OBJECT driverObject,
    _In_ BOOLEAN imageValidated,
    _In_ BOOLEAN descriptorValidated
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = IoEnumerateDeviceObjectList(
        driverObject,
        NULL,
        0UL,
        &requestedCount);
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        return status;
    }
    if (requestedCount == 0UL) {
        kswI8042AddDiagnostic(
            response,
            capacity,
            maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE,
            STATUS_NOT_FOUND,
            KSWORD_ARK_I8042_DETAIL_NO_DEVICES,
            0ULL,
            0ULL,
            FALSE);
        return STATUS_SUCCESS;
    }

    for (attempt = 0UL; attempt < KSW_I8042_DEVICE_ENUM_RETRIES; ++attempt) {
        ULONG index = 0UL;
        if (requestedCount > KSW_I8042_DEVICE_LIMIT) {
            return STATUS_NOT_SUPPORTED;
        }
        deviceObjects = (PDEVICE_OBJECT*)kswordArkAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_I8042_POOL_TAG);
        if (deviceObjects == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        actualCount = 0UL;
        status = IoEnumerateDeviceObjectList(
            driverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        if (status == STATUS_BUFFER_TOO_SMALL) {
            kswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            deviceObjects = NULL;
            if (actualCount <= requestedCount) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            requestedCount = actualCount;
            continue;
        }
        if (!NT_SUCCESS(status)) {
            kswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            return status;
        }
        if (actualCount > requestedCount) {
            kswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }
        if (actualCount == 0UL) {
            kswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            kswI8042AddDiagnostic(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE,
                STATUS_NOT_FOUND,
                KSWORD_ARK_I8042_DETAIL_NO_DEVICES,
                0ULL,
                0ULL,
                FALSE);
            return STATUS_SUCCESS;
        }
        for (index = 0UL; index < actualCount; ++index) {
            if (deviceObjects[index] != NULL) {
                kswI8042AuditDevice(
                    response,
                    capacity,
                    maxRows,
                    moduleInfo,
                    driverObject,
                    deviceObjects[index],
                    imageValidated,
                    descriptorValidated);
            }
        }
        kswI8042ReleaseDeviceList(deviceObjects, requestedCount);
        ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
        return STATUS_SUCCESS;
    }
    return STATUS_RETRY;
}

NTSTATUS
kswordArkI8042AuditIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST defaultRequest;
    const KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST* requestPacket = NULL;
    KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    const KswHookSystemModuleEntry* i8042Module = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS;
    ULONG failedOpcodeRva = 0UL;
    ULONG pdbAge = 0UL;
    GUID pdbGuid;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG64 observedDispatch = 0ULL;
    ULONG64 observedAddDevice = 0ULL;
    BOOLEAN imageValidated = FALSE;
    BOOLEAN descriptorValidated = FALSE;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
    defaultRequest.maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputBytes,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    requestPacket = hasInput ?
        (const KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST*)inputBuffer :
        &defaultRequest;
    if (requestPacket->size != sizeof(*requestPacket) ||
        requestPacket->version != KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION ||
        requestPacket->flags != 0UL ||
        requestPacket->reserved0 != 0UL ||
        requestPacket->reserved1 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    maxRows = requestPacket->maxRows == 0UL ?
        KSWORD_ARK_I8042_DEFAULT_MAX_ROWS :
        requestPacket->maxRows;
    if (maxRows > KSWORD_ARK_I8042_HARD_MAX_ROWS) {
        maxRows = KSWORD_ARK_I8042_HARD_MAX_ROWS;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_I8042_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, actualOutputBytes);
    response = (KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSW_I8042_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
    response->entrySize = sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY);
    response->descriptorId = KSWORD_ARK_I8042_DESCRIPTOR_WIN11_26100_7934;
    response->lastStatus = STATUS_SUCCESS;
    capacity = kswI8042OutputCapacity(actualOutputBytes);

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }
        kswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL,
            status,
            KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND,
            moduleInfoBytes,
            0ULL,
            FALSE);
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            moduleInfo = NULL;
        }
    }
    if (moduleInfo != NULL) {
        i8042Module = kswI8042FindUniqueModule(moduleInfo, "i8042prt.sys");
    }
    if (moduleInfo != NULL && i8042Module == NULL) {
        kswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL,
            STATUS_NOT_FOUND,
            KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND,
            0ULL,
            0ULL,
            FALSE);
    }

    if (i8042Module != NULL) {
        status = kswI8042ValidateImage(
            i8042Module,
            &ntHeaders,
            &pdbGuid,
            &pdbAge,
            &failedOpcodeRva);
        response->imageBase = (ULONGLONG)(ULONG_PTR)i8042Module->imageBase;
        response->imageTimeDateStamp = ntHeaders.FileHeader.TimeDateStamp;
        response->imageSize = ntHeaders.OptionalHeader.SizeOfImage;
        response->imageChecksum = ntHeaders.OptionalHeader.CheckSum;
        response->pdbAge = pdbAge;
        RtlCopyMemory(response->pdbGuid, &pdbGuid, sizeof(pdbGuid));
        if (!NT_SUCCESS(status)) {
            ULONG detailCode = KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH;
            if (status == STATUS_REVISION_MISMATCH) {
                detailCode = KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH;
            }
            else if (status == STATUS_DATA_ERROR) {
                detailCode = KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH;
            }
            kswI8042AddDiagnostic(
                response, capacity, maxRows,
                KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL,
                status,
                detailCode,
                failedOpcodeRva,
                response->imageBase,
                FALSE);
        }
        else {
            imageValidated = TRUE;
            response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED;
        }
    }

    status = kswI8042ReferenceDriver(&driverObject);
    if (!NT_SUCCESS(status) || driverObject == NULL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_NOT_FOUND;
        }
        kswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND,
            0ULL,
            0ULL,
            FALSE);
        goto Exit;
    }
    if (imageValidated) {
        status = kswI8042ValidateDriverLayout(
            driverObject,
            i8042Module,
            &observedDispatch,
            &observedAddDevice);
        if (!NT_SUCCESS(status)) {
            kswI8042AddDiagnostic(
                response, capacity, maxRows,
                KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL,
                status,
                KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH,
                observedDispatch,
                observedAddDevice,
                FALSE);
        }
        else {
            descriptorValidated = TRUE;
            response->responseFlags |=
                KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED;
        }
    }

    status = kswI8042EnumerateDevices(
        response,
        capacity,
        maxRows,
        moduleInfo,
        driverObject,
        imageValidated,
        descriptorValidated);
    if (!NT_SUCCESS(status)) {
        kswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED,
            0ULL,
            0ULL,
            FALSE);
    }

Exit:
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    *bytesReturned = KSW_I8042_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
         sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
