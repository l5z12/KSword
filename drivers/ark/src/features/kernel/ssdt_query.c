/*++

Module Name:

    ssdt_query.c

Abstract:

    This file contains SSDT traversal snapshot helpers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ssdt_fallback.h"

#include <ntimage.h>
#include <ntstrsafe.h>

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID pcValue,
    _Outptr_ PVOID* baseOfImage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef struct KswordArkServiceTableDescriptor
{
    PVOID serviceTableBase;
    PVOID serviceCounterTableBase;
    ULONG_PTR numberOfServices;
    PVOID paramTableBase;
} KswordArkServiceTableDescriptor;

static const ULONG kGKswordArkSsdtResponseHeaderSize =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY));

static VOID
kswordArkDriverCopyAnsiText(
    _Out_writes_bytes_(destinationBytes) CHAR* destinationText,
    _In_ size_t destinationBytes,
    _In_opt_z_ const CHAR* sourceText
    );

static BOOLEAN
kswordArkDriverStartsWithZw(
    _In_opt_z_ const CHAR* nameText
    )
{
    if (nameText == NULL) {
        return FALSE;
    }

    if (nameText[0] != 'Z' || nameText[1] != 'w') {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
kswordArkDriverStartsWithAnsi(
    _In_opt_z_ const CHAR* nameText,
    _In_z_ const CHAR* prefixText
    )
/*++

Routine Description:

    Check if the exported name has the specified ANSI prefix. Note: SSSDT relies on win32k/win32u
    export naming in System Informer; this reuses the same approach for prefix matching only.

Arguments:

    NameText - Export name to check.
    PrefixText: The prefix to match.

Return Value:

    TRUE indicates prefix match; FALSE indicates no match or invalid parameters.

--*/
{
    ULONG index = 0UL;

    if (nameText == NULL || prefixText == NULL) {
        return FALSE;
    }

    while (prefixText[index] != '\0') {
        if (nameText[index] == '\0' || nameText[index] != prefixText[index]) {
            return FALSE;
        }
        ++index;
    }

    return TRUE;
}

static BOOLEAN
kswordArkDriverAsciiEqualsInsensitive(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    )
/*++

Routine Description:

    Compare the limited-length module filenames in SystemModuleInformation. Note: Module paths are
    not guaranteed to be NUL-terminated, so a byte-by-byte comparison with length must be used.

Arguments:

    LeftText - Left-side finite-length ANSI text.
    LeftBytes - Number of readable bytes on the left.
    RightText - Right-side NUL-terminated constant text.

Return Value:

    TRUE indicates case-insensitive equality.

--*/
{
    ULONG index = 0UL;

    if (leftText == NULL || rightText == NULL || leftBytes == 0UL) {
        return FALSE;
    }

    for (index = 0UL; index < leftBytes; ++index) {
        CHAR leftChar = (CHAR)leftText[index];
        CHAR rightChar = rightText[index];

        if (leftChar >= 'A' && leftChar <= 'Z') {
            leftChar = (CHAR)(leftChar + ('a' - 'A'));
        }
        if (rightChar >= 'A' && rightChar <= 'Z') {
            rightChar = (CHAR)(rightChar + ('a' - 'A'));
        }
        if (rightChar == '\0') {
            return leftChar == '\0';
        }
        if (leftChar == '\0' || leftChar != rightChar) {
            return FALSE;
        }
    }

    return rightText[index] == '\0';
}

static NTSTATUS
kswordArkDriverResolveLoadedModuleImage(
    _In_z_ PCSTR moduleFileName,
    _Outptr_ PVOID* imageBaseOut,
    _Out_ ULONG* imageSizeOut,
    _Out_writes_bytes_(moduleNameBytes) CHAR* moduleNameTextOut,
    _In_ size_t moduleNameBytes
    )
/*++

Routine Description:

    Locate loaded kernel modules from SystemModuleInformation. Note: SSSDT requires base addresses for graphics
    subsystem modules such as win32k.sys/win32u.dll; this does not load files but uses already-loaded images.

Arguments:

    ModuleFileName - Target module file name.
    ImageBaseOut - Returns the loaded base address.
    ImageSizeOut - Returns the image size.
    ModuleNameTextOut: Returns the module name.
    ModuleNameBytes: Buffer size in bytes for the module name.

Return Value:

    STATUS_SUCCESS or query/not found status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    PVOID rawBuffer = NULL;
    ULONG moduleIndex = 0UL;

    typedef struct KswSsdtSystemModuleEntry {
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
    } KswSsdtSystemModuleEntry;
    typedef struct KswSsdtSystemModuleInformation {
        ULONG numberOfModules;
        KswSsdtSystemModuleEntry modules[1];
    } KswSsdtSystemModuleInformation;

    if (imageBaseOut == NULL || imageSizeOut == NULL || moduleFileName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *imageBaseOut = NULL;
    *imageSizeOut = 0UL;
    if (moduleNameTextOut != NULL && moduleNameBytes > 0U) {
        moduleNameTextOut[0] = '\0';
    }

    status = ZwQuerySystemInformation(11UL, NULL, 0UL, &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    rawBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, requiredBytes, 'sSsK');
#pragma warning(pop)
    if (rawBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(11UL, rawBuffer, requiredBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        KswSsdtSystemModuleInformation* moduleInfo =
            (KswSsdtSystemModuleInformation*)rawBuffer;
        for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
            const KswSsdtSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
            const UCHAR* fileName = moduleEntry->fullPathName;
            ULONG fileNameBytes = (ULONG)sizeof(moduleEntry->fullPathName);

            if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
                fileName = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
                fileNameBytes = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
            }

            if (!kswordArkDriverAsciiEqualsInsensitive(fileName, fileNameBytes, moduleFileName)) {
                continue;
            }

            *imageBaseOut = moduleEntry->imageBase;
            *imageSizeOut = moduleEntry->imageSize;
            kswordArkDriverCopyAnsiText(moduleNameTextOut, moduleNameBytes, moduleFileName);
            ExFreePoolWithTag(rawBuffer, 'sSsK');
            return STATUS_SUCCESS;
        }
        status = STATUS_NOT_FOUND;
    }

    ExFreePoolWithTag(rawBuffer, 'sSsK');
    return status;
}

static VOID
kswordArkDriverCopyAnsiText(
    _Out_writes_bytes_(destinationBytes) CHAR* destinationText,
    _In_ size_t destinationBytes,
    _In_opt_z_ const CHAR* sourceText
    )
{
    if (destinationText == NULL || destinationBytes == 0U) {
        return;
    }

    destinationText[0] = '\0';
    if (sourceText == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyNA(
        destinationText,
        destinationBytes,
        sourceText,
        destinationBytes - 1U);
    destinationText[destinationBytes - 1U] = '\0';
}

static BOOLEAN
kswordArkDriverFindServiceIndexFromStub(
    _In_reads_bytes_(stubLengthBytes) const UCHAR* stubBytes,
    _In_ ULONG stubLengthBytes,
    _Out_ ULONG* serviceIndexOut
    )
{
    ULONG scanOffset = 0;

    if (stubBytes == NULL || serviceIndexOut == NULL) {
        return FALSE;
    }

    *serviceIndexOut = 0U;
    if (stubLengthBytes < 5U) {
        return FALSE;
    }

    for (scanOffset = 0U; scanOffset + 5U <= stubLengthBytes; ++scanOffset) {
        if (stubBytes[scanOffset] == 0xB8U) {
            ULONG serviceIndex = 0U;
            RtlCopyMemory(&serviceIndex, stubBytes + scanOffset + 1U, sizeof(serviceIndex));
            *serviceIndexOut = serviceIndex;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkDriverValidateRvaRange(
    _In_ ULONG rvaValue,
    _In_ ULONG dataLength,
    _In_ ULONG imageSize
    )
{
    if (rvaValue >= imageSize) {
        return FALSE;
    }

    if (dataLength > imageSize) {
        return FALSE;
    }

    if (rvaValue > (imageSize - dataLength)) {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS
kswordArkDriverResolveKernelImage(
    _Outptr_ PVOID* imageBaseOut,
    _Out_ ULONG* imageSizeOut,
    _Out_writes_bytes_(moduleNameBytes) CHAR* moduleNameTextOut,
    _In_ size_t moduleNameBytes
    )
{
    UNICODE_STRING routineName;
    PVOID ntOpenProcessAddress = NULL;
    PVOID imageBase = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    if (imageBaseOut == NULL || imageSizeOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *imageBaseOut = NULL;
    *imageSizeOut = 0U;
    if (moduleNameTextOut != NULL && moduleNameBytes > 0U) {
        moduleNameTextOut[0] = '\0';
    }

    RtlInitUnicodeString(&routineName, L"NtOpenProcess");
    ntOpenProcessAddress = MmGetSystemRoutineAddress(&routineName);
    if (ntOpenProcessAddress == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (RtlPcToFileHeader(ntOpenProcessAddress, &imageBase) == NULL || imageBase == NULL) {
        return STATUS_NOT_FOUND;
    }

    dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + (ULONG)dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *imageBaseOut = imageBase;
    *imageSizeOut = ntHeaders->OptionalHeader.SizeOfImage;

    if (moduleNameTextOut != NULL && moduleNameBytes > 0U) {
        const IMAGE_DATA_DIRECTORY* exportDirectory =
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirectory->VirtualAddress != 0U &&
            kswordArkDriverValidateRvaRange(exportDirectory->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), *imageSizeOut)) {
            const PIMAGE_EXPORT_DIRECTORY kExportHeader =
                (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirectory->VirtualAddress);
            if (kExportHeader->Name != 0U &&
                kswordArkDriverValidateRvaRange(kExportHeader->Name, 2U, *imageSizeOut)) {
                const CHAR* exportModuleName = (const CHAR*)((PUCHAR)imageBase + kExportHeader->Name);
                kswordArkDriverCopyAnsiText(moduleNameTextOut, moduleNameBytes, exportModuleName);
            }
        }

        if (moduleNameTextOut[0] == '\0') {
            kswordArkDriverCopyAnsiText(moduleNameTextOut, moduleNameBytes, "ntoskrnl.exe");
        }
    }

    return STATUS_SUCCESS;
}

static VOID
kswordArkDriverTryResolveServiceTable(
    _Outptr_result_maybenull_ PVOID* tableBaseOut,
    _Out_ ULONG* serviceCountOut
    )
{
    UNICODE_STRING tableName;
    PVOID descriptorAddress = NULL;

    if (tableBaseOut == NULL || serviceCountOut == NULL) {
        return;
    }

    *tableBaseOut = NULL;
    *serviceCountOut = 0U;

    RtlInitUnicodeString(&tableName, L"KeServiceDescriptorTable");
    descriptorAddress = MmGetSystemRoutineAddress(&tableName);
    if (descriptorAddress != NULL) {
        const KswordArkServiceTableDescriptor* descriptor =
            (const KswordArkServiceTableDescriptor*)descriptorAddress;
        if (descriptor->serviceTableBase != NULL &&
            descriptor->numberOfServices > 0U &&
            descriptor->numberOfServices <= MAXULONG) {
            *tableBaseOut = descriptor->serviceTableBase;
            *serviceCountOut = (ULONG)descriptor->numberOfServices;
            return;
        }
    }
}

static BOOLEAN
kswordArkDriverIsDynGlobalRvaPresent(
    _In_ ULONG rvaValue
    )
/*++

Routine Description:

    Check if the global RVA provided by DynData is valid. Note: Shadow SSDT only consumes PDB RVAs that have
    completed ntoskrnl identity matching or have passed unique hit and liveness table entry validation.
    runtime pattern RVA。

Arguments:

    RvaValue - RVA of the global variable stored in DynData.

Return Value:

    TRUE indicates that image range verification can continue; FALSE indicates the profile does not provide this global.

--*/
{
    if (rvaValue == 0UL) {
        return FALSE;
    }

    if (rvaValue == KSW_DYN_OFFSET_UNAVAILABLE || rvaValue == 0x0000FFFFUL) {
        return FALSE;
    }

    return TRUE;
}

static VOID
kswordArkDriverTryResolveShadowServiceTable(
    _Outptr_result_maybenull_ PVOID* tableBaseOut,
    _Out_ ULONG* serviceCountOut
    )
/*++

Routine Description:

    Parse the GUI shadow service table from the KeServiceDescriptorTableShadow RVA in
    the DynData/PDB profile. Note: KeServiceDescriptorTableShadow is a descriptor array;
    index 0 corresponds to ntoskrnl, index 1 to win32k/GUI shadow table; read only if
    the profile identity matches and the RVA falls within the current ntoskrnl image.

Arguments:

    tableBaseOut: Returns the base address of the shadow service table.
    serviceCountOut - Returns the number of shadow service table entries.

Return Value:

    None. On failure, return NULL/0; the caller retains the stub/index degraded view.

--*/
{
    KswDynState dynState;
    ULONG tableShadowRva = 0UL;
    ULONG tableShadowSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
    ULONG64 descriptorAddress = 0ULL;
    const KswordArkServiceTableDescriptor* descriptorArray = NULL;

    if (tableBaseOut == NULL || serviceCountOut == NULL) {
        return;
    }

    *tableBaseOut = NULL;
    *serviceCountOut = 0UL;
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    if (!dynState.initialized ||
        !dynState.ntosActive ||
        dynState.ntoskrnl.imageBase == 0ULL ||
        dynState.ntoskrnl.sizeOfImage == 0UL) {
        return;
    }

    tableShadowRva = dynState.kernelGlobals.keServiceDescriptorTableShadow;
    tableShadowSource = dynState.kernelGlobalSources.keServiceDescriptorTableShadow;
    if (!kswordArkDriverIsDynGlobalRvaPresent(tableShadowRva) ||
        (tableShadowSource != KSW_DYN_FIELD_SOURCE_PDB_PROFILE &&
         tableShadowSource != KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
        return;
    }
    if (tableShadowSource == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN &&
        kswordArkDriverResolveShadowSsdtRva(&dynState.ntoskrnl) != (LONG)tableShadowRva) {
        return;
    }

    if (tableShadowRva >= dynState.ntoskrnl.sizeOfImage ||
        (sizeof(KswordArkServiceTableDescriptor) * 2U) > (SIZE_T)(dynState.ntoskrnl.sizeOfImage - tableShadowRva)) {
        return;
    }

    descriptorAddress = dynState.ntoskrnl.imageBase + (ULONG64)tableShadowRva;
    descriptorArray = (const KswordArkServiceTableDescriptor*)(ULONG_PTR)descriptorAddress;

    __try {
        const KswordArkServiceTableDescriptor* shadowDescriptor = &descriptorArray[1];

        if (shadowDescriptor->serviceTableBase != NULL &&
            shadowDescriptor->numberOfServices > 0U &&
            shadowDescriptor->numberOfServices <= MAXULONG) {
            *tableBaseOut = shadowDescriptor->serviceTableBase;
            *serviceCountOut = (ULONG)shadowDescriptor->numberOfServices;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *tableBaseOut = NULL;
        *serviceCountOut = 0UL;
    }
}

static ULONG_PTR
kswordArkDriverResolveServiceRoutineAddress(
    _In_opt_ PVOID serviceTableBase,
    _In_ ULONG serviceCount,
    _In_ ULONG serviceIndex
    )
{
    if (serviceTableBase == NULL || serviceCount == 0U) {
        return 0U;
    }

    if (serviceIndex >= serviceCount) {
        return 0U;
    }

#if defined(_M_AMD64)
    {
        ULONG_PTR routineAddress = 0U;

        __try {
            const LONG kEntryValue = ((volatile LONG*)serviceTableBase)[serviceIndex];
            const LONG_PTR kSignedOffset = ((LONG_PTR)kEntryValue) >> 4;
            routineAddress = (ULONG_PTR)((PUCHAR)serviceTableBase + kSignedOffset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            routineAddress = 0U;
        }

        return routineAddress;
    }
#elif defined(_M_IX86)
    {
        ULONG_PTR routineAddress = 0U;

        __try {
            routineAddress = ((volatile ULONG_PTR*)serviceTableBase)[serviceIndex];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            routineAddress = 0U;
        }

        return routineAddress;
    }
#else
    UNREFERENCED_PARAMETER(serviceTableBase);
    UNREFERENCED_PARAMETER(serviceCount);
    UNREFERENCED_PARAMETER(serviceIndex);
    return 0U;
#endif
}

static VOID
kswordArkDriverFillServiceTableEntryMetadata(
    _In_opt_ PVOID serviceTableBase,
    _In_ ULONG serviceCount,
    _In_ ULONG serviceIndex,
    _Inout_ KSWORD_ARK_SSDT_ENTRY* entry
    )
/*++

Routine Description:

    Collect service table slot addresses and encoded values. Note: This metadata allows R3 to establish an independent baseline
    using disk image bytes at the same RVA; this function reads only the current slot and performs no table entry writes.

Arguments:

    ServiceTableBase: Current service table base address.
    ServiceCount: Number of entries in the service table.
    ServiceIndex: Target service index.
    Entry: protocol row to be added.

Return Value:

    None. On read failure, retain zero values and do not set TABLE_VALUE_CAPTURED.

--*/
{
    if (serviceTableBase == NULL ||
        entry == NULL ||
        serviceCount == 0UL ||
        serviceIndex >= serviceCount) {
        return;
    }

    __try {
#if defined(_M_AMD64)
        const volatile LONG* table =
            (const volatile LONG*)serviceTableBase;
        entry->tableEntryAddress =
            (ULONGLONG)(ULONG_PTR)&table[serviceIndex];
        entry->currentTableValue =
            (ULONGLONG)(ULONG)(table[serviceIndex]);
        entry->tableEntrySize = sizeof(LONG);
#elif defined(_M_IX86)
        const volatile ULONG_PTR* table =
            (const volatile ULONG_PTR*)ServiceTableBase;
        Entry->tableEntryAddress =
            (ULONGLONG)(ULONG_PTR)&table[ServiceIndex];
        Entry->currentTableValue =
            (ULONGLONG)table[ServiceIndex];
        Entry->tableEntrySize = sizeof(ULONG_PTR);
#else
        UNREFERENCED_PARAMETER(ServiceTableBase);
        UNREFERENCED_PARAMETER(ServiceCount);
        UNREFERENCED_PARAMETER(ServiceIndex);
#endif
        if (entry->tableEntryAddress != 0ULL &&
            entry->tableEntrySize != 0UL) {
            entry->flags |=
                KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_VALUE_CAPTURED;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        entry->tableEntryAddress = 0ULL;
        entry->currentTableValue = 0ULL;
        entry->tableEntrySize = 0UL;
    }
}

NTSTATUS
kswordArkDriverEnumerateSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader = NULL;
    ULONG entryCapacity = 0U;
    ULONG requestFlags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
    PVOID imageBase = NULL;
    ULONG imageSize = 0U;
    CHAR moduleNameText[KSWORD_ARK_SSDT_ENTRY_MAX_MODULE] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    const IMAGE_DATA_DIRECTORY* exportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportHeader = NULL;
    PULONG nameRvaArray = NULL;
    PUSHORT nameOrdinalArray = NULL;
    PULONG functionRvaArray = NULL;
    ULONG exportNameIndex = 0U;
    PVOID serviceTableBase = NULL;
    ULONG serviceCountFromTable = 0U;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < kGKswordArkSsdtResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request != NULL) {
        requestFlags = request->flags;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    responseHeader = (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
    responseHeader->version = KSWORD_ARK_ENUM_SSDT_PROTOCOL_VERSION;
    responseHeader->entrySize = sizeof(KSWORD_ARK_SSDT_ENTRY);
    entryCapacity = (ULONG)((outputBufferLength - kGKswordArkSsdtResponseHeaderSize) / sizeof(KSWORD_ARK_SSDT_ENTRY));

    status = kswordArkDriverResolveKernelImage(
        &imageBase,
        &imageSize,
        moduleNameText,
        sizeof(moduleNameText));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kswordArkDriverTryResolveServiceTable(&serviceTableBase, &serviceCountFromTable);
    responseHeader->serviceTableBase = (ULONGLONG)(ULONG_PTR)serviceTableBase;
    responseHeader->serviceCountFromTable = serviceCountFromTable;

    dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + (ULONG)dosHeader->e_lfanew);
    exportDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectory->VirtualAddress == 0U ||
        !kswordArkDriverValidateRvaRange(exportDirectory->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), imageSize)) {
        return STATUS_NOT_FOUND;
    }

    exportHeader = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirectory->VirtualAddress);
    if (exportHeader->AddressOfNames == 0U ||
        exportHeader->AddressOfNameOrdinals == 0U ||
        exportHeader->AddressOfFunctions == 0U) {
        return STATUS_NOT_FOUND;
    }

    if (!kswordArkDriverValidateRvaRange(
        exportHeader->AddressOfNames,
        exportHeader->NumberOfNames * sizeof(ULONG),
        imageSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!kswordArkDriverValidateRvaRange(
        exportHeader->AddressOfNameOrdinals,
        exportHeader->NumberOfNames * sizeof(USHORT),
        imageSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!kswordArkDriverValidateRvaRange(
        exportHeader->AddressOfFunctions,
        exportHeader->NumberOfFunctions * sizeof(ULONG),
        imageSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    nameRvaArray = (PULONG)((PUCHAR)imageBase + exportHeader->AddressOfNames);
    nameOrdinalArray = (PUSHORT)((PUCHAR)imageBase + exportHeader->AddressOfNameOrdinals);
    functionRvaArray = (PULONG)((PUCHAR)imageBase + exportHeader->AddressOfFunctions);

    for (exportNameIndex = 0U; exportNameIndex < exportHeader->NumberOfNames; ++exportNameIndex) {
        const ULONG kNameRva = nameRvaArray[exportNameIndex];
        const USHORT kOrdinalIndex = nameOrdinalArray[exportNameIndex];
        const CHAR* exportNameText = NULL;
        ULONG functionRva = 0U;
        const UCHAR* stubBytes = NULL;
        ULONG serviceIndex = 0U;
        BOOLEAN indexResolved = FALSE;
        ULONG_PTR serviceRoutineAddress = 0U;
        KSWORD_ARK_SSDT_ENTRY* entry = NULL;

        if (kOrdinalIndex >= exportHeader->NumberOfFunctions) {
            continue;
        }

        if (!kswordArkDriverValidateRvaRange(kNameRva, 2U, imageSize)) {
            continue;
        }

        exportNameText = (const CHAR*)((PUCHAR)imageBase + kNameRva);
        if (!kswordArkDriverStartsWithZw(exportNameText)) {
            continue;
        }

        functionRva = functionRvaArray[kOrdinalIndex];
        if (functionRva >= exportDirectory->VirtualAddress &&
            functionRva < exportDirectory->VirtualAddress + exportDirectory->Size) {
            // Forwarded export points into export directory string area.
            continue;
        }
        if (!kswordArkDriverValidateRvaRange(functionRva, 16U, imageSize)) {
            continue;
        }

        stubBytes = (const UCHAR*)((PUCHAR)imageBase + functionRva);
        indexResolved = kswordArkDriverFindServiceIndexFromStub(stubBytes, 32U, &serviceIndex);
        if (!indexResolved &&
            (requestFlags & KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED) == 0U) {
            continue;
        }

        responseHeader->totalCount += 1UL;
        if (responseHeader->returnedCount >= entryCapacity) {
            continue;
        }

        entry = &responseHeader->entries[responseHeader->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->zwRoutineAddress = (ULONGLONG)(ULONG_PTR)stubBytes;
        if (indexResolved) {
            entry->serviceIndex = serviceIndex;
            entry->flags |= KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED;

            serviceRoutineAddress = kswordArkDriverResolveServiceRoutineAddress(
                serviceTableBase,
                serviceCountFromTable,
                serviceIndex);
            if (serviceRoutineAddress != 0U) {
                entry->serviceRoutineAddress = (ULONGLONG)serviceRoutineAddress;
                entry->flags |= KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID;
            }
            kswordArkDriverFillServiceTableEntryMetadata(
                serviceTableBase,
                serviceCountFromTable,
                serviceIndex,
                entry);
        }
        else {
            entry->serviceIndex = 0U;
        }

        kswordArkDriverCopyAnsiText(entry->serviceName, sizeof(entry->serviceName), exportNameText);
        kswordArkDriverCopyAnsiText(entry->moduleName, sizeof(entry->moduleName), moduleNameText);

        responseHeader->returnedCount += 1UL;
    }

    *bytesWrittenOut = kGKswordArkSsdtResponseHeaderSize +
        ((size_t)responseHeader->returnedCount * sizeof(KSWORD_ARK_SSDT_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnumerateShadowSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate shadow system calls exported by the graphics subsystem. Note: Refer to System Informer's ksyscall.c.
    Prioritize scanning the __win32kstub_ exports from the loaded win32k.sys. For older systems or different
    distribution layouts, fall back to scanning Nt* exports from win32u.dll to provide a user-friendly SSSDT name view.

Arguments:

    outputBuffer: Response buffer.
    outputBufferLength: Response buffer length.
    request: Optional request; flags control whether to include unresolved items.
    bytesWrittenOut: Returns the number of bytes written.

Return Value:

    STATUS_SUCCESS indicates a valid response packet; underlying failures return an NTSTATUS.

--*/
{
    KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader = NULL;
    ULONG entryCapacity = 0U;
    ULONG requestFlags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
    const CHAR* moduleCandidates[] = { "win32k.sys", "win32u.dll" };
    ULONG candidateIndex = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;
    PVOID shadowServiceTableBase = NULL;
    ULONG shadowServiceCount = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < kGKswordArkSsdtResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request != NULL) {
        requestFlags = request->flags;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    responseHeader = (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
    responseHeader->version = KSWORD_ARK_ENUM_SSDT_PROTOCOL_VERSION;
    responseHeader->entrySize = sizeof(KSWORD_ARK_SSDT_ENTRY);
    responseHeader->serviceTableBase = 0ULL;
    responseHeader->serviceCountFromTable = 0UL;
    entryCapacity = (ULONG)((outputBufferLength - kGKswordArkSsdtResponseHeaderSize) / sizeof(KSWORD_ARK_SSDT_ENTRY));
    kswordArkDriverTryResolveShadowServiceTable(&shadowServiceTableBase, &shadowServiceCount);
    responseHeader->serviceTableBase = (ULONGLONG)(ULONG_PTR)shadowServiceTableBase;
    responseHeader->serviceCountFromTable = shadowServiceCount;

    for (candidateIndex = 0UL; candidateIndex < RTL_NUMBER_OF(moduleCandidates); ++candidateIndex) {
        PVOID imageBase = NULL;
        ULONG imageSize = 0U;
        CHAR moduleNameText[KSWORD_ARK_SSDT_ENTRY_MAX_MODULE] = { 0 };
        PIMAGE_DOS_HEADER dosHeader = NULL;
        PIMAGE_NT_HEADERS ntHeaders = NULL;
        const IMAGE_DATA_DIRECTORY* exportDirectory = NULL;
        PIMAGE_EXPORT_DIRECTORY exportHeader = NULL;
        PULONG nameRvaArray = NULL;
        PUSHORT nameOrdinalArray = NULL;
        PULONG functionRvaArray = NULL;
        ULONG exportNameIndex = 0UL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkDriverResolveLoadedModuleImage(
            moduleCandidates[candidateIndex],
            &imageBase,
            &imageSize,
            moduleNameText,
            sizeof(moduleNameText));
        lastStatus = status;
        if (!NT_SUCCESS(status) || imageBase == NULL || imageSize == 0UL) {
            continue;
        }

        __try {
            dosHeader = (PIMAGE_DOS_HEADER)imageBase;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
                continue;
            }
            ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + (ULONG)dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                continue;
            }
            exportDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDirectory->VirtualAddress == 0U ||
                !kswordArkDriverValidateRvaRange(exportDirectory->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), imageSize)) {
                continue;
            }
            exportHeader = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirectory->VirtualAddress);
            if (exportHeader->AddressOfNames == 0U ||
                exportHeader->AddressOfNameOrdinals == 0U ||
                exportHeader->AddressOfFunctions == 0U) {
                continue;
            }
            if (!kswordArkDriverValidateRvaRange(exportHeader->AddressOfNames, exportHeader->NumberOfNames * sizeof(ULONG), imageSize) ||
                !kswordArkDriverValidateRvaRange(exportHeader->AddressOfNameOrdinals, exportHeader->NumberOfNames * sizeof(USHORT), imageSize) ||
                !kswordArkDriverValidateRvaRange(exportHeader->AddressOfFunctions, exportHeader->NumberOfFunctions * sizeof(ULONG), imageSize)) {
                continue;
            }

            nameRvaArray = (PULONG)((PUCHAR)imageBase + exportHeader->AddressOfNames);
            nameOrdinalArray = (PUSHORT)((PUCHAR)imageBase + exportHeader->AddressOfNameOrdinals);
            functionRvaArray = (PULONG)((PUCHAR)imageBase + exportHeader->AddressOfFunctions);

            for (exportNameIndex = 0UL; exportNameIndex < exportHeader->NumberOfNames; ++exportNameIndex) {
                const ULONG kNameRva = nameRvaArray[exportNameIndex];
                const USHORT kOrdinalIndex = nameOrdinalArray[exportNameIndex];
                const CHAR* exportNameText = NULL;
                ULONG functionRva = 0UL;
                const UCHAR* stubBytes = NULL;
                ULONG serviceIndex = 0UL;
                BOOLEAN indexResolved = FALSE;
                ULONG_PTR serviceRoutineAddress = 0U;
                KSWORD_ARK_SSDT_ENTRY* entry = NULL;

                if (kOrdinalIndex >= exportHeader->NumberOfFunctions ||
                    !kswordArkDriverValidateRvaRange(kNameRva, 2U, imageSize)) {
                    continue;
                }

                exportNameText = (const CHAR*)((PUCHAR)imageBase + kNameRva);
                if (!kswordArkDriverStartsWithAnsi(exportNameText, "__win32kstub_") &&
                    !kswordArkDriverStartsWithAnsi(exportNameText, "Nt")) {
                    continue;
                }

                functionRva = functionRvaArray[kOrdinalIndex];
                if (functionRva >= exportDirectory->VirtualAddress &&
                    functionRva < exportDirectory->VirtualAddress + exportDirectory->Size) {
                    continue;
                }
                if (!kswordArkDriverValidateRvaRange(functionRva, 16U, imageSize)) {
                    continue;
                }

                stubBytes = (const UCHAR*)((PUCHAR)imageBase + functionRva);
                indexResolved = kswordArkDriverFindServiceIndexFromStub(stubBytes, 32U, &serviceIndex);
                if (!indexResolved &&
                    (requestFlags & KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED) == 0U) {
                    continue;
                }

                responseHeader->totalCount += 1UL;
                if (responseHeader->returnedCount >= entryCapacity) {
                    continue;
                }

                entry = &responseHeader->entries[responseHeader->returnedCount];
                RtlZeroMemory(entry, sizeof(*entry));
                entry->zwRoutineAddress = (ULONGLONG)(ULONG_PTR)stubBytes;
                entry->serviceRoutineAddress = 0ULL;
                entry->flags = KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE | KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT;
                if (indexResolved) {
                    entry->serviceIndex = serviceIndex & 0x0FFFUL;
                    entry->flags |= KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED;

                    serviceRoutineAddress = kswordArkDriverResolveServiceRoutineAddress(
                        shadowServiceTableBase,
                        shadowServiceCount,
                        entry->serviceIndex);
                    if (serviceRoutineAddress != 0U) {
                        entry->serviceRoutineAddress = (ULONGLONG)serviceRoutineAddress;
                        entry->flags |= KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID;
                    }
                    kswordArkDriverFillServiceTableEntryMetadata(
                        shadowServiceTableBase,
                        shadowServiceCount,
                        entry->serviceIndex,
                        entry);
                }
                kswordArkDriverCopyAnsiText(entry->serviceName, sizeof(entry->serviceName), exportNameText);
                if (kswordArkDriverStartsWithAnsi(entry->serviceName, "__win32kstub_")) {
                    RtlMoveMemory(
                        entry->serviceName,
                        entry->serviceName + 13,
                        sizeof(entry->serviceName) - 13);
                    entry->serviceName[sizeof(entry->serviceName) - 1U] = '\0';
                }
                kswordArkDriverCopyAnsiText(entry->moduleName, sizeof(entry->moduleName), moduleNameText);
                responseHeader->returnedCount += 1UL;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            lastStatus = GetExceptionCode();
            continue;
        }

        if (responseHeader->totalCount > 0UL) {
            *bytesWrittenOut = kGKswordArkSsdtResponseHeaderSize +
                ((size_t)responseHeader->returnedCount * sizeof(KSWORD_ARK_SSDT_ENTRY));
            return STATUS_SUCCESS;
        }
    }

    *bytesWrittenOut = kGKswordArkSsdtResponseHeaderSize;
    return NT_SUCCESS(lastStatus) ? STATUS_NOT_FOUND : lastStatus;
}
