/*++

Module Name:

    callback_external_wfp.c

Abstract:

    WFP callout enumeration and safe removal through public WFP management APIs.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_external_wfp.h"
#include <ntimage.h>

#define KSWORD_ARK_WFP_ENUM_PAGE_SIZE 64U
#define KSWORD_ARK_WFP_MAX_CALLOUT_ID 0xFFFFFFFFULL

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

typedef struct _SEC_WINNT_AUTH_IDENTITY_W SEC_WINNT_AUTH_IDENTITY_W;

typedef struct KswordArkFwpmDisplayDatA0
{
    WCHAR* name;
    WCHAR* description;
} KswordArkFwpmDisplayDatA0;

typedef struct KswordArkFwpmSessioN0
{
    GUID sessionKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    ULONG processId;
    SID* sid;
    WCHAR* username;
    BOOLEAN kernelMode;
} KswordArkFwpmSessioN0;

typedef struct KswordArkFwpmCalloutEnumTemplatE0
{
    GUID* providerKey;
    GUID layerKey;
} KswordArkFwpmCalloutEnumTemplatE0;

typedef struct KswordArkFwpmCallouT0
{
    GUID calloutKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    struct
    {
        UINT32 size;
        UINT8* data;
    } providerData;
    GUID applicableLayer;
    UINT32 calloutId;
} KswordArkFwpmCallouT0;

typedef NTSTATUS (*KswordArkWfpEngineOpen)(
    _In_opt_ const WCHAR* serverName,
    _In_ UINT32 authnService,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
    _In_opt_ const KswordArkFwpmSessioN0* session,
    _Out_ HANDLE* engineHandle);
typedef NTSTATUS (*KswordArkWfpEngineClose)(_In_ HANDLE engineHandle);
typedef NTSTATUS (*KswordArkWfpCalloutCreateEnumHandle)(
    _In_ HANDLE engineHandle,
    _In_opt_ const KswordArkFwpmCalloutEnumTemplatE0* enumTemplate,
    _Out_ HANDLE* enumHandle);
typedef NTSTATUS (*KswordArkWfpCalloutDestroyEnumHandle)(
    _In_ HANDLE engineHandle,
    _In_ HANDLE enumHandle);
typedef NTSTATUS (*KswordArkWfpCalloutEnum)(
    _In_ HANDLE engineHandle,
    _In_ HANDLE enumHandle,
    _In_ UINT32 numEntriesRequested,
    _Outptr_result_buffer_(*numEntriesReturned) KswordArkFwpmCallouT0*** entries,
    _Out_ UINT32* numEntriesReturned);
typedef NTSTATUS (*KswordArkWfpCalloutGetById)(
    _In_ HANDLE engineHandle,
    _In_ UINT32 id,
    _Outptr_ KswordArkFwpmCallouT0** callout);
typedef NTSTATUS (*KswordArkWfpCalloutDeleteById)(
    _In_ HANDLE engineHandle,
    _In_ UINT32 id);
typedef VOID (*KswordArkWfpFreeMemory)(_Inout_ VOID** pointer);

typedef struct KswordArkWfpApi
{
    KswordArkWfpEngineOpen engineOpen;
    KswordArkWfpEngineClose engineClose;
    KswordArkWfpCalloutCreateEnumHandle calloutCreateEnumHandle;
    KswordArkWfpCalloutDestroyEnumHandle calloutDestroyEnumHandle;
    KswordArkWfpCalloutEnum calloutEnum;
    KswordArkWfpCalloutGetById calloutGetById;
    KswordArkWfpCalloutDeleteById calloutDeleteById;
    KswordArkWfpFreeMemory freeMemory;
} KswordArkWfpApi;

static BOOLEAN
kswordArkWfpAsciiEquals(
    _In_z_ const CHAR* left,
    _In_z_ const CHAR* right
    )
/*++

Routine Description:

    Compare two PE export ASCII names. Note: Comparison length is limited to
    128 bytes to prevent infinite loops caused by malformed export tables.

Arguments:

    Left - Name in the exported table.
    Right - Expected name input.

Return Value:

    Returns TRUE if equal; otherwise returns FALSE.

--*/
{
    ULONG index = 0UL;

    if (left == NULL || right == NULL) {
        return FALSE;
    }

    __try {
        for (index = 0UL; index < 128UL; ++index) {
            if (left[index] != right[index]) {
                return FALSE;
            }
            if (left[index] == '\0') {
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

static BOOLEAN
kswordArkWfpAnsiPathContains(
    _In_reads_bytes_(textBytes) const UCHAR* text,
    _In_ ULONG textBytes,
    _In_z_ const CHAR* needle
    )
/*++

Routine Description:

    Search for lowercase substrings in system module ANSI paths. Note:
    Read-only fixed module path fields to identify loaded fwpkclnt.sys.

Arguments:

    Text - Input module path.
    TextBytes - Length of the input path field.
    Needle - lowercase ASCII substring input.

Return Value:

    Returns TRUE on match; otherwise returns FALSE.

--*/
{
    ULONG textIndex = 0UL;

    if (text == NULL || textBytes == 0UL || needle == NULL) {
        return FALSE;
    }

    for (textIndex = 0UL; textIndex < textBytes && text[textIndex] != '\0'; ++textIndex) {
        ULONG needleIndex = 0UL;

        for (needleIndex = 0UL; needle[needleIndex] != '\0'; ++needleIndex) {
            UCHAR current = 0U;

            if (textIndex + needleIndex >= textBytes) {
                return FALSE;
            }
            current = text[textIndex + needleIndex];
            if (current == '\0') {
                return FALSE;
            }
            if (current >= 'A' && current <= 'Z') {
                current = (UCHAR)(current - 'A' + 'a');
            }
            if ((CHAR)current != needle[needleIndex]) {
                break;
            }
        }
        if (needle[needleIndex] == '\0') {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkWfpRvaValid(
    _In_ ULONG rva,
    _In_ ULONG size,
    _In_ ULONG imageSize
    )
/*++

Routine Description:

    Validate PE RVA range. Note: All export directory fields must fall entirely
    within the image range; overflow or empty ranges are considered unavailable.

Arguments:

    Rva - Input RVA.
    Size - input region size.
    ImageSize: Input image size.

Return Value:

    Return TRUE if the range is trusted; otherwise, return FALSE.

--*/
{
    if (rva == 0UL || size == 0UL || imageSize == 0UL) {
        return FALSE;
    }
    if (size > imageSize || rva >= imageSize || size > imageSize - rva) {
        return FALSE;
    }
    return TRUE;
}

static PVOID
kswordArkWfpResolveExport(
    _In_ ULONG64 imageBase,
    _In_ ULONG imageSize,
    _In_z_ const CHAR* routineName
    )
/*++

Routine Description:

    Parse exports from the loaded fwpkclnt.sys image. Note: The function reads only the PE header
    and export directory; it does not follow forwarders and does not write to module memory.

Arguments:

    ImageBase: Input module base address.
    ImageSize: Input module size.
    RoutineName - Input exported name.

Return Value:

    Returns the export address on success; returns NULL on failure.

--*/
{
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
    ULONG exportRva = 0UL;
    ULONG exportSize = 0UL;
    ULONG nameIndex = 0UL;
    ULONG* nameArray = NULL;
    ULONG* functionArray = NULL;
    USHORT* ordinalArray = NULL;

    if (imageBase == 0ULL || imageSize < sizeof(IMAGE_DOS_HEADER) || routineName == NULL) {
        return NULL;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)(ULONG_PTR)imageBase;
        if (!MmIsAddressValid(dosHeader) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }
        if (dosHeader->e_lfanew <= 0 || (ULONG)dosHeader->e_lfanew > imageSize - sizeof(IMAGE_NT_HEADERS)) {
            return NULL;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)(ULONG_PTR)imageBase + dosHeader->e_lfanew);
        if (!MmIsAddressValid(ntHeaders) || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }
        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
            return NULL;
        }

        exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!kswordArkWfpRvaValid(exportRva, exportSize, imageSize)) {
            return NULL;
        }

        exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)(ULONG_PTR)imageBase + exportRva);
        if (!MmIsAddressValid(exportDirectory) || exportDirectory->NumberOfNames == 0UL) {
            return NULL;
        }
        if (!kswordArkWfpRvaValid(exportDirectory->AddressOfNames, exportDirectory->NumberOfNames * sizeof(ULONG), imageSize) ||
            !kswordArkWfpRvaValid(exportDirectory->AddressOfNameOrdinals, exportDirectory->NumberOfNames * sizeof(USHORT), imageSize) ||
            !kswordArkWfpRvaValid(exportDirectory->AddressOfFunctions, exportDirectory->NumberOfFunctions * sizeof(ULONG), imageSize)) {
            return NULL;
        }

        nameArray = (ULONG*)((PUCHAR)(ULONG_PTR)imageBase + exportDirectory->AddressOfNames);
        ordinalArray = (USHORT*)((PUCHAR)(ULONG_PTR)imageBase + exportDirectory->AddressOfNameOrdinals);
        functionArray = (ULONG*)((PUCHAR)(ULONG_PTR)imageBase + exportDirectory->AddressOfFunctions);

        for (nameIndex = 0UL; nameIndex < exportDirectory->NumberOfNames; ++nameIndex) {
            ULONG nameRva = nameArray[nameIndex];
            USHORT ordinalIndex = ordinalArray[nameIndex];
            ULONG functionRva = 0UL;
            const CHAR* exportedName = NULL;

            if (!kswordArkWfpRvaValid(nameRva, 1UL, imageSize) || ordinalIndex >= exportDirectory->NumberOfFunctions) {
                continue;
            }
            exportedName = (const CHAR*)((PUCHAR)(ULONG_PTR)imageBase + nameRva);
            if (!MmIsAddressValid((PVOID)exportedName) || !kswordArkWfpAsciiEquals(exportedName, routineName)) {
                continue;
            }
            functionRva = functionArray[ordinalIndex];
            if (functionRva >= exportRva && functionRva < exportRva + exportSize) {
                return NULL;
            }
            if (!kswordArkWfpRvaValid(functionRva, 1UL, imageSize)) {
                return NULL;
            }
            return (PVOID)((PUCHAR)(ULONG_PTR)imageBase + functionRva);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return NULL;
}

static PVOID
kswordArkWfpGetRoutine(
    _In_z_ const CHAR* routineName
    )
/*++

Routine Description:

    Parse WFP management API addresses. Note: To avoid modifying the vcxproj link libraries, this function only
    reads the system module table and resolves exports from the already-loaded fwpkclnt.sys; return NULL if missing.

Arguments:

    RoutineName - Input ASCII export name.

Return Value:

    Returns the routine address on success; returns NULL on failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG moduleIndex = 0UL;
    PVOID routineAddress = NULL;
    KswordArkCallbackModuleCache moduleCache;

    if (routineName == NULL) {
        return NULL;
    }

    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    status = kswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    if (!NT_SUCCESS(status) || moduleCache.moduleInfo == NULL) {
        kswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return NULL;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleCache.moduleInfo->numberOfModules; ++moduleIndex) {
        KswordArkCallbackModuleEntry* moduleEntry = &moduleCache.moduleInfo->modules[moduleIndex];
        if (!kswordArkWfpAnsiPathContains(moduleEntry->fullPathName, RTL_NUMBER_OF(moduleEntry->fullPathName), "fwpkclnt.sys")) {
            continue;
        }
        routineAddress = kswordArkWfpResolveExport((ULONG64)(ULONG_PTR)moduleEntry->imageBase, moduleEntry->imageSize, routineName);
        break;
    }

    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
    return routineAddress;
}

static NTSTATUS
kswordArkWfpResolveApi(
    _Out_ KswordArkWfpApi* apiOut
    )
/*++

Routine Description:

    Parse the WFP API table. Note: WFP enumeration/removal capabilities are enabled
    only if all required exports exist; otherwise, return STATUS_NOT_SUPPORTED.

Arguments:

    ApiOut - Output API table.

Return Value:

    Returns STATUS_SUCCESS on success; returns STATUS_NOT_SUPPORTED if the export is missing.

--*/
{
    if (apiOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(apiOut, sizeof(*apiOut));
    apiOut->engineOpen = (KswordArkWfpEngineOpen)kswordArkWfpGetRoutine("FwpmEngineOpen0");
    apiOut->engineClose = (KswordArkWfpEngineClose)kswordArkWfpGetRoutine("FwpmEngineClose0");
    apiOut->calloutCreateEnumHandle = (KswordArkWfpCalloutCreateEnumHandle)kswordArkWfpGetRoutine("FwpmCalloutCreateEnumHandle0");
    apiOut->calloutDestroyEnumHandle = (KswordArkWfpCalloutDestroyEnumHandle)kswordArkWfpGetRoutine("FwpmCalloutDestroyEnumHandle0");
    apiOut->calloutEnum = (KswordArkWfpCalloutEnum)kswordArkWfpGetRoutine("FwpmCalloutEnum0");
    apiOut->calloutGetById = (KswordArkWfpCalloutGetById)kswordArkWfpGetRoutine("FwpmCalloutGetById0");
    apiOut->calloutDeleteById = (KswordArkWfpCalloutDeleteById)kswordArkWfpGetRoutine("FwpmCalloutDeleteById0");
    apiOut->freeMemory = (KswordArkWfpFreeMemory)kswordArkWfpGetRoutine("FwpmFreeMemory0");

    if (apiOut->engineOpen == NULL || apiOut->engineClose == NULL || apiOut->calloutCreateEnumHandle == NULL ||
        apiOut->calloutDestroyEnumHandle == NULL || apiOut->calloutEnum == NULL || apiOut->calloutGetById == NULL ||
        apiOut->calloutDeleteById == NULL || apiOut->freeMemory == NULL) {
        RtlZeroMemory(apiOut, sizeof(*apiOut));
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkWfpOpenEngine(
    _In_ const KswordArkWfpApi* api,
    _Out_ HANDLE* engineHandleOut
    )
/*++

Routine Description:

    Open WFP engine session. Note: WFP management API requires
    PASSIVE_LEVEL; this function performs IRQL gating first.

Arguments:

    Api - Input API table.
    EngineHandleOut: Output engine handle.

Return Value:

    Returns STATUS_SUCCESS on success; returns STATUS_NOT_SUPPORTED if the context is unsafe.

--*/
{
    if (api == NULL || api->engineOpen == NULL || engineHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *engineHandleOut = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_NOT_SUPPORTED;
    }
    return api->engineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, engineHandleOut);
}

static VOID
kswordArkWfpAddRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ const KswordArkFwpmCallouT0* callout
    )
/*++

Routine Description:

    Writing to the WFP callout enumeration entry. Note: Publicly exposing FWPM_CALLOUT0 does not reveal kernel
    function addresses; therefore, callbackAddress stores the calloutId, and the IDENTIFIER field is used as a flag.

Arguments:

    Builder - The input/output enumeration builder.
    Callout - Input WFP callout.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (builder == NULL || callout == NULL) {
        return;
    }
    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE;
    entry->callbackAddress = (ULONG64)callout->calloutId;
    entry->registrationAddress = (ULONG64)callout->calloutId;
    entry->lastStatus = STATUS_SUCCESS;

    if (callout->displayData.name != NULL) {
        kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), callout->displayData.name);
    }
    else {
        (VOID)RtlStringCbPrintfW(entry->name, sizeof(entry->name), L"WFP Callout #%lu", (unsigned long)callout->calloutId);
    }
    if (callout->displayData.description != NULL) {
        kswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), callout->displayData.description);
        if (entry->altitude[0] != L'\0') {
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        }
    }
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"WFP FWPM_CALLOUT0；CalloutId=%lu，Flags=0x%08lX；公开 API 不返回 classify/notify 函数地址，移除使用 FwpmCalloutDeleteById0。",
        (unsigned long)callout->calloutId,
        (unsigned long)callout->flags);
}

VOID
kswordArkCallbackExternalWfpAddCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    enumerate WFP callouts. Note: Use only public Fwpm* management APIs; do not scan or modify
    BFE internal linked lists. If APIs are unavailable, write a line indicating unsupported.

Arguments:

    Builder - The input/output enumeration builder.

Return Value:

    No return value.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE engineHandle = NULL;
    HANDLE enumHandle = NULL;
    UINT32 returnedCount = 0U;
    KswordArkWfpApi api;

    if (builder == NULL) {
        return;
    }
    RtlZeroMemory(&api, sizeof(api));

    status = kswordArkWfpResolveApi(&api);
    if (!NT_SUCCESS(status)) {
        builder->lastStatus = status;
        kswordArkCallbackEnumAddUnsupportedRow(builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", L"未解析到完整 fwpkclnt.sys Fwpm* 管理 API；当前返回 STATUS_NOT_SUPPORTED。");
        return;
    }

    status = kswordArkWfpOpenEngine(&api, &engineHandle);
    if (!NT_SUCCESS(status)) {
        builder->lastStatus = status;
        kswordArkCallbackEnumAddUnsupportedRow(builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", L"FwpmEngineOpen0 失败或当前 IRQL 不满足 PASSIVE_LEVEL。");
        return;
    }

    status = api.calloutCreateEnumHandle(engineHandle, NULL, &enumHandle);
    if (!NT_SUCCESS(status)) {
        builder->lastStatus = status;
        (VOID)api.engineClose(engineHandle);
        kswordArkCallbackEnumAddUnsupportedRow(builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", L"FwpmCalloutCreateEnumHandle0 失败，无法获取枚举快照。");
        return;
    }

    do {
        KswordArkFwpmCallouT0** entries = NULL;
        UINT32 entryIndex = 0U;
        returnedCount = 0U;

        status = api.calloutEnum(engineHandle, enumHandle, KSWORD_ARK_WFP_ENUM_PAGE_SIZE, &entries, &returnedCount);
        if (!NT_SUCCESS(status)) {
            builder->lastStatus = status;
            if (entries != NULL) {
                VOID* freePointer = entries;
                api.freeMemory(&freePointer);
            }
            break;
        }
        for (entryIndex = 0U; entryIndex < returnedCount; ++entryIndex) {
            if (entries != NULL && entries[entryIndex] != NULL) {
                kswordArkWfpAddRow(builder, entries[entryIndex]);
            }
        }
        if (entries != NULL) {
            VOID* freePointer = entries;
            api.freeMemory(&freePointer);
        }
    } while (returnedCount == KSWORD_ARK_WFP_ENUM_PAGE_SIZE);

    (VOID)api.calloutDestroyEnumHandle(engineHandle, enumHandle);
    (VOID)api.engineClose(engineHandle);
}

NTSTATUS
kswordArkCallbackExternalWfpRemove(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket
    )
/*++

Routine Description:

    Remove the WFP callout via calloutId. Note: First verify that the ID belongs to an
    currently enumerable object using FwpmCalloutGetById0, then call FwpmCalloutDeleteById0.

Arguments:

    RequestPacket: input request, with callbackAddress carrying the calloutId.
    ResponsePacket - input/output response.

Return Value:

    Returns STATUS_SUCCESS on success; returns the corresponding NTSTATUS if verification fails or the API is unavailable.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE engineHandle = NULL;
    KswordArkFwpmCallouT0* callout = NULL;
    UINT32 calloutId = 0U;
    KswordArkWfpApi api;

    if (requestPacket == NULL || responsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestPacket->callbackClass != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT ||
        requestPacket->callbackAddress == 0ULL || requestPacket->callbackAddress > KSWORD_ARK_WFP_MAX_CALLOUT_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    calloutId = (UINT32)requestPacket->callbackAddress;
    RtlZeroMemory(&api, sizeof(api));
    status = kswordArkWfpResolveApi(&api);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkWfpOpenEngine(&api, &engineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = api.calloutGetById(engineHandle, calloutId, &callout);
    if (!NT_SUCCESS(status) || callout == NULL) {
        (VOID)api.engineClose(engineHandle);
        return status;
    }

    responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
    if (callout->displayData.name != NULL) {
        kswordArkCallbackEnumCopyWide(responsePacket->serviceName, RTL_NUMBER_OF(responsePacket->serviceName), callout->displayData.name);
    }

    {
        VOID* freePointer = callout;
        api.freeMemory(&freePointer);
        callout = NULL;
    }

    status = api.calloutDeleteById(engineHandle, calloutId);
    (VOID)api.engineClose(engineHandle);
    return status;
}
